from __future__ import annotations

import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThreadPool, QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMessageBox, QProgressBar, QPushButton, QSplitter, QStackedWidget,
    QTabWidget, QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,

)

from ..cache import CacheDB
from ..fs_scan import scan_cache_key
from ..models import (
    BackupComponent, BackupState, ConfigKind, ConfigPolicy, ConfigRecord, DependencyState, DependencyStatus, DryRunSummary,
    ExclusionOrigin, PackageManager, PackagePolicy, PackageRecord, RestoreState, SelectionPolicy, SnapshotRecord,
)
from ..paths import GuiPaths
from ..profiles import DEFAULT_RULES, ExcludeRule, enabled_rules
from .privileged_client import CredentialDescriptor, PrivilegedClient
from .workers import Worker
from .startup_flow import StartupFlow
from .task_monitor import TaskMonitorDialog, TaskRegistry
from .semantic_style import semantic_color, semantic_label
from ..selection import (
    SelectionResolver, aggregate_directory_backup_state, apply_rule_overrides,
    checkbox_selection_policy, filesystem_order_key, review_ancestor_paths,
    review_watch_directories,
)
from ..system_scan import real_mounted_filesystems
from ..telemetry import gate_restic_backup_progress, human_bytes, staged_progress_fraction

ROLE_PATH = Qt.ItemDataRole.UserRole + 1
ROLE_IS_DIR = Qt.ItemDataRole.UserRole + 2
ROLE_LOADED = Qt.ItemDataRole.UserRole + 3
ROLE_POLICY = Qt.ItemDataRole.UserRole + 4
ROLE_CONFIG_LEAF = Qt.ItemDataRole.UserRole + 5
ROLE_STATE = Qt.ItemDataRole.UserRole + 6
ROLE_SIZE = Qt.ItemDataRole.UserRole + 7
ROLE_SCANNED_AT = Qt.ItemDataRole.UserRole + 8
ROLE_CACHE_STALE = Qt.ItemDataRole.UserRole + 9
ROLE_SCAN_KEY = Qt.ItemDataRole.UserRole + 10
ROLE_TOTAL_SIZE = Qt.ItemDataRole.UserRole + 11
ROLE_IS_SYMLINK = Qt.ItemDataRole.UserRole + 12
ROLE_RENDERED_CHECK = Qt.ItemDataRole.UserRole + 13
# Compatibility alias for older tests/plugins; the column now represents physical total size.
ROLE_SELECTED_SIZE = ROLE_TOTAL_SIZE

# Python-level Qt item comparison is expensive for very large branches. Live
# and cached privileged listings already arrive in deterministic dirs/name
# order, so avoid one monolithic custom sort that can stall the event loop.
MAX_SYNC_FS_SORT_CHILDREN = 2000
FS_RENDER_CHUNK_SIZE = 64
FS_BROWSE_LIMIT = 10_000



STATUS_LABELS = {state: semantic_label(state) for state in BackupState}
STATUS_COLORS = {state: semantic_color(state) for state in BackupState}



class FilesystemTreeItem(QTreeWidgetItem):
    """Filesystem row with a stable domain-aware ordering.

    Qt's native ``sortChildren`` preserves expansion and selection state,
    unlike manually detaching/re-attaching children with ``takeChildren``.
    The comparison intentionally ignores the currently sorted visual column
    and always applies UBackup's filesystem order: status, size, name.
    """

    def __lt__(self, other) -> bool:
        try:
            left_path = self.data(0, ROLE_PATH)
            right_path = other.data(0, ROLE_PATH)
            if not left_path:
                return False if right_path else super().__lt__(other)
            if not right_path:
                return True
            try:
                left_state = BackupState(self.data(0, ROLE_STATE))
            except (TypeError, ValueError):
                left_state = BackupState.NOT_SELECTED
            try:
                right_state = BackupState(other.data(0, ROLE_STATE))
            except (TypeError, ValueError):
                right_state = BackupState.NOT_SELECTED
            left_size = self.data(0, ROLE_SIZE)
            right_size = other.data(0, ROLE_SIZE)
            left_name = Path(str(left_path)).name.casefold() or "/"
            right_name = Path(str(right_path)).name.casefold() or "/"
            left_key = filesystem_order_key(
                left_state, int(left_size) if isinstance(left_size, (int, float)) else None, left_name
            )
            right_key = filesystem_order_key(
                right_state, int(right_size) if isinstance(right_size, (int, float)) else None, right_name
            )
            return left_key < right_key
        except RuntimeError:
            return False

def _set_text(item, column: int, text: object) -> None:
    value = str(text)
    item.setText(column, value)
    item.setToolTip(column, value)


def _table_item(text: object) -> QTableWidgetItem:
    value = str(text)
    item = QTableWidgetItem(value)
    item.setToolTip(value)
    return item


def _mounted_filesystems() -> list[dict]:
    return real_mounted_filesystems()

def human_size(value: int | None) -> str:
    return human_bytes(value)


def scan_status_label(scanned_at: float | int | None, *, cached: bool, stale: bool = False) -> str:
    timestamp = float(scanned_at or 0.0)
    if timestamp <= 0:
        return "—"
    when = datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    if cached:
        state = "Cached (stale)" if stale else "Cached"
    else:
        state = "Calculated"
    return f"{state} · {when}"


def _set_scan_status(item, scanned_at: float | int | None, *, cached: bool, stale: bool = False) -> None:
    """Render cache age and make stale cached measurements visually distinct."""
    _set_text(item, 4, scan_status_label(scanned_at, cached=cached, stale=stale))
    brush = QBrush(QColor(semantic_color(BackupState.PENDING))) if stale else QBrush()
    # Status has its own semantic colour. Highlight only the cached measurement
    # cells so stale data is obvious without obscuring backup state.
    for column in (1, 2, 4):
        item.setForeground(column, brush)
    warning = QColor(semantic_color(BackupState.PENDING))
    warning.setAlpha(28)
    background = QBrush(warning) if stale else QBrush()
    for column in range(item.columnCount()):
        item.setBackground(column, background)


def _records_page(value):
    """Normalize a broker page and return records plus its continuation."""
    if isinstance(value, dict):
        return value.get("records", []), value.get("next_offset")
    return value or [], None


class PasswordDialog(QDialog):
    def __init__(self, parent=None, *, confirm: bool = True):
        super().__init__(parent)
        self.confirm = bool(confirm)
        self.setWindowTitle("Restic password")
        lay = QVBoxLayout(self)
        if self.confirm:
            text = (
                "Choose the password for the new encrypted Restic repository. "
                "UBackup keeps it only for this application session and does not persist it. "
                "Keep it in a password manager or use --password-file."
            )
        else:
            text = (
                "Enter the password for the existing encrypted Restic repository. "
                "UBackup keeps it only for this application session and does not persist it."
            )
        lab = QLabel(text)
        lab.setWordWrap(True)
        lay.addWidget(lab)
        self.a = QLineEdit(); self.a.setEchoMode(QLineEdit.EchoMode.Password); self.a.setPlaceholderText("Password")
        self.b = None
        lay.addWidget(self.a)
        if self.confirm:
            self.b = QLineEdit(); self.b.setEchoMode(QLineEdit.EchoMode.Password); self.b.setPlaceholderText("Repeat password")
            lay.addWidget(self.b)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self._accept); buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _accept(self):
        if not self.a.text():
            QMessageBox.warning(self, "Password", "Password cannot be empty.")
            return
        if self.confirm and self.b is not None and self.a.text() != self.b.text():
            QMessageBox.warning(self, "Password", "Passwords do not match.")
            return
        self.accept()

    @property
    def password(self): return self.a.text()


class MainWindow(QMainWindow):
    def __init__(self, paths: GuiPaths, env: dict[str, str], client: PrivilegedClient,
                 credentials: CredentialDescriptor | None = None, startup_session=None):
        super().__init__()
        self.paths = paths
        self.env = env
        self.client = client
        self.credentials = credentials
        self.startup_session = startup_session
        self.repository_initialized = bool(
            getattr(startup_session, "repository_initialized", False)
        )
        self._startup_root_item = None
        self._startup_root_complete = False
        self._startup_state = "pending" if startup_session is not None else "inactive"
        self._startup_flow = StartupFlow(startup_session is not None)
        self._startup_packages: list[dict] = []
        self._startup_configs: list[dict] = []
        self.cache = CacheDB(paths.db)
        # Own a dedicated thread pool so shutdown can drain only UBackup work
        # without depending on unrelated Qt global-pool users.
        self.pool = QThreadPool(self)
        self._closing = False
        self._cache_closed = False
        # QRunnable auto-deletion can destroy the Python/Signal wrappers before
        # queued cross-thread signals are delivered.  Besides stale task state,
        # that can leave callbacks holding deleted QTreeWidgetItems and has
        # caused native PySide crashes while expanding the filesystem tree.
        # Retain every worker until its finished signal is handled on the GUI
        # thread and disable QThreadPool's C++ auto-delete for the runnable.
        self._active_workers: dict[int, Worker] = {}
        self._backup_action_buttons: list[QPushButton] = []
        self._fs_children_inflight: set[str] = set()
        self._fs_size_inflight: set[str] = set()
        self._fs_scan_after_browse: set[str] = set()
        self._fs_force_scan_after_browse: set[str] = set()
        self._fs_auto_scan_queue: list[str] = []
        self._fs_auto_scan_queued: set[str] = set()
        self._fs_auto_scan_active: str | None = None
        self._fs_cache_refresh_inflight = False
        self._fs_cache_refresh_pending = False
        self._fs_cached_records: dict[str, dict] = {}
        self._fs_calculated_this_session: set[str] = set()
        self._fs_items_by_path: dict[str, QTreeWidgetItem] = {}
        # Policy writes are user intent. Passive/asynchronous checkbox repaint
        # must never feed back into persistence and silently replace EXCLUDE.
        self._fs_policy_revision = 0
        self._fs_check_render_depth = 0
        self.packages: list[PackageRecord] = []
        self.configs: list[ConfigRecord] = []
        self.deps: list[DependencyStatus] = []
        self.last_manifest = self.cache.get_kv("last_successful_manifest", {})
        self.current_task = ""
        self.active_dry_run = False
        self.active_backup_components: set[BackupComponent] = set()
        self.restore_state = RestoreState.IDLE
        self.tasks = TaskRegistry(self)
        self.task_dialog = None
        self._seen_paths: set[str] = set()
        self._new_unselected_paths: set[str] = set()
        self._review_ancestors: set[str] = set()
        self._review_scan_scheduled = False
        self._last_estimated_delta = 0
        if not self.cache.path_policy_rows():
            self.cache.set_path_policy("/home", SelectionPolicy.INCLUDE_RECURSIVE)
        self.setWindowTitle(f"UBackup — {paths.root}")
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.WindowMinMaxButtonsHint |
                            Qt.WindowType.WindowCloseButtonHint)
        self.resize(1440, 900)
        self._build_ui()
        QTimer.singleShot(0, self.startup_checks)

    def closeEvent(self, event):
        self.shutdown(close_cache=False)
        super().closeEvent(event)

    def shutdown(self, *, close_cache: bool = False) -> None:
        """Stop GUI-owned background work before releasing shared state.

        Qt queued signals can outlive the visual window. Closing SQLite from
        ``closeEvent`` used to race those callbacks and produced
        ``Cannot operate on a closed database`` while QThreadPool threads kept
        the process alive. The first phase stops/cancels work; the application
        closes SQLite only after ``app.exec()`` has returned and no queued GUI
        callbacks can run.
        """
        if not self._closing:
            self._closing = True
            if self._startup_state == "pending":
                self._startup_flow.cancel(); self._startup_state = "cancelled"
            dialog = getattr(self, "task_dialog", None)
            timer = getattr(dialog, "timer", None) if dialog is not None else None
            if timer is not None:
                timer.stop()
            # Prevent queued or currently running workers from delivering more
            # GUI/cache callbacks while shutdown blocks waiting for them.
            for worker in tuple(self._active_workers.values()):
                for name in ("started", "result", "error", "progress", "finished"):
                    try:
                        getattr(worker.signals, name).disconnect()
                    except (RuntimeError, TypeError):
                        pass
            self.pool.clear()
            # EOF/cancel on the authenticated session interrupts any privileged
            # RPC currently blocking a worker.
            self._safe_close_startup()
            if not self.pool.waitForDone(15000):
                print("UBackup: background workers did not stop within the shutdown budget.", file=sys.stderr)
            self._active_workers.clear()
        if close_cache and not self._cache_closed:
            self.cache.close()
            self._cache_closed = True

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        root = QHBoxLayout(central); root.setContentsMargins(0, 0, 0, 0); root.setSpacing(0)
        sidebar = QFrame(); sidebar.setObjectName("Sidebar"); sidebar.setFixedWidth(220)
        side = QVBoxLayout(sidebar); side.setContentsMargins(14, 18, 14, 18)
        title = QLabel("UBackup"); title.setObjectName("Title"); side.addWidget(title)
        sub = QLabel(str(self.paths.root)); sub.setObjectName("Muted"); sub.setWordWrap(True); side.addWidget(sub)
        side.addSpacing(18)
        self.stack = QStackedWidget()
        pages = [
            ("Dashboard", self._dashboard_page()), ("Filesystem", self._files_page()),
            ("/etc configuration", self._configs_page()), ("Packages", self._packages_page()),
            ("Exclusions", self._excludes_page()), ("Snapshots / Restore", self._restore_page()),
            ("Log", self._log_page()),
        ]
        for idx, (name, page) in enumerate(pages):
            self.stack.addWidget(page)
            b = QPushButton(name); b.setObjectName("Nav"); b.setCheckable(True); b.setAutoExclusive(True)
            b.clicked.connect(lambda _checked=False, i=idx: self.stack.setCurrentIndex(i))
            if idx == 0: b.setChecked(True)
            side.addWidget(b)
        side.addStretch(1)
        self.tasks_button = QPushButton("Background tasks")
        self.tasks_button.clicked.connect(self._show_tasks)
        side.addWidget(self.tasks_button)
        self.tasks.changed.connect(self._update_task_button)
        self.status_label = QLabel("Ready"); self.status_label.setObjectName("Muted"); self.status_label.setWordWrap(True); side.addWidget(self.status_label)
        root.addWidget(sidebar); root.addWidget(self.stack, 1)

    def _card(self, title: str, value_attr: str):
        f = QFrame(); f.setObjectName("Card"); lay = QVBoxLayout(f)
        lay.addWidget(QLabel(title)); val = QLabel("—"); val.setObjectName("CardValue"); setattr(self, value_attr, val); lay.addWidget(val)
        return f

    def _dashboard_page(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(24, 24, 24, 24)
        h = QLabel("Overview"); h.setObjectName("Title"); lay.addWidget(h)
        cards = QHBoxLayout()
        cards.addWidget(self._card("Selected sources", "card_sources"))
        cards.addWidget(self._card("Selected configs", "card_configs"))
        cards.addWidget(self._card("Kept packages", "card_packages"))
        cards.addWidget(self._card("Latest snapshot", "card_snapshot"))
        lay.addLayout(cards)

        capacity = QFrame(); capacity.setObjectName("Card"); cap = QVBoxLayout(capacity)
        cap.addWidget(QLabel("Backup filesystem capacity"))
        self.backup_capacity_bar = QProgressBar(); self.backup_capacity_bar.setRange(0, 100); cap.addWidget(self.backup_capacity_bar)
        self.backup_capacity_label = QLabel("Capacity information is loading…")
        self.backup_capacity_label.setObjectName("Muted"); self.backup_capacity_label.setWordWrap(True); cap.addWidget(self.backup_capacity_label)
        lay.addWidget(capacity)

        self.fs_usage_table = QTableWidget(0, 6)
        self.fs_usage_table.setHorizontalHeaderLabels(["Mount point", "Filesystem", "Total", "Used", "Available", "Usage"])
        self.fs_usage_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(QLabel("Real filesystems")); lay.addWidget(self.fs_usage_table, 1)

        self.dep_table = QTableWidget(0, 4); self.dep_table.setHorizontalHeaderLabels(["Dependency", "Status", "Version", "Installation"])
        self.dep_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.dep_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.dep_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(QLabel("Dependencies")); lay.addWidget(self.dep_table)

        contents = QFrame(); contents.setObjectName("Card"); contents_lay = QVBoxLayout(contents)
        contents_lay.addWidget(QLabel("Snapshot contents"))
        contents_note = QLabel(
            "Choose which data classes are included by Create snapshot and Dry-run / estimate. "
            "Package data is inventory metadata used for later APT restore; packages themselves are not copied."
        )
        contents_note.setObjectName("Muted"); contents_note.setWordWrap(True); contents_lay.addWidget(contents_note)
        contents_row = QHBoxLayout()
        self.backup_component_checks: dict[BackupComponent, QCheckBox] = {}
        for component, label in (
            (BackupComponent.FILESYSTEM, "Filesystem"),
            (BackupComponent.CONFIGS, "/etc configuration"),
            (BackupComponent.PACKAGES, "Packages"),
        ):
            check = QCheckBox(label)
            check.setChecked(self.cache.get_selected("backup-component", component.value, True))
            check.toggled.connect(lambda selected, c=component: self.cache.set_selected("backup-component", c.value, selected))
            self.backup_component_checks[component] = check
            contents_row.addWidget(check)
        contents_row.addStretch(1); contents_lay.addLayout(contents_row); lay.addWidget(contents)

        bar = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh inventories"); self.btn_refresh.clicked.connect(lambda: self.refresh_inventories(True)); bar.addWidget(self.btn_refresh)
        self.btn_preview = QPushButton("Dry-run / estimate"); self.btn_preview.clicked.connect(self.preview_backup); bar.addWidget(self.btn_preview)
        self.btn_backup = QPushButton("Create snapshot"); self.btn_backup.setObjectName("Primary"); self.btn_backup.clicked.connect(self.run_backup); bar.addWidget(self.btn_backup)
        self._backup_action_buttons.extend([self.btn_preview, self.btn_backup])
        bar.addStretch(1); lay.addLayout(bar)
        self.progress = QProgressBar(); self.progress.setRange(0, 100); self.progress.setValue(0); lay.addWidget(self.progress)
        self.live = QLabel("No operation in progress."); self.live.setObjectName("Muted"); self.live.setWordWrap(True); lay.addWidget(self.live)
        lay.addStretch(1)
        return w

    def _show_tasks(self):
        if self.task_dialog is None:
            self.task_dialog = TaskMonitorDialog(self.tasks, self)
        self.task_dialog.show(); self.task_dialog.raise_(); self.task_dialog.activateWindow()

    def _update_task_button(self):
        count = self.tasks.running_count()
        self.tasks_button.setText(f"Background tasks ({count})" if count else "Background tasks")

    def _start_worker(self, worker, name: str, *, visible: bool = True):
        if self._closing:
            return None
        worker.setAutoDelete(False)
        worker_key = id(worker)
        self._active_workers[worker_key] = worker
        task_id = self.tasks.create(name) if visible else None
        if task_id is not None:
            worker.signals.started.connect(lambda tid=task_id: self.tasks.start(tid))
            worker.signals.progress.connect(lambda value, tid=task_id: self.tasks.progress(tid, value))
            worker.signals.error.connect(lambda trace, tid=task_id: self.tasks.fail(tid, trace))
            # A successful result is already terminal. Completing here makes
            # the monitor robust even if the immediately following QRunnable
            # finished notification is delayed by Qt's queued delivery.
            worker.signals.result.connect(lambda _value, tid=task_id: self.tasks.complete(tid))
            worker.signals.finished.connect(lambda tid=task_id: self.tasks.complete(tid))
        worker.signals.finished.connect(lambda key=worker_key: self._active_workers.pop(key, None))
        self.pool.start(worker)
        return task_id

    def refresh_disk_usage(self):
        mounts = _mounted_filesystems()
        self.fs_usage_table.setRowCount(len(mounts))
        for row, info in enumerate(mounts):
            ratio = (info["used"] / info["total"] * 100.0) if info["total"] else 0.0
            for col, value in enumerate((info["mount"], info["fstype"], human_size(info["total"]), human_size(info["used"]), human_size(info["free"]), f"{ratio:.1f}%")):
                self.fs_usage_table.setItem(row, col, _table_item(value))
        try:
            usage = shutil.disk_usage(self.paths.root)
        except OSError:
            self.backup_capacity_label.setText("Backup filesystem capacity is unavailable.")
            return
        percent = int((usage.used / usage.total) * 100) if usage.total else 0
        self.backup_capacity_bar.setValue(percent)
        delta_estimate = int(self._last_estimated_delta or 0)
        repo_raw = self.cache.get_kv("repository_size", None)
        repo = int(repo_raw or 0)
        logical = int(self.cache.get_kv("logical_selected_size", 0) or 0)
        # Before the first snapshot, a measured logical selection is a useful
        # conservative capacity floor when no Restic dry-run exists yet.  For
        # incrementals we intentionally do not reuse full logical size: only a
        # fresh Restic delta estimate is meaningful.
        if delta_estimate:
            capacity_estimate = delta_estimate
            estimate_label = f"Dry-run repository delta {human_size(delta_estimate)}"
        elif not self.last_manifest and logical:
            capacity_estimate = logical
            estimate_label = f"Conservative first-backup estimate {human_size(logical)}"
        else:
            capacity_estimate = 0
            estimate_label = "Estimated next repository delta not estimated yet"
        safety = max(512 * 1024 * 1024, int(capacity_estimate * 0.15)) if capacity_estimate else 0
        sufficient = usage.free >= capacity_estimate + safety if capacity_estimate else True
        assessment = "Sufficient" if sufficient else "Insufficient"
        self.backup_capacity_label.setText(
            f"Total {human_size(usage.total)} · Used {human_size(usage.used)} · Available {human_size(usage.free)}\n"
            f"Restic repository {human_size(repo) if repo_raw is not None else 'not measured yet'} · Logical selected data {human_size(logical) if logical else 'not measured yet'} · "
            f"{estimate_label}"
            + (f" · Safety margin {human_size(safety)} · {assessment}" if capacity_estimate else "")
        )

    def refresh_repository_size(self):
        def task(progress_cb=None):
            return self.client.repository_size(progress_cb=progress_cb)
        w = Worker(task)
        def done(value):
            if isinstance(value, dict):
                self.cache.put_kv("repository_size", int(value.get("size", 0) or 0))
            self.refresh_disk_usage()
        w.signals.result.connect(done); w.signals.error.connect(self._worker_error)
        self._start_worker(w, "Measure Restic repository")

    def _files_page(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(24, 24, 24, 24)
        hdr = QHBoxLayout(); title = QLabel("Filesystem"); title.setObjectName("Title"); hdr.addWidget(title)
        hdr.addStretch(1)
        dry = QPushButton("Dry run"); dry.clicked.connect(lambda: self._start_backup(True, {BackupComponent.FILESYSTEM})); hdr.addWidget(dry)
        snap = QPushButton("Create snapshot"); snap.setObjectName("Primary"); snap.clicked.connect(lambda: self._start_backup(False, {BackupComponent.FILESYSTEM})); hdr.addWidget(snap)
        self._backup_action_buttons.extend([dry, snap])
        lay.addLayout(hdr)
        note = QLabel(
            "Checking a file includes that file. Checking a folder includes the complete folder recursively: current and future "
            "descendants are automatically considered for backup, while hard/system and enabled preconfigured exclusions "
            "such as node_modules remain excluded unless explicitly overridden where allowed. New non-excluded files therefore "
            "appear as Pending backup automatically. /etc is excluded here by default: use the /etc Configuration section, "
            "which audits and backs up only non-default/customized candidates."
        )
        note.setObjectName("Muted"); note.setWordWrap(True); lay.addWidget(note)
        actions = QHBoxLayout()
        actions.addStretch(1)
        self.show_system_excluded = QCheckBox("Show system excluded")
        self.show_system_excluded.setToolTip(
            "Show hard exclusions such as pseudo-filesystems, /swapfile, the backup root, and Ubuntu usrmerge compatibility symlinks. "
            "These entries cannot be selected for backup."
        )
        self.show_system_excluded.setChecked(self.cache.get_selected("ui", "show-system-excluded", False))
        self.show_system_excluded.toggled.connect(self._show_system_excluded_changed)
        actions.addWidget(self.show_system_excluded)
        lay.addLayout(actions)
        self.fs_tree = QTreeWidget(); self.fs_tree.setColumnCount(6); self.fs_tree.setHeaderLabels(["Path", "Size", "Total size", "Status", "Last scan", "Actions"])
        self.fs_tree.setObjectName("FilesystemTree")
        self.fs_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.fs_tree.header().resizeSection(2, 140)
        self.fs_tree.header().resizeSection(3, 240)
        self.fs_tree.header().resizeSection(4, 235)
        self.fs_tree.header().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.fs_tree.headerItem().setTextAlignment(5, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.fs_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.fs_tree.itemExpanded.connect(self._expand_fs)
        self.fs_tree.itemChanged.connect(self._fs_changed)
        self.fs_tree.currentItemChanged.connect(self._fs_current_item_changed)
        self._fs_action_item = None
        self._fs_action_widget = None
        lay.addWidget(self.fs_tree)
        self._ensure_deferred_root()
        return w

    def _fs_current_item_changed(self, current, previous) -> None:
        self._sync_fs_action_widget()

    def _clear_fs_action_widget(self) -> None:
        tree = getattr(self, "fs_tree", None)
        item = getattr(self, "_fs_action_item", None)
        widget = getattr(self, "_fs_action_widget", None)
        if tree is not None and item is not None:
            try:
                tree.removeItemWidget(item, 5)
            except RuntimeError:
                # The row may have been deleted by a full tree rebuild.
                pass
        if widget is not None:
            try:
                widget.deleteLater()
            except RuntimeError:
                pass
        self._fs_action_item = None
        self._fs_action_widget = None

    def _sync_fs_action_widget(self) -> None:
        """Show row actions only for the current filesystem row."""
        tree = getattr(self, "fs_tree", None)
        if tree is None:
            return
        current = tree.currentItem()
        if current is getattr(self, "_fs_action_item", None) and getattr(self, "_fs_action_widget", None) is not None:
            try:
                if tree.itemWidget(current, 5) is self._fs_action_widget:
                    return
            except RuntimeError:
                pass
        self._clear_fs_action_widget()
        if current is None or not current.data(0, ROLE_PATH):
            return

        path = str(current.data(0, ROLE_PATH))
        hard_excluded = self._resolver().is_hard_excluded(path)
        widget = QWidget(tree)
        widget.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(2, 1, 2, 1)
        layout.setSpacing(6)
        layout.addStretch(1)

        exclude = QPushButton("Exclude manually", widget)
        exclude.setObjectName("Danger")
        exclude.setToolTip("Persistently exclude this row from backup, including when it is selected through an ancestor.")
        exclude.setEnabled(not hard_excluded)
        exclude.clicked.connect(lambda _checked=False: self._set_current_fs_policy(SelectionPolicy.EXCLUDE))
        layout.addWidget(exclude)

        clear = QPushButton("Clear policy", widget)
        clear.setToolTip("Remove the explicit policy for this row and inherit the effective policy from its parent/defaults.")
        clear.setEnabled(not hard_excluded)
        clear.clicked.connect(lambda _checked=False: self._set_current_fs_policy(SelectionPolicy.DEFAULT))
        layout.addWidget(clear)

        recalculate = QPushButton("Recalculate", widget)
        recalculate.setToolTip("Refresh this row from the filesystem and recalculate its exclusion-aware size, ignoring cached results.")
        recalculate.setEnabled(not hard_excluded)
        recalculate.clicked.connect(lambda _checked=False: self._recalculate_current_fs_item())
        layout.addWidget(recalculate)

        tree.setItemWidget(current, 5, widget)
        self._fs_action_item = current
        self._fs_action_widget = widget

    def _recalculate_current_fs_item(self) -> None:
        item = self.fs_tree.currentItem() if hasattr(self, "fs_tree") else None
        if item is None:
            return
        path = str(item.data(0, ROLE_PATH) or "")
        if not path:
            return
        if self._resolver().is_hard_excluded(path):
            QMessageBox.information(self, "Protected path", "This path is a hard system exclusion and cannot be recalculated.")
            return
        # Recalculate is authoritative for the row: refresh directory membership
        # first (so deleted/new children are reconciled), then force a fresh
        # exclusion-aware size scan after the listing is visible.
        if item.data(0, ROLE_IS_DIR):
            self._fs_scan_after_browse.add(path)
            self._fs_force_scan_after_browse.add(path)
            self._load_children(item, force=True)
        else:
            self._start_fs_size_scan(path, force=True, require_expanded=False, task_title=f"Recalculate {path}")

    def _show_system_excluded_changed(self, checked: bool) -> None:
        self.cache.set_selected("ui", "show-system-excluded", bool(checked))
        self._refresh_system_excluded_visibility()

    def _refresh_system_excluded_visibility(self) -> None:
        if not hasattr(self, "fs_tree"):
            return
        show = bool(getattr(self, "show_system_excluded", None) and self.show_system_excluded.isChecked())
        resolver = self._resolver()
        def walk(item):
            path = item.data(0, ROLE_PATH)
            if path and path != "/":
                item.setHidden(resolver.is_hard_excluded(path) and not show)
            for index in range(item.childCount()):
                child = item.child(index)
                if child.data(0, ROLE_PATH):
                    walk(child)
        for index in range(self.fs_tree.topLevelItemCount()):
            root = self.fs_tree.topLevelItem(index)
            if root is not None:
                walk(root)

    def _configs_page(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(24, 24, 24, 24)
        hdr = QHBoxLayout(); t = QLabel("/etc configuration"); t.setObjectName("Title"); hdr.addWidget(t); hdr.addStretch(1)
        dry = QPushButton("Dry run"); dry.clicked.connect(lambda: self._start_backup(True, {BackupComponent.CONFIGS})); hdr.addWidget(dry)
        snap = QPushButton("Create snapshot"); snap.setObjectName("Primary"); snap.clicked.connect(lambda: self._start_backup(False, {BackupComponent.CONFIGS})); hdr.addWidget(snap)
        self._backup_action_buttons.extend([dry, snap])
        b = QPushButton("Rescan /etc"); b.clicked.connect(lambda: self.refresh_configs(True)); hdr.addWidget(b); lay.addLayout(hdr)
        n = QLabel(
            "Only audited candidate files are shown. Intermediate directories are virtual grouping nodes; "
            "selecting them changes only the candidate files below them and never adds the whole real /etc subtree."
        )
        n.setObjectName("Muted"); n.setWordWrap(True); lay.addWidget(n)
        self.config_tree = QTreeWidget(); self.config_tree.setColumnCount(5)
        self.config_tree.setHeaderLabels(["Path", "Type", "Package", "Size", "Status"])
        self.config_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.config_tree.header().resizeSection(4, 180)
        self.config_tree.itemChanged.connect(self._config_changed)
        lay.addWidget(self.config_tree)
        return w

    def _packages_page(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(24, 24, 24, 24)
        hdr = QHBoxLayout(); t = QLabel("Installed software packages"); t.setObjectName("Title"); hdr.addWidget(t); hdr.addStretch(1)
        dry = QPushButton("Dry run"); dry.clicked.connect(lambda: self._start_backup(True, {BackupComponent.PACKAGES})); hdr.addWidget(dry)
        snap = QPushButton("Create snapshot"); snap.setObjectName("Primary"); snap.clicked.connect(lambda: self._start_backup(False, {BackupComponent.PACKAGES})); hdr.addWidget(snap)
        self._backup_action_buttons.extend([dry, snap])
        b = QPushButton("Refresh"); b.clicked.connect(lambda: self.refresh_packages(True)); hdr.addWidget(b); lay.addLayout(hdr)
        n = QLabel("The checkbox controls which packages are kept in the restore plan. UBackup inventories APT manual packages, installed Snaps and Flatpak applications. Package payloads are not copied; restore uses the recorded package manager metadata. apt-clone remains an optional APT compatibility/export tool rather than a separate package manager.")
        n.setObjectName("Muted"); n.setWordWrap(True); lay.addWidget(n)
        self.package_table = QTableWidget(0, 9); self.package_table.setHorizontalHeaderLabels(["Keep", "Package", "Package manager", "Version", "Arch", "Installation", "Status", "Backup policy", "Custom configs"])
        self.package_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.package_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.package_table.itemChanged.connect(self._package_changed); lay.addWidget(self.package_table)
        return w

    def _excludes_page(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(24, 24, 24, 24)
        t = QLabel("Preconfigured exclusions"); t.setObjectName("Title"); lay.addWidget(t)
        n = QLabel("Enabled rules are written to the Restic exclude file. Steam userdata and compatdata are retained. steamapps/common remains disabled by default because some games may store saves inside installation directories.")
        n.setObjectName("Muted"); n.setWordWrap(True); lay.addWidget(n)
        self.excl_table = QTableWidget(len(DEFAULT_RULES), 4); self.excl_table.setHorizontalHeaderLabels(["Enabled", "Pattern", "Category", "Reason / caution"])
        self.excl_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.excl_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for row, rule in enumerate(DEFAULT_RULES):
            chk = QTableWidgetItem(); chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            active = self.cache.get_selected("exclude", rule.pattern, rule.default_enabled)
            chk.setCheckState(Qt.CheckState.Checked if active else Qt.CheckState.Unchecked); chk.setData(ROLE_PATH, rule.pattern)
            self.excl_table.setItem(row, 0, chk); self.excl_table.setItem(row, 1, _table_item(rule.pattern)); self.excl_table.setItem(row, 2, _table_item(rule.category))
            reason = rule.reason + ((" — CAUTION: " + rule.caution) if rule.caution else "")
            reason_item = _table_item(reason); reason_item.setForeground(QColor("#7893ad" if active else "#8998aa"))
            self.excl_table.setItem(row, 3, reason_item)
        self.excl_table.itemChanged.connect(self._exclude_changed); lay.addWidget(self.excl_table)
        return w

    def _restore_page(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(24, 24, 24, 24)
        hdr = QHBoxLayout(); t = QLabel("Snapshots and restore"); t.setObjectName("Title"); hdr.addWidget(t); hdr.addStretch(1)
        self.btn_consolidate_history = QPushButton("Consolidate history")
        self.btn_consolidate_history.setToolTip(
            "Keep the latest snapshot in the currently selected repository, forget all older snapshots in that same history, and prune unreferenced data."
        )
        self.btn_consolidate_history.setEnabled(False)
        self.btn_consolidate_history.clicked.connect(self.consolidate_snapshot_history)
        hdr.addWidget(self.btn_consolidate_history)
        self.btn_delete_latest_snapshot = QPushButton("Delete latest snapshot")
        self.btn_delete_latest_snapshot.setObjectName("Danger")
        self.btn_delete_latest_snapshot.setToolTip(
            "Permanently forget the latest snapshot from the currently selected repository and prune data no longer referenced there."
        )
        self.btn_delete_latest_snapshot.setEnabled(False)
        self.btn_delete_latest_snapshot.clicked.connect(self.delete_latest_snapshot)
        hdr.addWidget(self.btn_delete_latest_snapshot)
        b = QPushButton("Refresh histories"); b.clicked.connect(lambda _checked=False: self.refresh_snapshots()); hdr.addWidget(b); lay.addLayout(hdr)

        split = QSplitter()
        self.restore_domain = BackupComponent.FILESYSTEM
        self.snap_domain_tabs = QTabWidget()
        self.snap_domain_tabs.setMinimumWidth(320)
        self.snap_lists: dict[BackupComponent, QListWidget] = {}
        for component, label in (
            (BackupComponent.FILESYSTEM, "Filesystem"),
            (BackupComponent.CONFIGS, "/etc configuration"),
            (BackupComponent.PACKAGES, "Packages"),
        ):
            page = QWidget(); page_layout = QVBoxLayout(page); page_layout.setContentsMargins(6, 6, 6, 6)
            history = QListWidget()
            history.currentItemChanged.connect(
                lambda current, previous, domain=component: self._snapshot_selected(domain, current, previous)
            )
            self.snap_lists[component] = history
            page_layout.addWidget(history)
            self.snap_domain_tabs.addTab(page, label)
        self.snap_domain_tabs.currentChanged.connect(self._snapshot_domain_changed)
        self.snap_list = self.snap_lists[self.restore_domain]
        split.addWidget(self.snap_domain_tabs)

        right = QWidget(); rl = QVBoxLayout(right)
        self.snap_info = QLabel("Select a snapshot"); self.snap_info.setWordWrap(True); rl.addWidget(self.snap_info)
        self.restore_tree_label = QLabel("Files/configuration to restore"); rl.addWidget(self.restore_tree_label)
        self.restore_tree = QTreeWidget(); self.restore_tree.setColumnCount(3); self.restore_tree.setHeaderLabels(["Snapshot path", "Size", "Type"])
        self.restore_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.restore_tree.itemExpanded.connect(self._restore_expand)
        self.restore_tree.itemChanged.connect(self._restore_tree_changed)
        rl.addWidget(self.restore_tree, 2)
        self.restore_packages_label = QLabel("Packages to reinstall"); rl.addWidget(self.restore_packages_label)
        self.restore_packages = QListWidget(); rl.addWidget(self.restore_packages, 1)
        buttons = QHBoxLayout()
        stage = QPushButton("Restore to staging"); stage.clicked.connect(lambda: self.restore_selected(False)); self.btn_restore_stage = stage; buttons.addWidget(stage)
        inplace = QPushButton("Restore files in place"); inplace.setObjectName("Danger"); inplace.clicked.connect(lambda: self.restore_selected(True)); self.btn_restore_inplace = inplace; buttons.addWidget(inplace)
        aptdry = QPushButton("Simulate package restore"); aptdry.clicked.connect(lambda: self.restore_selected_packages(True)); self.btn_apt_simulate = aptdry; buttons.addWidget(aptdry)
        apt = QPushButton("Reinstall packages"); apt.clicked.connect(lambda: self.restore_selected_packages(False)); self.btn_apt_install = apt; buttons.addWidget(apt)
        for button in (stage, inplace, aptdry, apt): button.setEnabled(False)
        rl.addLayout(buttons); split.addWidget(right); split.setStretchFactor(1, 2); lay.addWidget(split)
        self._update_restore_domain_visibility()
        return w

    def _snapshot_domain_changed(self, index: int) -> None:
        domains = (BackupComponent.FILESYSTEM, BackupComponent.CONFIGS, BackupComponent.PACKAGES)
        if not 0 <= index < len(domains):
            return
        self.restore_domain = domains[index]
        self.snap_list = self.snap_lists[self.restore_domain]
        self._update_restore_domain_visibility()
        self._snapshot_selected(self.restore_domain, self.snap_list.currentItem(), None)

    def _update_restore_domain_visibility(self) -> None:
        packages = getattr(self, "restore_domain", BackupComponent.FILESYSTEM) == BackupComponent.PACKAGES
        for widget in (getattr(self, "restore_tree_label", None), getattr(self, "restore_tree", None)):
            if widget is not None: widget.setVisible(not packages)
        for widget in (getattr(self, "restore_packages_label", None), getattr(self, "restore_packages", None)):
            if widget is not None: widget.setVisible(packages)
        self._set_restore_actions(bool(getattr(self, "restore_metadata_loaded", False)))

    def _log_page(self):
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(24,24,24,24)
        t = QLabel("Session log"); t.setObjectName("Title"); lay.addWidget(t)
        from PySide6.QtWidgets import QTextEdit
        self.log_box = QTextEdit(); self.log_box.setReadOnly(True); lay.addWidget(self.log_box)
        return w

    def log(self, text: str):
        self.log_box.append(text)
        self.status_label.setText(text[-180:])

    def startup_checks(self):
        w = Worker(lambda progress_cb=None: self.client.dependency_status())
        w.signals.result.connect(self._startup_dependencies_loaded)
        w.signals.error.connect(self._worker_error)
        self._start_worker(w, "Check dependencies")

    def _startup_dependencies_loaded(self, deps):
        self.deps = deps; self._fill_deps()
        missing = [d.command for d in self.deps if d.required and not d.installed]
        if missing:
            for button in self._backup_action_buttons:
                button.setEnabled(False)
            QMessageBox.critical(self, "Missing dependencies", "Required dependencies are missing: " + ", ".join(missing) + ".\n\nInstall them with APT and restart UBackup. The application does not auto-install system dependencies.")
            if self.startup_session is not None:
                self._safe_close_startup(); self.startup_session = None
            if self._startup_state == "pending":
                self._startup_flow.cancel(); self._startup_state = "cancelled"
            self._reset_deferred_root()
            self.update_cards()
            return
        if self.startup_session is None:
            self.log("Privileged startup session is unavailable.")
            return
        credentials = self._credential_for_request()
        if credentials is None:
            self.log("Automatic startup cancelled: Restic credentials were not provided.")
            if self._startup_state == "pending":
                self._startup_flow.cancel(); self._startup_state = "cancelled"
            try:
                self.startup_session.cancel()
            except Exception as exc:
                self.log(f"Closing startup session: {exc}")
            self._safe_close_startup(); self.startup_session = None
            self._reset_deferred_root()
            self.update_cards()
            return
        session = self.startup_session
        def task(progress_cb=None):
            session.start(password=credentials.password, password_file=credentials.password_file)
            for frame in session.events():
                if progress_cb is not None:
                    progress_cb(frame)
        w = Worker(task)
        w.signals.progress.connect(self._startup_frame)
        w.signals.result.connect(self._startup_success)
        w.signals.finished.connect(self._startup_worker_finished)
        w.signals.error.connect(self._startup_failed)
        self._start_worker(w, "Initial privileged inventory")
        self.update_cards()

    def _startup_frame(self, frame):
        if not self._startup_flow.accept_frame(frame):
            return
        if isinstance(frame, dict) and frame.get("type") == "navigation-ready":
            return
        if not isinstance(frame, dict) or frame.get("type") != "result":
            self.log("Unexpected startup frame: " + str(frame))
            return
        section = frame.get("section")
        records = frame.get("records", [])
        if section == "filesystem-children":
            self._startup_root_page(records, bool(frame.get("final")), bool(frame.get("truncated")))
        elif section == "package-inventory":
            self._startup_packages.extend(records)
            self._packages_loaded(self._startup_packages)
        elif section == "config-inventory":
            self._startup_configs.extend(records)
            self._configs_loaded(self._startup_configs)
        else:
            self.log("Unexpected startup section: " + str(section))

    def _startup_root_page(self, records, final, truncated):
        if self._startup_root_item is None:
            self._clear_fs_action_widget()
            self._fs_items_by_path.clear()
            self.fs_tree.blockSignals(True); self.fs_tree.clear()
            self._startup_root_item = self._make_fs_item(Path("/"), True, None, 0)
            self._startup_root_item.takeChildren()
            self._startup_root_item.setData(0, ROLE_LOADED, False)
            self.fs_tree.addTopLevelItem(self._startup_root_item)
            self.fs_tree.blockSignals(False)
        if self._startup_root_item.childCount() and not self._startup_root_item.child(self._startup_root_item.childCount() - 1).data(0, ROLE_PATH):
            self._startup_root_item.takeChild(self._startup_root_item.childCount() - 1)
        for record in records:
            path = Path(record.get("path", record.get("name", "")))
            if str(path):
                blocked = bool(record.get("blocked", False)) or record.get("type") == "blocked-dir"
                is_dir = record.get("type") in {"dir", "blocked-dir"}
                self._startup_root_item.addChild(self._make_fs_item(
                    path, is_dir, record.get("size"), record.get("mtime_ns", 0),
                    blocked=blocked, scanned_at=record.get("scanned_at"), cache_stale=bool(record.get("cache_stale", False)),
                    total_size=record.get("total_size"), is_symlink=bool(record.get("symlink", False)),
                ))
        self._refresh_item_and_ancestors(self._startup_root_item)
        self._refresh_system_excluded_visibility()
        if not final:
            self._startup_root_item.setData(0, ROLE_LOADED, False)
            self._startup_root_item.addChild(FilesystemTreeItem(["…", "", "", "", "", ""]))
        else:
            self._startup_root_complete = True
            self._startup_flow.mark_root_complete()
            self._startup_root_item.setData(0, ROLE_LOADED, True)
            self._startup_root_item.setExpanded(True)
            self.log("Initial filesystem loaded" + (" (limit reached)" if truncated else ""))

    def _startup_worker_finished(self):
        # The authenticated helper intentionally remains alive after startup.
        # It is the sole privileged RPC channel for the lifetime of the GUI.
        pass

    def _startup_success(self, _value=True):
        if not self._startup_flow.succeed():
            return
        self._startup_state = "success"
        if not self._startup_root_complete:
            self._reset_deferred_root()
        self.log("Initial inventories loaded. Privileged helper session is ready.")
        # Give interactive filesystem browsing priority over the optional
        # discovery frontier scan immediately after startup.
        QTimer.singleShot(1000, self._schedule_review_refresh)
        # Credentials are now bound to the root helper.  Keep only a non-secret
        # sentinel in the GUI so later operations do not prompt again and do
        # not retain the Restic password in the desktop process.
        if getattr(self.client, "uses_persistent_session", False):
            self.credentials = CredentialDescriptor()
        # Startup intentionally does not trust filesystem size cache without
        # knowing the GUI's current exclusion profile. Refresh visible root
        # rows now through the authenticated profile-aware inspect channel.
        self._refresh_children_cache("/")
        self._refresh_visible_fs_cache()
        self.refresh_snapshots()
        self.refresh_disk_usage()

    def _startup_failed(self, trace):
        if not self._startup_flow.fail():
            return
        self._startup_state = "failed"
        self._safe_close_startup()
        self._reset_deferred_root()
        self._worker_error(trace)

    def _safe_close_startup(self):
        session = self.startup_session
        if session is None:
            return
        try:
            session.close()
        except Exception as exc:
            self.log(f"Closing startup session: {exc}")
        finally:
            self.startup_session = None

    def _ensure_deferred_root(self):
        if self._startup_root_item is not None:
            return self._startup_root_item
        self._clear_fs_action_widget()
        self.fs_tree.blockSignals(True)
        self.fs_tree.clear()
        item = self._make_fs_item(Path("/"), True, None, 0)
        item.setData(0, ROLE_LOADED, False)
        item.setExpanded(False)
        self.fs_tree.addTopLevelItem(item)
        self.fs_tree.blockSignals(False)
        self._startup_root_item = item
        return item

    def _reset_deferred_root(self):
        item = self._ensure_deferred_root()
        self.fs_tree.blockSignals(True)
        item.takeChildren()
        item.addChild(FilesystemTreeItem(["…", "", "", "", "", ""]))
        item.setData(0, ROLE_LOADED, False)
        item.setExpanded(False)
        self.fs_tree.blockSignals(False)
        self._startup_root_complete = False

    def _credential_for_request(self):
        if self.credentials is not None:
            return self.credentials
        dlg = PasswordDialog(self, confirm=not self.repository_initialized)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None
        self.credentials = CredentialDescriptor(password=dlg.password)
        return self.credentials

    def _fill_deps(self):
        self.dep_table.setRowCount(len(self.deps))
        for r, d in enumerate(self.deps):
            self.dep_table.setItem(r, 0, _table_item(d.name + (" *" if d.required else "")))
            status = _table_item(semantic_label(d.state))
            status.setForeground(QColor(semantic_color(d.state)))
            self.dep_table.setItem(r, 1, status)
            self.dep_table.setItem(r, 2, _table_item(d.version or ("Unavailable" if d.installed else "—")))
            self.dep_table.setItem(r, 3, _table_item(d.install_hint))

    def _populate_root(self):
        self._clear_fs_action_widget()
        self._fs_items_by_path.clear()
        self.fs_tree.blockSignals(True); self.fs_tree.clear()
        item = self._make_fs_item(Path("/"), True, None, 0); item.setExpanded(True); self.fs_tree.addTopLevelItem(item)
        self.fs_tree.blockSignals(False)
        self._load_children(item)

    def _has_persisted_descendant_selection_mismatch(
        self, path: str, selected: bool, *, resolver: SelectionResolver | None = None,
        policy_rows: list[tuple[str, SelectionPolicy]] | None = None,
    ) -> bool:
        """Whether a closed tree node already contains an explicit contrary policy.

        This keeps the tri-state checkbox meaningful before descendants are
        expanded.  The value is derived from persistent policy; it is never
        stored as a policy itself.
        """
        prefix = path.rstrip("/") + "/" if path != "/" else "/"
        if resolver is None or policy_rows is None:
            resolver, policy_rows = self._selection_context()
        for child_path, _policy in policy_rows:
            if child_path == path or not child_path.startswith(prefix):
                continue
            if resolver.resolve(child_path).selected != selected:
                return True
        return False

    def _has_persisted_selected_descendant(
        self, path: str, *, resolver: SelectionResolver | None = None,
        policy_rows: list[tuple[str, SelectionPolicy]] | None = None,
    ) -> bool:
        """Whether an otherwise-unselected directory contains selected policy islands."""
        prefix = path.rstrip("/") + "/" if path != "/" else "/"
        if resolver is None or policy_rows is None:
            resolver, policy_rows = self._selection_context()
        for child_path, _policy in policy_rows:
            if child_path == path or not child_path.startswith(prefix):
                continue
            if resolver.resolve(child_path).selected:
                return True
        return False

    def _child_sizes_for_sum(
        self, child, *, resolver: SelectionResolver | None = None,
    ) -> tuple[int | None, int | None, bool, float] | None:
        """Return effective/physical contribution from one materialized child.

        Stale cache remains usable by design and propagates a stale marker to
        the derived parent. Missing aggregates are the only reason aggregation
        must wait for a background size scan.
        """
        path = str(child.data(0, ROLE_PATH) or "")
        if not path:
            return None
        if resolver is None:
            resolver = self._resolver()
        decision = resolver.resolve(path, is_dir=bool(child.data(0, ROLE_IS_DIR)))
        raw_size = child.data(0, ROLE_SIZE)
        raw_total = child.data(0, ROLE_TOTAL_SIZE)
        protected_zero = decision.exclusion_origin in {ExclusionOrigin.SYSTEM, ExclusionOrigin.BACKUP_ROOT}
        if isinstance(raw_total, (int, float)):
            physical: int | None = max(0, int(raw_total))
        elif protected_zero:
            # UBackup deliberately never scans pseudo-filesystems or the backup
            # root. They are therefore a known zero contribution to both
            # displayed aggregates rather than an unknown child that prevents
            # root/ancestor recomputation forever.
            physical = 0
        else:
            physical = None
        if decision.exclusion_origin is not ExclusionOrigin.NONE:
            effective: int | None = 0
        elif isinstance(raw_size, (int, float)):
            effective = max(0, int(raw_size))
        else:
            effective = None
        scanned_at = float(child.data(0, ROLE_SCANNED_AT) or 0.0)
        if child.data(0, ROLE_IS_DIR) and not scanned_at and not protected_zero:
            effective = None
            physical = None
        if effective is None and physical is None:
            return None
        return effective, physical, bool(child.data(0, ROLE_CACHE_STALE)), scanned_at

    def _child_effective_size_for_sum(
        self, child, *, allow_profile_reuse: bool = False, resolver: SelectionResolver | None = None,
    ) -> int | None:
        """Compatibility wrapper used by focused tests/helpers."""
        values = self._child_sizes_for_sum(child, resolver=resolver)
        return None if values is None else values[0]

    def _recompute_loaded_directory_size(
        self, item, *, allow_profile_reuse: bool = False, resolver: SelectionResolver | None = None,
    ) -> bool:
        """Derive ``Size`` and ``Total size`` from direct materialized children."""
        if item is None or not item.data(0, ROLE_IS_DIR) or not item.data(0, ROLE_LOADED):
            return False
        path = str(item.data(0, ROLE_PATH) or "")
        if not path or path in self._fs_children_inflight:
            return False
        if resolver is None:
            resolver = self._resolver()
        effective_total = 0
        physical_total = 0
        effective_complete = True
        physical_complete = True
        stale = False
        scan_times: list[float] = []
        for index in range(item.childCount()):
            child = item.child(index)
            if not child.data(0, ROLE_PATH):
                return False
            values = self._child_sizes_for_sum(child, resolver=resolver)
            if values is None:
                return False
            effective, physical, child_stale, scanned_at = values
            if effective is None:
                effective_complete = False
            else:
                effective_total += effective
            if physical is None:
                physical_complete = False
            else:
                physical_total += physical
            stale = stale or child_stale
            if scanned_at > 0:
                scan_times.append(scanned_at)
        if not effective_complete and not physical_complete:
            return False
        if effective_complete:
            self._set_fs_size(item, effective_total)
        if physical_complete:
            self._set_fs_total_size(
                item, physical_total,
                "Total filesystem bytes under this row, independent of backup selection policy.",
            )
        scanned_at = min(scan_times) if scan_times else float(item.data(0, ROLE_SCANNED_AT) or time.time())
        item.setData(0, ROLE_SCANNED_AT, scanned_at)
        item.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key())
        item.setData(0, ROLE_CACHE_STALE, stale)
        _set_scan_status(item, scanned_at, cached=True, stale=stale)
        return True

    def _recompute_loaded_size_and_ancestors(
        self, item, *, allow_profile_reuse: bool = False,
        resolver: SelectionResolver | None = None,
    ) -> None:
        """Recompute loaded ancestors in bounded Qt event-loop chunks."""
        if item is None:
            return
        if resolver is None:
            resolver, _policy_rows = self._selection_context((), known_paths_override=set())

        policy_revision = int(getattr(self, "_fs_policy_revision", 0))
        current = item
        child_index = 0
        effective_total = 0
        physical_total = 0
        effective_complete = True
        physical_complete = True
        stale = False
        scan_times: list[float] = []

        def process_chunk() -> None:
            nonlocal current, child_index, effective_total, physical_total, effective_complete, physical_complete, stale, scan_times
            if getattr(self, "_closing", False):
                return
            if policy_revision != int(getattr(self, "_fs_policy_revision", policy_revision)):
                return

            while current is not None:
                if not current.data(0, ROLE_IS_DIR) or not current.data(0, ROLE_LOADED):
                    return
                current_path = str(current.data(0, ROLE_PATH) or "")
                if not current_path or current_path in self._fs_children_inflight:
                    return

                processed = 0
                while child_index < current.childCount() and processed < FS_RENDER_CHUNK_SIZE:
                    child = current.child(child_index)
                    if not child.data(0, ROLE_PATH):
                        return
                    values = self._child_sizes_for_sum(child, resolver=resolver)
                    if values is None:
                        return
                    effective, physical, child_stale, scanned_at = values
                    if effective is None:
                        effective_complete = False
                    else:
                        effective_total += effective
                    if physical is None:
                        physical_complete = False
                    else:
                        physical_total += physical
                    stale = stale or child_stale
                    if scanned_at > 0:
                        scan_times.append(scanned_at)
                    child_index += 1
                    processed += 1

                if child_index < current.childCount():
                    QTimer.singleShot(0, process_chunk)
                    return

                if effective_complete:
                    self._set_fs_size(current, effective_total)
                if physical_complete:
                    self._set_fs_total_size(
                        current, physical_total,
                        "Total filesystem bytes under this row, independent of backup selection policy.",
                    )
                scanned_at = min(scan_times) if scan_times else float(current.data(0, ROLE_SCANNED_AT) or time.time())
                current.setData(0, ROLE_SCANNED_AT, scanned_at)
                current.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key())
                current.setData(0, ROLE_CACHE_STALE, stale)
                _set_scan_status(current, scanned_at, cached=True, stale=stale)
                parent = current.parent()
                if parent is not None:
                    self._sort_fs_children(parent)
                current = parent
                child_index = 0
                effective_total = 0
                physical_total = 0
                effective_complete = True
                physical_complete = True
                stale = False
                scan_times = []

        process_chunk()

    def _recompute_all_loaded_directory_sizes(self) -> None:
        """Refresh every fully scanned expanded branch from child sizes."""
        resolver, _policy_rows = self._selection_context([
            str(item.data(0, ROLE_PATH))
            for item in self._visible_fs_items()
            if item.data(0, ROLE_PATH)
        ])
        def walk(item) -> None:
            for index in range(item.childCount()):
                child = item.child(index)
                if child.data(0, ROLE_PATH):
                    walk(child)
            if self._recompute_loaded_directory_size(item, resolver=resolver):
                parent = item.parent()
                if parent is not None:
                    self._sort_fs_children(parent)

        for index in range(self.fs_tree.topLevelItemCount()):
            root = self.fs_tree.topLevelItem(index)
            if root is not None:
                walk(root)

    def _apply_manual_exclusion_size(self, item) -> None:
        """Apply a local exclusion without rescanning or subtracting deltas.

        The excluded subtree contributes exactly zero. Ancestors are then
        recomputed from their already displayed direct children, bottom-up.
        If an ancestor is not expanded or has an unscanned child, aggregation
        stops there rather than guessing. ``Total size`` is untouched.
        """
        if item is None:
            return
        current_key = self._current_fs_scan_key()
        # Only the excluded subtree root is needed for ancestor accounting.
        # Descendant rows are repainted once by _refresh_policy_branch, avoiding
        # a second full traversal of a large expanded branch on the GUI thread.
        self._set_fs_size(item, 0)
        item.setData(0, ROLE_SCAN_KEY, current_key)
        parent = item.parent()
        if parent is not None:
            self._recompute_loaded_size_and_ancestors(parent, allow_profile_reuse=True)

    def _make_fs_item(
        self, path: Path, is_dir: bool, size: int | None, mtime_ns: int, *,
        blocked: bool = False, scanned_at: float | None = None, cache_stale: bool = False,
        total_size: int | None = None, is_symlink: bool = False,
        resolver: SelectionResolver | None = None,
        policy_rows: list[tuple[str, SelectionPolicy]] | None = None,
    ):
        path_text = str(path)
        self._seen_paths.add(path_text)
        if resolver is None or policy_rows is None:
            resolver, policy_rows = self._selection_context()
        decision = resolver.resolve(path_text, is_dir=is_dir)
        # Folder selection semantics are recursive in the current model. The
        # migration path is rare; avoid a SQLite lookup for every rendered row.
        if is_dir and decision.explicit_policy is SelectionPolicy.INCLUDE:
            self.cache.set_path_policy(path_text, SelectionPolicy.INCLUDE_RECURSIVE)
            resolver, policy_rows = self._selection_context()
            decision = resolver.resolve(path_text, is_dir=is_dir)
        display_state = self._display_backup_state(path_text, decision.backup_state)
        if decision.exclusion_origin is not ExclusionOrigin.NONE:
            size = 0
        scan_label = scan_status_label(scanned_at, cached=True, stale=cache_stale)
        item = FilesystemTreeItem([path.name or "/", human_size(size), "—", STATUS_LABELS[display_state], scan_label, ""])
        item.setData(0, ROLE_PATH, path_text); item.setData(0, ROLE_IS_DIR, is_dir); item.setData(0, ROLE_LOADED, False)
        item.setData(0, ROLE_POLICY, decision.explicit_policy.value); item.setData(0, ROLE_STATE, display_state.value)
        item.setData(0, ROLE_SIZE, int(size) if size is not None else None)
        item.setData(0, ROLE_SCANNED_AT, float(scanned_at or 0.0))
        item.setData(0, ROLE_CACHE_STALE, bool(cache_stale))
        item.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key() if scanned_at else "")
        item.setData(0, ROLE_TOTAL_SIZE, int(total_size) if total_size is not None else None)
        item.setData(0, ROLE_IS_SYMLINK, bool(is_symlink))
        _set_text(item, 2, human_size(int(total_size) if total_size is not None else None))
        if not blocked and not resolver.is_hard_excluded(path_text):
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            if is_dir and self._has_persisted_descendant_selection_mismatch(
                path_text, decision.selected, resolver=resolver, policy_rows=policy_rows
            ):
                initial_check = Qt.CheckState.PartiallyChecked
            else:
                initial_check = Qt.CheckState.Checked if decision.selected else Qt.CheckState.Unchecked
            item.setData(0, ROLE_RENDERED_CHECK, int(initial_check.value))
            item.setCheckState(0, initial_check)
        else:
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
        if is_dir and not blocked and not resolver.is_hard_excluded(path_text):
            item.addChild(FilesystemTreeItem(["…", "", "", "", "", ""]))
        for column in range(6): item.setToolTip(column, item.text(column))
        item.setToolTip(0, path_text)
        if scanned_at:
            _set_scan_status(item, scanned_at, cached=True, stale=cache_stale)
        self._style_status(item, display_state)
        self._fs_items_by_path[path_text] = item
        return item

    def _set_fs_size(self, item, size: int | None) -> None:
        value = int(size) if size is not None else None
        item.setData(0, ROLE_SIZE, value)
        _set_text(item, 1, human_size(value))

    def _set_fs_total_size(self, item, size: int | None, tooltip: str | None = None) -> None:
        value = int(size) if size is not None else None
        item.setData(0, ROLE_TOTAL_SIZE, value)
        _set_text(item, 2, human_size(value))
        if tooltip:
            item.setToolTip(2, tooltip)

    def _set_fs_selected_size(self, item, size: int | None, tooltip: str | None = None) -> None:
        """Compatibility wrapper for the former Selected size column."""
        self._set_fs_total_size(item, size, tooltip)

    def _set_fs_check_state(self, item, state: Qt.CheckState) -> None:
        """Render checkbox state without turning presentation into user policy.

        ``QTreeWidget.itemChanged`` is emitted for both real user toggles and
        programmatic data/check-state changes.  Persisting both made a stale
        asynchronous repaint capable of replacing a durable EXCLUDE with an
        INCLUDE.  A dedicated render guard is required here: merely storing a
        marker with ``setData`` is not sufficient because that marker write can
        itself emit ``itemChanged`` before ``setCheckState`` runs.
        """
        self._fs_check_render_depth += 1
        try:
            item.setData(0, ROLE_RENDERED_CHECK, int(state.value))
            item.setCheckState(0, state)
        finally:
            self._fs_check_render_depth -= 1

    def _mark_fs_user_check_consumed(self, item, state: Qt.CheckState) -> None:
        """Record a real user checkbox value without recursively handling it."""
        self._fs_check_render_depth += 1
        try:
            item.setData(0, ROLE_RENDERED_CHECK, int(state.value))
        finally:
            self._fs_check_render_depth -= 1

    def _current_fs_scan_key(self) -> str:
        return scan_cache_key(self._filesystem_scan_patterns())

    def _fs_sort_key(self, item) -> tuple[int, int, str]:
        raw_state = item.data(0, ROLE_STATE)
        try:
            state = BackupState(raw_state)
        except (ValueError, TypeError):
            state = BackupState.NOT_SELECTED
        raw_size = item.data(0, ROLE_SIZE)
        size = int(raw_size) if isinstance(raw_size, (int, float)) else -1
        name = Path(str(item.data(0, ROLE_PATH) or item.text(0))).name.casefold() or "/"
        return filesystem_order_key(state, size if size >= 0 else None, name)

    def _sort_fs_children(self, parent) -> None:
        """Sort a branch without detaching any Qt tree items.

        Manual ``takeChildren()/addChildren()`` reparenting caused native Qt
        expansion state to be lost whenever asynchronous scan results changed
        a row's status or size.  ``QTreeWidgetItem.sortChildren`` uses the
        filesystem item's ``__lt__`` comparator while keeping the tree nodes
        attached, so expanded branches and the current row remain intact.
        """
        if parent is None or parent.childCount() < 2:
            return
        if parent.childCount() > MAX_SYNC_FS_SORT_CHILDREN:
            return
        tree = getattr(self, "fs_tree", None)
        previous_block = tree.blockSignals(True) if tree is not None else False
        try:
            parent.sortChildren(0, Qt.SortOrder.AscendingOrder)
        finally:
            if tree is not None:
                tree.blockSignals(previous_block)
        if tree is not None:
            self._sync_fs_action_widget()

    def _forget_fs_item(self, item) -> None:
        if item is None:
            return
        for index in range(item.childCount()):
            child = item.child(index)
            if child.data(0, ROLE_PATH):
                self._forget_fs_item(child)
        path = str(item.data(0, ROLE_PATH) or "")
        if path and self._fs_items_by_path.get(path) is item:
            self._fs_items_by_path.pop(path, None)

    def _find_fs_item(self, path: str):
        """Resolve a current tree item in O(1) for scan/progress callbacks."""
        if not path or not hasattr(self, "fs_tree"):
            return None
        cached = self._fs_items_by_path.get(path)
        if cached is not None:
            try:
                if cached.data(0, ROLE_PATH) == path:
                    return cached
            except RuntimeError:
                pass
            self._fs_items_by_path.pop(path, None)
        stack = [self.fs_tree.topLevelItem(i) for i in range(self.fs_tree.topLevelItemCount())]
        while stack:
            current = stack.pop()
            if current is None:
                continue
            current_path = current.data(0, ROLE_PATH)
            if current_path:
                self._fs_items_by_path[str(current_path)] = current
            if current_path == path:
                return current
            stack.extend(current.child(i) for i in range(current.childCount()))
        return None

    def _load_children(self, item, *, force: bool = False):
        if item.data(0, ROLE_LOADED) and not force:
            return
        path = str(item.data(0, ROLE_PATH))
        if self._resolver().is_hard_excluded(path):
            return
        if path in self._fs_children_inflight:
            return

        # Navigation is intentionally live and one-level. The persistent cache
        # stores only per-path size aggregates; it is never used as a dirtree.
        item.setData(0, ROLE_LOADED, True)
        self._fs_children_inflight.add(path)
        patterns = self._filesystem_scan_patterns()
        previous_snapshot = str((self.last_manifest or {}).get("snapshot_id", ""))

        def task(progress_cb=None):
            pages, offset = [], 0
            directory_cache = None
            while True:
                page = self.client.filesystem_children(
                    path, limit=FS_BROWSE_LIMIT, offset=offset, exclude_patterns=patterns,
                )
                if isinstance(page, dict):
                    directory_cache = page.get("directory_cache") or directory_cache
                records, next_offset = _records_page(page)
                pages.extend(records)
                if progress_cb is not None and records:
                    progress_cb({"current_item": records[-1].get("path", path), "items_processed": len(pages)})
                if next_offset is None:
                    context_paths = [path]
                    context_paths.extend(
                        str(record.get("path", "")) for record in pages if record.get("path")
                    )
                    known_paths = (
                        self.cache.known_paths_for(context_paths, previous_snapshot)
                        if previous_snapshot else set()
                    )
                    return {
                        "records": pages, "known_paths": known_paths,
                        "directory_cache": directory_cache,
                    }
                offset = next_offset

        worker = Worker(task)
        worker.signals.result.connect(
            lambda result, p=path, f=force: self._fs_children_request_done(p, result, force=f)
        )
        worker.signals.error.connect(lambda trace, p=path: self._fs_children_failed(p, trace))
        self._start_worker(worker, f"Browse {path}")

    def _fs_children_request_done(self, path: str, result, *, force: bool) -> None:
        records = result.get("records", []) if isinstance(result, dict) else result
        known_paths = result.get("known_paths") if isinstance(result, dict) else None
        if isinstance(result, dict):
            item = self._find_fs_item(path)
            directory_cache = result.get("directory_cache")
            if item is not None and isinstance(directory_cache, dict):
                self._set_fs_size(item, int(directory_cache.get("size", 0) or 0))
                self._set_fs_total_size(
                    item, int(directory_cache.get("total_size", 0) or 0),
                    "Total filesystem bytes under this row, independent of backup selection policy.",
                )
                scanned_at = float(directory_cache.get("scanned_at", 0.0) or 0.0)
                stale = bool(directory_cache.get("cache_stale", False))
                item.setData(0, ROLE_SCANNED_AT, scanned_at)
                item.setData(0, ROLE_CACHE_STALE, stale)
                item.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key() if scanned_at else "")
                if scanned_at:
                    _set_scan_status(item, scanned_at, cached=True, stale=stale)
        self._fs_children_loaded(path, records, known_paths=known_paths)

    def _fs_children_loaded(self, path: str, records, *, known_paths: set[str] | None = None):
        item = self._find_fs_item(path)
        if item is None:
            self._fs_children_inflight.discard(path)
            self._fs_scan_after_browse.discard(path)
            return

        # Reconciliation is intentionally sliced across Qt event-loop turns.
        # A directory may contain up to 10k entries; inserting/resolving them in
        # one queued result callback made GNOME classify the GUI as hung even
        # though the privileged browse itself was running in a worker thread.
        records = list(records or [])
        existing = {
            str(item.child(index).data(0, ROLE_PATH)): item.child(index)
            for index in range(item.childCount())
            if item.child(index).data(0, ROLE_PATH)
        }
        for index in range(item.childCount() - 1, -1, -1):
            if not item.child(index).data(0, ROLE_PATH):
                item.takeChild(index)
        seen: set[str] = set()
        resolver, policy_rows = self._selection_context(
            (), known_paths_override=known_paths
        )
        policy_revision = self._fs_policy_revision
        chunk_size = FS_RENDER_CHUNK_SIZE

        def ensure_current_policy_context() -> None:
            nonlocal resolver, policy_rows, policy_revision
            if policy_revision == self._fs_policy_revision:
                return
            resolver, policy_rows = self._selection_context(
                (), known_paths_override=known_paths
            )
            policy_revision = self._fs_policy_revision

        def finish() -> None:
            current_item = self._find_fs_item(path)
            if current_item is not item:
                self._fs_children_inflight.discard(path)
                return
            tree_blocked = self.fs_tree.blockSignals(True)
            try:
                for child_path, child in existing.items():
                    if child_path not in seen and child.parent() is item:
                        self._forget_fs_item(child)
                        item.removeChild(child)
            finally:
                self.fs_tree.blockSignals(tree_blocked)
            self._fs_children_inflight.discard(path)
            self._review_ancestors = review_ancestor_paths(self._new_unselected_paths)
            self._sort_fs_children(item)
            self._recompute_loaded_size_and_ancestors(item)
            ancestor_paths: list[str] = []
            current = item
            while current is not None:
                current_path = current.data(0, ROLE_PATH)
                if current_path:
                    ancestor_paths.append(str(current_path))
                current = current.parent()
            current_resolver, current_rows = self._selection_context(ancestor_paths)
            self._refresh_item_and_ancestors_chunked(
                item, resolver=current_resolver, policy_rows=current_rows
            )
            self._queue_missing_child_scans(records)
            if path in self._fs_scan_after_browse:
                self._fs_scan_after_browse.discard(path)
                forced = path in self._fs_force_scan_after_browse
                self._fs_force_scan_after_browse.discard(path)
                if forced:
                    QTimer.singleShot(75, lambda p=path: self._start_fs_size_scan(
                        p, force=True, require_expanded=False, task_title=f"Recalculate {p}"
                    ))

        def render_from(offset: int) -> None:
            if self._closing:
                self._fs_children_inflight.discard(path)
                return
            current_item = self._find_fs_item(path)
            if current_item is not item:
                self._fs_children_inflight.discard(path)
                return
            ensure_current_policy_context()
            batch = records[offset:offset + chunk_size]
            tree_blocked = self.fs_tree.blockSignals(True)
            try:
                for record in batch:
                    child_path = Path(record.get("path", record.get("name", "")))
                    child_text = str(child_path)
                    if not child_text:
                        continue
                    seen.add(child_text)
                    blocked = bool(record.get("blocked", False)) or record.get("type") == "blocked-dir"
                    is_dir = record.get("type") in {"dir", "blocked-dir"} or bool(record.get("is_dir", False))
                    child = existing.get(child_text)
                    if child is not None and bool(child.data(0, ROLE_IS_DIR)) != is_dir:
                        self._forget_fs_item(child)
                        item.removeChild(child)
                        child = None
                    if child is None:
                        child = self._make_fs_item(
                            child_path, is_dir, record.get("size"), record.get("mtime_ns", 0),
                            blocked=blocked, scanned_at=record.get("scanned_at"),
                            cache_stale=bool(record.get("cache_stale", False)),
                            total_size=record.get("total_size"),
                            is_symlink=bool(record.get("symlink", False)),
                            resolver=resolver, policy_rows=policy_rows,
                        )
                        item.addChild(child)
                    else:
                        child.setData(0, ROLE_IS_SYMLINK, bool(record.get("symlink", False)))
                        size = record.get("size")
                        if size is not None:
                            self._set_fs_size(child, size)
                        if record.get("total_size") is not None:
                            self._set_fs_total_size(
                                child, int(record.get("total_size", 0) or 0),
                                "Total filesystem bytes under this row, independent of backup selection policy.",
                            )
                        scanned_at = float(record.get("scanned_at", 0.0) or 0.0)
                        cache_stale = bool(record.get("cache_stale", False))
                        child.setData(0, ROLE_SCANNED_AT, scanned_at)
                        child.setData(0, ROLE_CACHE_STALE, cache_stale)
                        child.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key() if scanned_at else "")
                        if scanned_at:
                            _set_scan_status(child, scanned_at, cached=True, stale=cache_stale)
                        elif child_text not in self._fs_size_inflight:
                            _set_text(child, 4, "—")
                            for column in (1, 2, 4):
                                child.setForeground(column, QBrush())
                        self._refresh_one_fs_item(child, resolver=resolver, policy_rows=policy_rows)
                    show_system = bool(
                        getattr(self, "show_system_excluded", None)
                        and self.show_system_excluded.isChecked()
                    )
                    child.setHidden(resolver.is_hard_excluded(child_text) and not show_system)
                    if child.data(0, ROLE_STATE) == BackupState.REVIEW_REQUIRED.value:
                        self._new_unselected_paths.add(child_text)
            finally:
                self.fs_tree.blockSignals(tree_blocked)
            next_offset = offset + len(batch)
            if next_offset < len(records):
                QTimer.singleShot(0, lambda n=next_offset: render_from(n))
            else:
                finish()

        if records:
            render_from(0)
        else:
            finish()

    def _queue_missing_child_scans(self, records) -> None:
        """Schedule one recursive scan per uncached direct child directory.

        Live browsing remains cheap and one-level. A missing directory cache is
        populated in the background; that recursive scan also caches every file
        and directory below it, so later expansions normally become live-list +
        bulk-cache-lookup only. Stale cache rows are intentionally not scanned.
        """
        resolver = self._resolver()
        for record in records or ():
            path = str(record.get("path", ""))
            if not path or bool(record.get("cache_present", False)):
                continue
            if record.get("type") not in {"dir", "blocked-dir"}:
                continue
            if bool(record.get("blocked", False)) or bool(record.get("symlink", False)):
                continue
            if resolver.is_hard_excluded(path):
                continue
            if path in self._fs_size_inflight or path in self._fs_auto_scan_queued:
                continue
            self._fs_auto_scan_queue.append(path)
            self._fs_auto_scan_queued.add(path)
        self._start_next_fs_auto_scan()

    def _start_next_fs_auto_scan(self) -> None:
        if self._closing or self._fs_auto_scan_active is not None:
            return
        while self._fs_auto_scan_queue:
            path = self._fs_auto_scan_queue.pop(0)
            self._fs_auto_scan_queued.discard(path)
            item = self._find_fs_item(path)
            if item is None or float(item.data(0, ROLE_SCANNED_AT) or 0.0) > 0:
                continue
            self._fs_auto_scan_active = path
            self._start_fs_size_scan(
                path, force=False, require_expanded=False,
                task_title=f"Scan size {path}", auto_scan=True,
            )
            if path not in self._fs_size_inflight:
                self._fs_auto_scan_active = None
                continue
            return

    def _fs_children_failed(self, path: str, trace):
        self._fs_children_inflight.discard(path)
        self._fs_scan_after_browse.discard(path)
        self._fs_force_scan_after_browse.discard(path)
        item = self._find_fs_item(path)
        if item is None:
            self._worker_error(trace)
            return
        item.setData(0, ROLE_LOADED, False)
        if item.data(0, ROLE_IS_DIR) and item.childCount() == 0:
            item.addChild(FilesystemTreeItem(["…", "", "", "", "", ""]))
        self._worker_error(trace)

    def _expand_fs(self, item):
        raw = item.data(0, ROLE_PATH)
        if not raw: return
        path = Path(raw)
        if self._startup_flow.blocks_root_expansion and str(path) == "/": return
        if self._resolver().is_hard_excluded(str(path)): return
        path_text = str(path)
        if path_text in self._fs_children_inflight:
            return
        # Every expansion observes current direct membership. No cached dirtree
        # is consulted; the expensive recursive size cache is independent.
        self._load_children(item, force=bool(item.data(0, ROLE_LOADED)))


    def _fs_item_needs_scan(self, item) -> bool:
        """Return whether an expanded directory needs a recursive size refresh.

        Any cached aggregate remains usable until explicit Recalculate, even if
        filesystem identity or policy changed. Ordinary expansion scans only
        when no aggregate has ever been cached for the row.
        """
        if item is None or not item.data(0, ROLE_IS_DIR):
            return False
        path = str(item.data(0, ROLE_PATH) or "")
        if path and self._resolver().resolve(path, is_dir=True).exclusion_origin is not ExclusionOrigin.NONE:
            # Effective Size of an excluded subtree is exactly zero. A first
            # scan may still be needed to populate Total size.
            self._set_fs_size(item, 0)
            return not float(item.data(0, ROLE_SCANNED_AT) or 0.0)
        scanned_at = float(item.data(0, ROLE_SCANNED_AT) or 0.0)
        return not scanned_at

    def _scan_expanded_item(self, path: str):
        self._start_fs_size_scan(path, force=False, require_expanded=True, task_title=f"Scan size {path}")

    def _start_fs_size_scan(
        self, path: str, *, force: bool, require_expanded: bool, task_title: str,
        auto_scan: bool = False,
    ) -> None:
        if path in self._fs_size_inflight:
            return
        item = self._find_fs_item(path)
        # Expansion-triggered scans are opportunistic. A row-scoped Recalculate
        # is explicit and may run even when the directory is collapsed or has a
        # fresh cache entry.
        if item is None:
            return
        if require_expanded and not item.isExpanded():
            return
        if not force and not self._fs_item_needs_scan(item):
            return
        _set_text(item, 4, "Scanning")
        self._fs_size_inflight.add(path)

        def task(progress_cb=None):
            return self.client.filesystem_size(
                path, progress_cb=progress_cb, exclude_patterns=self._filesystem_scan_patterns(), force=force
            )

        worker = Worker(task)
        worker.signals.progress.connect(lambda value, p=path: self._expanded_size_progress(p, value))
        worker.signals.result.connect(lambda value, p=path, a=auto_scan: self._expanded_size_done(p, value, auto_scan=a))
        worker.signals.error.connect(lambda trace, p=path, a=auto_scan: self._expanded_size_failed(p, trace, auto_scan=a))
        self._start_worker(worker, task_title)

    def _expanded_size_progress(self, path: str, value) -> None:
        root_item = self._find_fs_item(path)
        if root_item is not None:
            _set_text(root_item, 4, "Scanning")
        if isinstance(value, dict):
            current_path = str(value.get("current_item", ""))
            calculated_path = str(value.get("calculated_path", ""))
            if calculated_path:
                calculated_item = self._find_fs_item(calculated_path)
                if calculated_item is not None:
                    calculated_size = value.get("calculated_size")
                    if isinstance(calculated_size, int) and calculated_size >= 0:
                        self._set_fs_size(calculated_item, calculated_size)
                    calculated_total_size = value.get("calculated_total_size")
                    if isinstance(calculated_total_size, int) and calculated_total_size >= 0:
                        self._set_fs_total_size(
                            calculated_item, calculated_total_size,
                            "Total filesystem bytes under this row, independent of backup selection policy.",
                        )
                    calculated_item.setData(0, ROLE_SCANNED_AT, float(time.time()))
                    calculated_item.setData(0, ROLE_CACHE_STALE, False)
                    calculated_item.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key())
                    self._fs_calculated_this_session.add(calculated_path)
                    _set_scan_status(calculated_item, calculated_item.data(0, ROLE_SCANNED_AT), cached=False)
                    self._sort_fs_children(calculated_item.parent())
            current_item = self._find_fs_item(current_path) if current_path else None
            if current_item is not None and current_path != path and not calculated_path:
                _set_text(current_item, 4, "Scanning")
            self.live.setText(
                f"Scanning {current_path or '…'} — {human_size(value.get('bytes_done', 0))}, {value.get('items_processed', 0)} files"
            )
        else:
            self.live.setText(f"Scanning {value}")

    def _expanded_size_done(self, path: str, value, *, auto_scan: bool = False):
        self._fs_size_inflight.discard(path)
        item = self._find_fs_item(path)
        if item is None:
            return
        if isinstance(value, dict):
            size, count = value.get("size", 0), value.get("file_count", 0)
            total_size = value.get("total_size")
        else:
            size, count = value or 0, 0
            total_size = None
        self._set_fs_size(item, size)
        if total_size is not None:
            self._set_fs_total_size(
                item, total_size,
                "Total filesystem bytes under this row, independent of backup selection policy.",
            )
        source = str(value.get("source", "filesystem")) if isinstance(value, dict) else "filesystem"
        reported_scan = float(value.get("scanned_at", 0.0) or 0.0) if isinstance(value, dict) else 0.0
        scanned_at = reported_scan if source.startswith("cache") and reported_scan else float(time.time())
        item.setData(0, ROLE_SCANNED_AT, scanned_at)
        stale = source == "cache-stale-profile"
        item.setData(0, ROLE_CACHE_STALE, stale)
        item.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key())
        if source == "filesystem":
            self._fs_calculated_this_session.add(path)
        else:
            self._fs_calculated_this_session.discard(path)
        _set_scan_status(item, scanned_at, cached=source != "filesystem", stale=stale)
        self._sort_fs_children(item.parent())
        self.live.setText(f"{path} — {human_size(size)}, {count} files")
        # The recursive size scan populated cache entries for immediate child
        # directories too. Refresh the already visible children so their
        # cached size/scan state becomes visible without collapse/re-expand.
        self._refresh_children_cache(path)
        parent = item.parent()
        if parent is not None:
            self._recompute_loaded_size_and_ancestors(parent)
        if auto_scan and self._fs_auto_scan_active == path:
            self._fs_auto_scan_active = None
            QTimer.singleShot(0, self._start_next_fs_auto_scan)

    def _expanded_size_failed(self, path: str, trace: str, *, auto_scan: bool = False) -> None:
        self._fs_size_inflight.discard(path)
        item = self._find_fs_item(path)
        if item is not None:
            _set_text(item, 4, "—")
        self._worker_error(trace)
        if auto_scan and self._fs_auto_scan_active == path:
            self._fs_auto_scan_active = None
            QTimer.singleShot(0, self._start_next_fs_auto_scan)

    def _refresh_children_cache(self, path: str) -> None:
        """Refresh aggregate metadata for already materialized direct children.

        This is a bounded cache lookup, not navigation: it never reads a dirtree
        and never calls ``scandir``.
        """
        item = self._find_fs_item(path)
        if item is None or not item.data(0, ROLE_LOADED):
            return
        resolver = self._resolver()
        requested = [
            str(item.child(index).data(0, ROLE_PATH))
            for index in range(item.childCount())
            if item.child(index).data(0, ROLE_PATH)
            and not bool(item.child(index).data(0, ROLE_IS_SYMLINK))
            and not resolver.is_hard_excluded(str(item.child(index).data(0, ROLE_PATH)))
        ]
        requested = list(dict.fromkeys(requested))
        if not requested:
            return
        patterns = self._filesystem_scan_patterns()

        def task(progress_cb=None):
            records: list[dict] = []
            for offset in range(0, len(requested), 500):
                page = self.client.filesystem_cache(
                    requested[offset:offset + 500], exclude_patterns=patterns
                )
                values, _next_offset = _records_page(page)
                records.extend(values)
            return records

        worker = Worker(task)
        worker.signals.result.connect(lambda records, p=path: self._fs_cached_children_loaded(p, records))
        worker.signals.error.connect(lambda trace, p=path: self._fs_cached_children_failed(p, trace))
        self._start_worker(worker, f"Refresh cached sizes {path}", visible=False)

    def _fs_cached_children_loaded(self, path: str, records) -> None:
        item = self._find_fs_item(path)
        if item is None:
            return
        records = list(records or [])
        existing = {
            item.child(index).data(0, ROLE_PATH): item.child(index)
            for index in range(item.childCount())
            if item.child(index).data(0, ROLE_PATH)
        }
        scan_key = self._current_fs_scan_key()
        chunk_size = FS_RENDER_CHUNK_SIZE

        def finish() -> None:
            current_item = self._find_fs_item(path)
            if current_item is not item:
                return
            self._recompute_loaded_size_and_ancestors(item)
            self._sort_fs_children(item)

        def apply_from(offset: int) -> None:
            if self._closing:
                return
            current_item = self._find_fs_item(path)
            if current_item is not item:
                return
            previous = self.fs_tree.blockSignals(True)
            try:
                for record in records[offset:offset + chunk_size]:
                    child = existing.get(str(record.get("path", "")))
                    if child is None:
                        continue
                    size = record.get("size")
                    if size is not None:
                        self._set_fs_size(child, size)
                    if record.get("total_size") is not None:
                        self._set_fs_total_size(
                            child, int(record.get("total_size", 0) or 0),
                            "Total filesystem bytes under this row, independent of backup selection policy.",
                        )
                    scanned_at = float(record.get("scanned_at", 0.0) or 0.0)
                    cache_stale = bool(record.get("cache_stale", False))
                    child.setData(0, ROLE_SCANNED_AT, scanned_at)
                    child.setData(0, ROLE_CACHE_STALE, cache_stale)
                    child.setData(0, ROLE_SCAN_KEY, scan_key if scanned_at else "")
                    if scanned_at:
                        _set_scan_status(child, scanned_at, cached=True, stale=cache_stale)
            finally:
                self.fs_tree.blockSignals(previous)
            next_offset = offset + chunk_size
            if next_offset < len(records):
                QTimer.singleShot(0, lambda n=next_offset: apply_from(n))
            else:
                finish()

        if records:
            apply_from(0)
        else:
            finish()

    def _fs_cached_children_failed(self, path: str, trace: str) -> None:
        # Cache refresh is opportunistic.  Keep the successful parent scan and
        # log the refresh failure rather than showing a second modal error.
        self.log(trace)

    def _visible_fs_items(self) -> list[QTreeWidgetItem]:
        if not hasattr(self, "fs_tree"):
            return []
        result: list[QTreeWidgetItem] = []
        stack = [self.fs_tree.topLevelItem(i) for i in range(self.fs_tree.topLevelItemCount())]
        while stack:
            item = stack.pop()
            if item is None:
                continue
            if item.data(0, ROLE_PATH):
                result.append(item)
            stack.extend(item.child(i) for i in range(item.childCount()))
        return result

    def _canonical_selected_sources(self) -> list[str]:
        """Return non-overlapping explicit roots that contribute backup bytes."""
        sources = sorted(
            (str(Path(path)) for path in self.selected_sources()),
            key=lambda value: (len(Path(value).parts), value),
        )
        result: list[str] = []
        for source in sources:
            if any(source == root or source.startswith(root.rstrip("/") + "/") for root in result):
                continue
            result.append(source)
        return result

    def _refresh_visible_fs_cache(self) -> None:
        """Hydrate visible effective/total sizes from the privileged cache.

        The query never starts a scan. Effective ``Size`` is profile-bound;
        ``Total size`` is profile-independent and may therefore remain usable
        across a selection/exclusion policy change. Requests stay bounded so a
        large visible tree cannot recreate the historical large-message issue.
        """
        if self._closing or self._startup_state != "success" or not hasattr(self, "fs_tree"):
            return
        if self._fs_cache_refresh_inflight:
            self._fs_cache_refresh_pending = True
            return
        resolver = self._resolver()
        requested = [
            str(item.data(0, ROLE_PATH))
            for item in self._visible_fs_items()
            if item.data(0, ROLE_PATH)
            and not bool(item.data(0, ROLE_IS_SYMLINK))
            and not resolver.is_hard_excluded(str(item.data(0, ROLE_PATH)))
        ]
        requested = list(dict.fromkeys(requested))
        if not requested:
            self._apply_total_sizes({})
            return
        patterns = self._filesystem_scan_patterns()
        self._fs_cache_refresh_inflight = True
        self._fs_cache_refresh_pending = False

        def task(progress_cb=None):
            records: list[dict] = []
            for offset in range(0, len(requested), 500):
                page = self.client.filesystem_cache(requested[offset:offset + 500], exclude_patterns=patterns)
                values, _next_offset = _records_page(page)
                records.extend(values)
            return records

        worker = Worker(task)
        worker.signals.result.connect(self._fs_cache_loaded)
        worker.signals.error.connect(self._fs_cache_failed)
        self._start_worker(worker, "Load filesystem cache", visible=False)

    def _fs_cache_loaded(self, records) -> None:
        self._fs_cache_refresh_inflight = False
        by_path = {str(record.get("path", "")): record for record in records if record.get("path")}
        self._fs_cached_records = by_path
        resolver = self._resolver()
        for item in self._visible_fs_items():
            path = str(item.data(0, ROLE_PATH) or "")
            record = by_path.get(path)
            if record is None:
                continue
            if "size" in record:
                decision = resolver.resolve(path, is_dir=bool(item.data(0, ROLE_IS_DIR)))
                self._set_fs_size(
                    item, 0 if decision.exclusion_origin is not ExclusionOrigin.NONE
                    else int(record.get("size", 0) or 0),
                )
            scanned_at = float(record.get("scanned_at", 0.0) or 0.0)
            stale = bool(record.get("cache_stale", False))
            if scanned_at:
                item.setData(0, ROLE_SCANNED_AT, scanned_at)
                item.setData(0, ROLE_CACHE_STALE, stale)
                item.setData(0, ROLE_SCAN_KEY, self._current_fs_scan_key())
                cached_label = path not in self._fs_calculated_this_session or stale
                _set_scan_status(item, scanned_at, cached=cached_label, stale=stale)
        self._apply_total_sizes(by_path)
        self._recompute_all_loaded_directory_sizes()
        if self._fs_cache_refresh_pending:
            self._fs_cache_refresh_pending = False
            QTimer.singleShot(0, self._refresh_visible_fs_cache)

    def _fs_cache_failed(self, trace: str) -> None:
        self._fs_cache_refresh_inflight = False
        self.log(trace)
        if self._fs_cache_refresh_pending:
            self._fs_cache_refresh_pending = False
            QTimer.singleShot(0, self._refresh_visible_fs_cache)

    def _apply_total_sizes(self, cache_records: dict[str, dict]) -> None:
        resolver = self._resolver()
        for item in self._visible_fs_items():
            path = str(item.data(0, ROLE_PATH) or "")
            if not path:
                continue
            if resolver.is_hard_excluded(path):
                self._set_fs_total_size(
                    item, None,
                    "Total size is not scanned for hard/system-excluded or protected paths.",
                )
                continue
            record = cache_records.get(path)
            if record is None or "total_size" not in record:
                self._set_fs_total_size(
                    item, None,
                    "Total size has not been calculated yet. Expand or Recalculate this row to populate it.",
                )
                continue
            stale = bool(record.get("total_cache_stale", False))
            tooltip = "Total filesystem bytes under this row, independent of backup selection policy."
            if stale:
                tooltip += " The cached total may be stale; use Recalculate for an authoritative refresh."
            self._set_fs_total_size(item, int(record.get("total_size", 0) or 0), tooltip)

    def _apply_selected_sizes(self, cache_records: dict[str, dict], selected_roots: list[str] | None = None) -> None:
        """Compatibility wrapper for the column renamed from Selected size."""
        self._apply_total_sizes(cache_records)

    def _preconfigured_rules(self) -> list[ExcludeRule]:
        return enabled_rules(lambda p, d: self.cache.get_selected("exclude", p, d))

    def _filesystem_scan_patterns(self) -> list[str]:
        """Ordered effective exclusions used for ncdu-like backup-size accounting."""
        patterns = [rule.pattern for rule in self._effective_rules()]
        for path, policy in self.cache.path_policy_rows():
            if policy is SelectionPolicy.EXCLUDE:
                normalized = str(Path(path))
                patterns.append("/**" if normalized == "/" else normalized.rstrip("/") + "/**")
        return patterns

    def _selection_context(
        self, paths: list[str] | tuple[str, ...] | set[str] | None = None,
        *, known_paths_override: set[str] | None = None,
    ) -> tuple[SelectionResolver, list[tuple[str, SelectionPolicy]]]:
        """Snapshot selection inputs once for a synchronous GUI update.

        Filesystem rendering used to call SQLite-backed policy/known-path
        lookups repeatedly for every visible row and every ancestor.  Large
        browse results therefore turned a nominally background operation into
        seconds of work on the Qt thread. Policy is always snapshotted; when
        the affected row paths are known, snapshot membership is fetched only
        for that bounded set and resolution is then pure/in-memory.
        """
        policy_rows = self.cache.path_policy_rows()
        policy_map = dict(policy_rows)
        previous_sources = (self.last_manifest or {}).get("selected_sources", [])
        previous_snapshot = str((self.last_manifest or {}).get("snapshot_id", ""))
        known = (
            set(known_paths_override)
            if previous_snapshot and paths is not None and known_paths_override is not None else
            self.cache.known_paths_for(paths or (), previous_snapshot)
            if previous_snapshot and paths is not None else None
        )
        resolver = SelectionResolver(
            backup_root=str(self.paths.root),
            policy_lookup=lambda path: policy_map.get(str(Path(path)), SelectionPolicy.DEFAULT),
            enabled_rules=self._preconfigured_rules(),
            is_known=(
                (lambda path: str(Path(path)) in known)
                if known is not None else
                (lambda path: self.cache.is_known_path(path, previous_snapshot) if previous_snapshot else False)
            ),
            has_previous_snapshot=bool(previous_snapshot),
            previous_sources=previous_sources,
        )
        return resolver, policy_rows

    def _resolver(self) -> SelectionResolver:
        # Single-path decisions should stay lazy.  Bulk-loading the complete
        # known-path inventory just to expand one row can block the Qt thread
        # for large snapshots.
        previous_sources = (self.last_manifest or {}).get("selected_sources", [])
        previous_snapshot = str((self.last_manifest or {}).get("snapshot_id", ""))
        return SelectionResolver(
            backup_root=str(self.paths.root),
            policy_lookup=self.cache.get_path_policy,
            enabled_rules=self._preconfigured_rules(),
            is_known=lambda path: self.cache.is_known_path(path, previous_snapshot) if previous_snapshot else False,
            has_previous_snapshot=bool(previous_snapshot),
            previous_sources=previous_sources,
        )

    def _mark_policy_branch_size_stale(self, item) -> None:
        """Invalidate effective sizes only inside a policy branch, never globally."""
        current_key = self._current_fs_scan_key()
        stack = [item]
        while stack:
            current = stack.pop()
            if not current.data(0, ROLE_PATH):
                continue
            scanned_at = float(current.data(0, ROLE_SCANNED_AT) or 0.0)
            if scanned_at:
                current.setData(0, ROLE_CACHE_STALE, True)
                _set_scan_status(current, scanned_at, cached=True, stale=True)
            current.setData(0, ROLE_SCAN_KEY, current_key)
            stack.extend(
                current.child(index) for index in range(current.childCount())
                if current.child(index).data(0, ROLE_PATH)
            )

    def _refresh_policy_branch(self, item) -> None:
        """Repaint only the affected subtree plus ancestors after policy edits.

        Policy persistence is synchronous, but repainting a large expanded
        subtree is deliberately sliced across event-loop turns.  Previously a
        manual exclusion could spend seconds resolving thousands of rows in
        the checkbox/menu callback and GNOME would offer Force Quit.
        """
        path = str(item.data(0, ROLE_PATH) or "")
        if path and self.cache.get_path_policy(path) is SelectionPolicy.EXCLUDE:
            # Manual exclusion is stronger than all descendant selection/history
            # state.  Traverse the visible subtree incrementally instead of first
            # materializing every QTreeWidgetItem in one synchronous Python list.
            resolver, policy_rows = self._selection_context((), known_paths_override=set())
            generation = int(getattr(self, "_fs_policy_refresh_generation", 0)) + 1
            self._fs_policy_refresh_generation = generation
            self._refresh_one_fs_item(item, resolver=resolver, policy_rows=policy_rows)
            stack: list[tuple[QTreeWidgetItem, int]] = [(item, 0)]

            def finish_excluded() -> None:
                if generation != getattr(self, "_fs_policy_refresh_generation", generation):
                    return
                self._sort_fs_children(item)
                parent = item.parent()
                if parent is None:
                    return
                ancestor_paths: list[str] = []
                current = parent
                while current is not None:
                    current_path = current.data(0, ROLE_PATH)
                    if current_path:
                        ancestor_paths.append(str(current_path))
                    current = current.parent()
                ancestor_resolver, ancestor_rows = self._selection_context(ancestor_paths)
                self._refresh_item_and_ancestors_chunked(
                    parent, resolver=ancestor_resolver, policy_rows=ancestor_rows
                )

            def repaint_excluded_chunk() -> None:
                if (
                    generation != getattr(self, "_fs_policy_refresh_generation", generation)
                    or self._closing
                ):
                    return
                operations = 0
                previous = self.fs_tree.blockSignals(True)
                try:
                    while stack and operations < FS_RENDER_CHUNK_SIZE:
                        parent_node, child_index = stack[-1]
                        if child_index >= parent_node.childCount():
                            stack.pop()
                            continue
                        child = parent_node.child(child_index)
                        stack[-1] = (parent_node, child_index + 1)
                        operations += 1
                        if not child.data(0, ROLE_PATH):
                            continue
                        self._refresh_one_fs_item(
                            child, resolver=resolver, policy_rows=policy_rows
                        )
                        if child.childCount():
                            stack.append((child, 0))
                finally:
                    self.fs_tree.blockSignals(previous)
                if stack:
                    QTimer.singleShot(0, repaint_excluded_chunk)
                else:
                    finish_excluded()

            if stack and item.childCount():
                QTimer.singleShot(0, repaint_excluded_chunk)
            else:
                finish_excluded()
            return

        nodes = []
        stack = [item]
        while stack:
            current = stack.pop()
            if not current.data(0, ROLE_PATH):
                continue
            nodes.append(current)
            stack.extend(
                current.child(index) for index in range(current.childCount())
                if current.child(index).data(0, ROLE_PATH)
            )

        ancestor_paths: list[str] = []
        ancestor = item.parent()
        while ancestor is not None:
            ancestor_path = ancestor.data(0, ROLE_PATH)
            if ancestor_path:
                ancestor_paths.append(str(ancestor_path))
            ancestor = ancestor.parent()
        context_paths = [
            str(node.data(0, ROLE_PATH)) for node in nodes if node.data(0, ROLE_PATH)
        ]
        context_paths.extend(ancestor_paths)
        resolver, policy_rows = self._selection_context(context_paths)

        generation = int(getattr(self, "_fs_policy_refresh_generation", 0)) + 1
        self._fs_policy_refresh_generation = generation
        ordered = list(reversed(nodes))
        chunk_size = FS_RENDER_CHUNK_SIZE

        def finish() -> None:
            if generation != getattr(self, "_fs_policy_refresh_generation", generation):
                return
            self._sort_fs_children(item)
            parent = item.parent()
            if parent is not None:
                self._refresh_item_and_ancestors_chunked(
                    parent, resolver=resolver, policy_rows=policy_rows
                )
            else:
                self._refresh_one_fs_item(item, resolver=resolver, policy_rows=policy_rows)

        def repaint_from(offset: int) -> None:
            if generation != getattr(self, "_fs_policy_refresh_generation", generation) or self._closing:
                return
            previous = self.fs_tree.blockSignals(True)
            try:
                for current in ordered[offset:offset + chunk_size]:
                    self._refresh_one_fs_item(
                        current, resolver=resolver, policy_rows=policy_rows
                    )
            finally:
                self.fs_tree.blockSignals(previous)
            next_offset = offset + chunk_size
            if next_offset < len(ordered):
                QTimer.singleShot(0, lambda n=next_offset: repaint_from(n))
            else:
                finish()

        if len(ordered) <= chunk_size:
            repaint_from(0)
        else:
            # Give immediate feedback for the row the user acted on, then
            # yield before repainting the rest of the expanded subtree.
            self._refresh_one_fs_item(item, resolver=resolver, policy_rows=policy_rows)
            QTimer.singleShot(0, lambda: repaint_from(0))

    def _set_current_fs_policy(self, policy: SelectionPolicy) -> None:
        item = self.fs_tree.currentItem()
        if item is None: return
        path = item.data(0, ROLE_PATH)
        if not path: return
        resolver = self._resolver()
        if resolver.is_hard_excluded(path):
            QMessageBox.information(self, "Protected path", "This path is a hard system exclusion and cannot be overridden.")
            return
        if policy is SelectionPolicy.INCLUDE_RECURSIVE and not item.data(0, ROLE_IS_DIR):
            policy = SelectionPolicy.INCLUDE
        self.cache.set_path_policy(path, policy)
        self._fs_policy_revision += 1
        if policy is SelectionPolicy.EXCLUDE:
            self._apply_manual_exclusion_size(item)
        else:
            self._mark_policy_branch_size_stale(item)
        self._refresh_policy_branch(item)
        self._schedule_review_refresh()
        self.update_cards()

    def _fs_changed(self, item, column):
        if column != 0 or not item.data(0, ROLE_PATH): return
        if getattr(self, "_fs_check_render_depth", 0) > 0:
            # Rendering may emit itemChanged for both ROLE_RENDERED_CHECK and
            # the Qt check-state role. Neither event represents user intent.
            return
        path = item.data(0, ROLE_PATH)
        resolver_before, policy_rows_before = self._selection_context([path])
        if resolver_before.is_hard_excluded(path): return
        # Checking means explicit inclusion. Unchecking an item that was
        # effectively selected (including selection inherited from a checked
        # parent), or a partially selected directory containing selected policy
        # islands, is a durable manual exclusion.
        is_dir = bool(item.data(0, ROLE_IS_DIR))
        decision_before = resolver_before.resolve(path, is_dir=is_dir)
        state = item.checkState(0)
        if state not in {Qt.CheckState.Checked, Qt.CheckState.Unchecked}:
            return
        rendered = item.data(0, ROLE_RENDERED_CHECK)
        if rendered is not None and int(rendered) == int(state.value):
            # Passive rendering event, not a user checkbox interaction.
            return
        # Consume the explicit user toggle before any repaint can emit another
        # itemChanged event.
        self._mark_fs_user_check_consumed(item, state)
        subtree_selected = (
            state is Qt.CheckState.Unchecked
            and is_dir
            and not decision_before.selected
            and self._has_persisted_selected_descendant(
                path, resolver=resolver_before, policy_rows=policy_rows_before
            )
        )
        policy = checkbox_selection_policy(
            checked=state is Qt.CheckState.Checked,
            is_dir=is_dir,
            was_selected=decision_before.selected,
            subtree_selected=subtree_selected,
            existing_policy=decision_before.explicit_policy,
        )
        self.cache.set_path_policy(path, policy)
        self._fs_policy_revision += 1
        if policy is SelectionPolicy.EXCLUDE:
            self._apply_manual_exclusion_size(item)
        else:
            self._mark_policy_branch_size_stale(item)
        self._refresh_policy_branch(item)
        self._schedule_review_refresh()
        self.update_cards()

    def _display_backup_state(self, path: str, state: BackupState) -> BackupState:
        # Discovery review is an aggregate, high-priority presentation state.
        # A path enters this set only when a concrete descendant resolved to
        # NEW_UNSELECTED; hard, manual and preconfigured exclusions therefore
        # never manufacture review warnings by themselves.
        if state in {
            BackupState.MANUALLY_EXCLUDED, BackupState.PRECONFIGURED_EXCLUDED,
            BackupState.SYSTEM_EXCLUDED, BackupState.EXCLUDED,
        }:
            return state
        if path in self._review_ancestors:
            return BackupState.REVIEW_REQUIRED
        return state

    def _review_watch_directories(self) -> list[str]:
        return review_watch_directories(
            self.cache.path_policy_rows(), backup_root=str(self.paths.root)
        )

    def _schedule_review_refresh(self) -> None:
        if self._closing or self._startup_state != "success" or self._review_scan_scheduled:
            return
        self._review_scan_scheduled = True
        QTimer.singleShot(0, self.refresh_review_index)

    def refresh_review_index(self) -> None:
        if self._closing or self._startup_state != "success":
            self._review_scan_scheduled = False
            return
        # This maintenance scan shares the single privileged session with
        # interactive browsing. Never let it get in front of a directory
        # browse/size request already requested by the user.
        if self._fs_children_inflight or self._fs_size_inflight:
            self._review_scan_scheduled = False
            QTimer.singleShot(750, self._schedule_review_refresh)
            return
        watched = self._review_watch_directories()
        resolver = self._resolver()
        def task(progress_cb=None):
            seen: set[str] = set()
            new_paths: set[str] = set()
            total = max(1, len(watched))
            completed = 0
            for directory in watched:
                seen.add(directory)
                offset = 0
                while True:
                    page = self.client.filesystem_children(directory, limit=500, offset=offset)
                    records, next_offset = _records_page(page)
                    for record in records:
                        path = str(record.get("path", record.get("name", "")))
                        if not path:
                            continue
                        seen.add(path)
                        is_dir = record.get("type") in {"dir", "blocked-dir"} or bool(record.get("is_dir", False))
                        if resolver.resolve(path, is_dir=is_dir).backup_state is BackupState.REVIEW_REQUIRED:
                            new_paths.add(path)
                    if next_offset is None:
                        break
                    offset = next_offset
                completed += 1
                if progress_cb is not None:
                    progress_cb({"current_item": directory, "items_processed": completed, "percent_done": completed / total})

            return seen, new_paths

        worker = Worker(task)
        worker.signals.result.connect(self._review_index_loaded)
        worker.signals.error.connect(self._review_index_failed)
        # Internal discovery bookkeeping is intentionally omitted from the task
        # monitor. It is maintenance work triggered by policy/cache changes, not
        # a user action, and may wait behind interactive privileged RPCs.
        self._start_worker(worker, "Detect new unselected content", visible=False)

    def _review_index_loaded(self, value) -> None:
        self._review_scan_scheduled = False
        seen, new_paths = value
        self._seen_paths.update(seen)
        self._new_unselected_paths = set(new_paths)
        self._review_ancestors = review_ancestor_paths(self._new_unselected_paths)
        self._refresh_visible_fs()

    def _review_index_failed(self, trace) -> None:
        self._review_scan_scheduled = False
        self._worker_error(trace)

    def _refresh_visible_fs(self) -> None:
        if not hasattr(self, "fs_tree"):
            return
        visible_items = self._visible_fs_items()
        resolver, policy_rows = self._selection_context([
            str(item.data(0, ROLE_PATH)) for item in visible_items if item.data(0, ROLE_PATH)
        ])
        self.fs_tree.blockSignals(True)
        try:
            for index in range(self.fs_tree.topLevelItemCount()):
                self._refresh_fs_subtree(
                    self.fs_tree.topLevelItem(index), resolver=resolver, policy_rows=policy_rows
                )
        finally:
            self.fs_tree.blockSignals(False)

    def _refresh_fs_subtree(
        self, item, *, resolver: SelectionResolver | None = None,
        policy_rows: list[tuple[str, SelectionPolicy]] | None = None,
    ) -> None:
        if resolver is None or policy_rows is None:
            resolver, policy_rows = self._selection_context()
        for index in range(item.childCount()):
            child = item.child(index)
            if child.data(0, ROLE_PATH):
                self._refresh_fs_subtree(child, resolver=resolver, policy_rows=policy_rows)
        self._refresh_one_fs_item(item, resolver=resolver, policy_rows=policy_rows)
        self._sort_fs_children(item)

    def _refresh_one_fs_item(
        self, item, *, resolver: SelectionResolver | None = None,
        policy_rows: list[tuple[str, SelectionPolicy]] | None = None,
        child_states_override: list[BackupState] | None = None,
        child_checks_override: list[Qt.CheckState] | None = None,
    ) -> None:
        path = str(item.data(0, ROLE_PATH) or "")
        if not path:
            return
        if resolver is None or policy_rows is None:
            resolver, policy_rows = self._selection_context()
        decision = resolver.resolve(path, is_dir=bool(item.data(0, ROLE_IS_DIR)))
        excluded = decision.exclusion_origin is not ExclusionOrigin.NONE
        if excluded:
            # Exclusion precedence makes descendant presentation irrelevant to
            # this row: Size is exact zero, status is the exclusion origin and
            # the checkbox is off.  Do not synchronously walk thousands of
            # visible children merely to rediscover those facts.
            self._set_fs_size(item, 0)
        state = self._display_backup_state(path, decision.backup_state)

        child_states: list[BackupState] = []
        child_checks: list[Qt.CheckState] = []
        if not excluded:
            if child_states_override is not None and child_checks_override is not None:
                child_states = child_states_override
                child_checks = child_checks_override
            else:
                for i in range(item.childCount()):
                    child = item.child(i)
                    if not child.data(0, ROLE_PATH):
                        continue
                    raw_state = child.data(0, ROLE_STATE)
                    if raw_state:
                        try:
                            child_states.append(BackupState(raw_state))
                        except ValueError:
                            pass
                    child_checks.append(child.checkState(0))
            state = aggregate_directory_backup_state(state, child_states)

        if item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
            if excluded:
                check = Qt.CheckState.Unchecked
            elif child_checks:
                if all(x == Qt.CheckState.Checked for x in child_checks) and decision.selected:
                    check = Qt.CheckState.Checked
                elif all(x == Qt.CheckState.Unchecked for x in child_checks) and not decision.selected:
                    check = Qt.CheckState.Unchecked
                else:
                    check = Qt.CheckState.PartiallyChecked
            else:
                if item.data(0, ROLE_IS_DIR) and self._has_persisted_descendant_selection_mismatch(
                    path, decision.selected, resolver=resolver, policy_rows=policy_rows
                ):
                    check = Qt.CheckState.PartiallyChecked
                else:
                    check = Qt.CheckState.Checked if decision.selected else Qt.CheckState.Unchecked
            self._set_fs_check_state(item, check)
        item.setData(0, ROLE_POLICY, decision.explicit_policy.value)
        item.setData(0, ROLE_STATE, state.value)
        _set_text(item, 3, STATUS_LABELS[state])
        self._style_status(item, state)

    def _refresh_item_and_ancestors(
        self, item, *, resolver: SelectionResolver | None = None,
        policy_rows: list[tuple[str, SelectionPolicy]] | None = None,
    ) -> None:
        if resolver is None or policy_rows is None:
            resolver, policy_rows = self._selection_context()
        self.fs_tree.blockSignals(True)
        try:
            current = item
            while current is not None:
                self._refresh_one_fs_item(current, resolver=resolver, policy_rows=policy_rows)
                self._sort_fs_children(current)
                parent = current.parent()
                if parent is not None:
                    self._sort_fs_children(parent)
                current = parent
        finally:
            self.fs_tree.blockSignals(False)

    def _refresh_item_and_ancestors_chunked(
        self, item, *, resolver: SelectionResolver | None = None,
        policy_rows: list[tuple[str, SelectionPolicy]] | None = None,
    ) -> None:
        """Refresh loaded parent presentation without one huge Qt loop.

        Large expansions and policy edits can leave a parent with thousands of
        visible children.  Reading every child state/check in one queued slot
        blocks the Qt event loop even though all filesystem I/O is already in a
        worker.  Aggregate at most ``FS_RENDER_CHUNK_SIZE`` children per turn.
        """
        if item is None:
            return
        if resolver is None or policy_rows is None:
            resolver, policy_rows = self._selection_context()
        policy_revision = int(getattr(self, "_fs_policy_revision", 0))
        current = item
        child_index = 0
        child_states: list[BackupState] = []
        child_checks: list[Qt.CheckState] = []

        def advance_parent() -> None:
            nonlocal current, child_index, child_states, child_checks
            parent = current.parent() if current is not None else None
            if current is not None:
                self._sort_fs_children(current)
            if parent is not None:
                self._sort_fs_children(parent)
            current = parent
            child_index = 0
            child_states = []
            child_checks = []

        def process_chunk() -> None:
            nonlocal current, child_index, child_states, child_checks
            if getattr(self, "_closing", False):
                return
            if policy_revision != int(getattr(self, "_fs_policy_revision", policy_revision)):
                return
            previous = self.fs_tree.blockSignals(True)
            try:
                while current is not None:
                    path = str(current.data(0, ROLE_PATH) or "")
                    if not path:
                        advance_parent()
                        continue
                    decision = resolver.resolve(path, is_dir=bool(current.data(0, ROLE_IS_DIR)))
                    # Excluded rows have deterministic presentation and small
                    # parents are cheap enough to keep synchronous.
                    if (
                        decision.exclusion_origin is not ExclusionOrigin.NONE
                        or current.childCount() <= FS_RENDER_CHUNK_SIZE
                    ):
                        self._refresh_one_fs_item(
                            current, resolver=resolver, policy_rows=policy_rows
                        )
                        advance_parent()
                        continue

                    processed = 0
                    while child_index < current.childCount() and processed < FS_RENDER_CHUNK_SIZE:
                        child = current.child(child_index)
                        if child.data(0, ROLE_PATH):
                            raw_state = child.data(0, ROLE_STATE)
                            if raw_state:
                                try:
                                    child_states.append(BackupState(raw_state))
                                except ValueError:
                                    pass
                            child_checks.append(child.checkState(0))
                        child_index += 1
                        processed += 1
                    if child_index < current.childCount():
                        QTimer.singleShot(0, process_chunk)
                        return
                    self._refresh_one_fs_item(
                        current, resolver=resolver, policy_rows=policy_rows,
                        child_states_override=child_states, child_checks_override=child_checks,
                    )
                    advance_parent()
            finally:
                self.fs_tree.blockSignals(previous)

        process_chunk()

    def _path_status(self, path: str) -> str:
        return STATUS_LABELS[self._resolver().resolve(path).backup_state]

    def _style_status(self, item, state: BackupState | None = None):
        if state is None:
            raw = item.data(0, ROLE_STATE)
            try: state = BackupState(raw) if raw else self._resolver().resolve(item.data(0, ROLE_PATH)).backup_state
            except (ValueError, TypeError): state = BackupState.NOT_SELECTED
        item.setForeground(3, QColor(STATUS_COLORS[state]))
        item.setToolTip(3, STATUS_LABELS[state])

    def selected_sources(self) -> list[str]:
        resolver = self._resolver()
        result: list[str] = []
        for path, policy in self.cache.path_policy_rows():
            if policy not in {SelectionPolicy.INCLUDE, SelectionPolicy.INCLUDE_RECURSIVE}:
                continue
            if not resolver.resolve(path).selected:
                continue
            result.append(path)
        return list(dict.fromkeys(result))

    def source_exclusions(self) -> list[str]:
        selected = self.selected_sources()
        out: list[str] = []
        policies = self.cache.path_policy_rows()
        for path, policy in policies:
            if policy is not SelectionPolicy.EXCLUDE:
                continue
            if any(path == root or path.startswith(root.rstrip("/") + "/") for root in selected):
                out.append(path)
        return out

    def refresh_inventories(self, force: bool):
        self.refresh_packages(force); self.refresh_configs(force); self.refresh_repository_size()

    def refresh_packages(self, force=False):
        def task(progress_cb=None):
            records, offset = [], 0
            while True:
                page = self.client.package_inventory(offset=offset, force=force and offset == 0, progress_cb=progress_cb)
                values, next_offset = _records_page(page); records.extend(values)
                if next_offset is None: return records
                offset = next_offset
        w=Worker(task); w.signals.result.connect(self._packages_loaded); w.signals.error.connect(self._worker_error); self._start_worker(w, "Scan software packages")

    def _packages_loaded(self, data):
        self.packages=[]
        for raw in data:
            if isinstance(raw, PackageRecord):
                p = raw
            else:
                p = PackageRecord(
                    name=raw.get("name", ""), version=raw.get("version", ""),
                    architecture=raw.get("architecture", raw.get("arch", "")),
                    installed=bool(raw.get("installed", True)), manual=bool(raw.get("manual", True)),
                    selected=bool(raw.get("selected", True)), origin=raw.get("origin", ""),
                    manager=raw.get("manager", PackageManager.APT.value), scope=raw.get("scope", "system"),
                    channel=raw.get("channel", ""), reference=raw.get("reference", ""),
                    origin_url=raw.get("origin_url", ""), classic=bool(raw.get("classic", False)),
                )
            p.selected = self.cache.get_selected("package", p.policy_key, p.selected)
            self.packages.append(p)
        self.packages.sort(key=lambda p: (p.manager.value, p.name.casefold(), p.scope))
        self.package_table.blockSignals(True); self.package_table.setRowCount(len(self.packages))
        config_counts = self._config_counts_by_package()
        for r,p in enumerate(self.packages):
            chk=QTableWidgetItem(); chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable|Qt.ItemFlag.ItemIsEnabled); chk.setCheckState(Qt.CheckState.Checked if p.selected else Qt.CheckState.Unchecked); chk.setData(ROLE_PATH,p.policy_key)
            self.package_table.setItem(r,0,chk); self.package_table.setItem(r,1,_table_item(p.name)); manager_item=_table_item(semantic_label(p.manager)); manager_item.setForeground(QColor(semantic_color(p.manager))); self.package_table.setItem(r,2,manager_item); self.package_table.setItem(r,3,_table_item(p.version)); self.package_table.setItem(r,4,_table_item(p.architecture))
            self.package_table.setItem(r,5,_table_item(p.scope or "system"))
            install_item=_table_item(semantic_label(p.install_state))
            install_item.setForeground(QColor(semantic_color(p.install_state))); self.package_table.setItem(r,6,install_item)
            policy_item=_table_item(semantic_label(p.policy))
            policy_item.setForeground(QColor(semantic_color(p.policy))); self.package_table.setItem(r,7,policy_item)
            custom_configs = config_counts.get(p.name,0) if p.manager is PackageManager.APT else 0
            self.package_table.setItem(r,8,_table_item(str(custom_configs)))
        self.package_table.blockSignals(False); self.update_cards()

    def _package_changed(self,item):
        if item.column()!=0: return
        key=item.data(ROLE_PATH); selected=item.checkState()==Qt.CheckState.Checked; self.cache.set_selected("package",key,selected)
        for p in self.packages:
            if p.policy_key==key: p.selected=selected; break
        status=self.package_table.item(item.row(),7)
        policy = PackagePolicy.INCLUDED if selected else PackagePolicy.EXCLUDED
        status.setText(semantic_label(policy)); status.setToolTip(status.text()); status.setForeground(QColor(semantic_color(policy))); self.update_cards()

    def refresh_configs(self, force=False):
        self.live.setText("Auditing /etc…")
        def task(progress_cb=None):
            records, offset = [], 0
            while True:
                page = self.client.config_inventory(offset=offset, force=force and offset == 0, progress_cb=progress_cb)
                values, next_offset = _records_page(page); records.extend(values)
                if progress_cb is not None and values:
                    progress_cb({"current_item": values[-1].get("path", "/etc"), "items_processed": len(records)})
                if next_offset is None: return records
                offset = next_offset
        w=Worker(task); w.signals.progress.connect(lambda x:self.live.setText(str(x.get("current_item", x)) if isinstance(x,dict) else str(x))); w.signals.result.connect(self._configs_loaded); w.signals.error.connect(self._worker_error); self._start_worker(w, "Audit /etc")

    def _configs_loaded(self,data):
        self.configs=[]
        for raw in data:
            c = raw if isinstance(raw, ConfigRecord) else ConfigRecord(
                path=raw.get("path", ""), kind=raw.get("kind", ConfigKind.UNMANAGED.value),
                package=raw.get("package", ""),
                selected=self.cache.get_selected("config", raw.get("path", ""), bool(raw.get("selected", True))),
                size=int(raw.get("size", 0) or 0), mtime_ns=int(raw.get("mtime_ns", 0) or 0))
            self.configs.append(c)
        self._populate_config_tree()
        self.live.setText(f"/etc inventory: {len(self.configs)} candidates")
        self._refresh_package_config_counts(); self.update_cards()

    def _config_counts_by_package(self):
        counts = {}
        for config in self.configs:
            if config.package:
                counts[config.package] = counts.get(config.package, 0) + 1
        return counts

    def _refresh_package_config_counts(self):
        if not hasattr(self, "package_table"):
            return
        counts = self._config_counts_by_package()
        for row in range(self.package_table.rowCount()):
            name_item = self.package_table.item(row, 1)
            package = self.packages[row] if row < len(self.packages) else None
            count = counts.get(name_item.text(), 0) if name_item and package and package.manager is PackageManager.APT else 0
            self.package_table.setItem(row, 8, _table_item(str(count)))

    def _populate_config_tree(self) -> None:
        self.config_tree.blockSignals(True); self.config_tree.clear()
        root = QTreeWidgetItem(["/etc", "", "", "", ""]); root.setData(0, ROLE_CONFIG_LEAF, False); root.setData(0, ROLE_PATH, "/etc")
        root.setToolTip(0, "/etc")
        root.setFlags(root.flags() | Qt.ItemFlag.ItemIsUserCheckable); self.config_tree.addTopLevelItem(root)
        nodes = {"/etc": root}
        for config in sorted(self.configs, key=lambda c: c.path):
            path = Path(config.path)
            parent = root; current = Path("/etc")
            try: relative = path.relative_to("/etc")
            except ValueError: continue
            for part in relative.parts[:-1]:
                current = current / part; key = str(current)
                child = nodes.get(key)
                if child is None:
                    child = QTreeWidgetItem([part, "", "", "", ""]); child.setData(0, ROLE_CONFIG_LEAF, False); child.setData(0, ROLE_PATH, key)
                    child.setToolTip(0, key)
                    child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable); parent.addChild(child); nodes[key] = child
                parent = child
            policy = config.policy
            leaf = QTreeWidgetItem([path.name, semantic_label(config.kind), config.package, human_size(config.size), semantic_label(policy)])
            leaf.setData(0, ROLE_PATH, config.path); leaf.setData(0, ROLE_CONFIG_LEAF, True)
            leaf.setFlags(leaf.flags() | Qt.ItemFlag.ItemIsUserCheckable); leaf.setCheckState(0, Qt.CheckState.Checked if config.selected else Qt.CheckState.Unchecked)
            leaf.setForeground(1, QColor(semantic_color(config.kind)))
            leaf.setForeground(4, QColor(semantic_color(policy)))
            for col in range(5): leaf.setToolTip(col, leaf.text(col))
            parent.addChild(leaf)
        self._refresh_config_aggregate(root); root.setExpanded(True)
        self.config_tree.blockSignals(False)

    def _refresh_config_aggregate(self, item) -> Qt.CheckState:
        if item.data(0, ROLE_CONFIG_LEAF): return item.checkState(0)
        states = [self._refresh_config_aggregate(item.child(i)) for i in range(item.childCount())]
        if not states: state = Qt.CheckState.Unchecked
        elif all(s is Qt.CheckState.Checked for s in states): state = Qt.CheckState.Checked
        elif all(s is Qt.CheckState.Unchecked for s in states): state = Qt.CheckState.Unchecked
        else: state = Qt.CheckState.PartiallyChecked
        item.setCheckState(0, state)
        return state

    def _config_changed(self,item,column):
        if column != 0: return
        state = item.checkState(0)
        if state is Qt.CheckState.PartiallyChecked: return
        selected = state is Qt.CheckState.Checked
        self.config_tree.blockSignals(True)
        try:
            def apply(node):
                if node.data(0, ROLE_CONFIG_LEAF):
                    path=node.data(0,ROLE_PATH); node.setCheckState(0,state)
                    policy = ConfigPolicy.INCLUDED if selected else ConfigPolicy.EXCLUDED
                    _set_text(node,4,semantic_label(policy)); node.setForeground(4,QColor(semantic_color(policy))); self.cache.set_selected("config",path,selected)
                    for c in self.configs:
                        if c.path==path: c.selected=selected; break
                else:
                    for i in range(node.childCount()): apply(node.child(i))
            apply(item)
            root=item
            while root.parent() is not None: root=root.parent()
            self._refresh_config_aggregate(root)
        finally: self.config_tree.blockSignals(False)
        self.update_cards()

    def _exclude_changed(self,item):
        if item.column()!=0:return
        pattern=item.data(ROLE_PATH)
        if not pattern:return
        self.cache.set_selected("exclude",pattern,item.checkState()==Qt.CheckState.Checked); self._populate_root(); self._refresh_visible_fs_cache(); self._schedule_review_refresh()

    def _effective_rules(self):
        resolver = self._resolver()
        policies = self.cache.path_policy_rows()
        recursive_overrides = [
            path for path, policy in policies
            if policy is SelectionPolicy.INCLUDE_RECURSIVE and not resolver.is_hard_excluded(path)
            and resolver.resolve(path).selected
        ]
        exact_overrides = [
            path for path, policy in policies
            if policy is SelectionPolicy.INCLUDE and not resolver.is_hard_excluded(path)
            and resolver.resolve(path).selected
        ]
        return apply_rule_overrides(self._preconfigured_rules(), recursive_overrides, exact_overrides)

    def _ensure_state(self, components: set[BackupComponent] | None = None):
        components = self._backup_components(components)
        if not components:
            raise ValueError("Select at least one snapshot component: filesystem, /etc configuration, or packages.")
        filesystem_enabled = BackupComponent.FILESYSTEM in components
        packages_enabled = BackupComponent.PACKAGES in components
        configs_enabled = BackupComponent.CONFIGS in components
        return {
            "sources": self.selected_sources() if filesystem_enabled else [],
            "source_exclusions": self.source_exclusions() if filesystem_enabled else [],
            # Exclusion profiles are a filesystem-domain concern. Curated /etc
            # snapshots use explicit config sources and therefore must not carry
            # generic filesystem exclusions such as /etc/**.
            "exclude_rules": [r.to_dict() for r in self._effective_rules()] if filesystem_enabled else [],
            # Package/config candidates are rediscovered by the privileged
            # helper immediately before building the snapshot. Their default
            # policy is Included, so only explicit exclusions need to cross the
            # RPC boundary. This keeps requests small even on systems with many
            # thousands of /etc candidates while preserving every user choice.
            "packages": [p.to_dict() for p in self.packages if not p.selected] if packages_enabled else [],
            "configs": [c.to_dict() for c in self.configs if not c.selected] if configs_enabled else [],
            "components": [component.value for component in sorted(components, key=lambda item: item.value)],
        }

    def _backup_components(self, scope: set[BackupComponent] | None = None) -> set[BackupComponent]:
        if scope is not None:
            return set(scope)
        checks = getattr(self, "backup_component_checks", {})
        return {component for component, check in checks.items() if check.isChecked()}

    def preview_backup(self): self._start_backup(True)
    def run_backup(self): self._start_backup(False)

    def _start_backup(self, dry_run: bool, components: set[BackupComponent] | None = None):
        requested = self._backup_components(components)
        if not requested:
            QMessageBox.critical(self, "Backup preparation", "Select at least one backup component.")
            return
        try:
            policies = {component: self._ensure_state({component}) for component in requested}
        except Exception as exc:
            QMessageBox.critical(self, "Backup preparation", str(exc)); return
        credentials = self._credential_for_request()
        if credentials is None: return
        self.active_dry_run = dry_run
        self.active_backup_components = set(requested)
        self.progress.setRange(0,100); self.progress.setValue(0); self.progress.setFormat("%p%")
        self.live.setText("Dry-run Restic repositories…" if dry_run else "Backup Restic repositories…")
        order = [component for component in (BackupComponent.FILESYSTEM, BackupComponent.CONFIGS, BackupComponent.PACKAGES) if component in requested]
        def task(progress_cb=None):
            method = self.client.dry_run if dry_run else self.client.backup
            results = {}
            last_fraction = 0.0
            for stage_index, component in enumerate(order):
                policy = policies[component]
                stage_scan_finished = False
                def domain_progress(message, domain=component, index=stage_index):
                    nonlocal last_fraction, stage_scan_finished
                    if progress_cb is None:
                        return
                    raw_value = dict(message) if isinstance(message, dict) else {"text": str(message)}
                    value, stage_scan_finished = gate_restic_backup_progress(raw_value, stage_scan_finished)
                    raw_percent = value.get("percent_done")
                    if isinstance(raw_percent, (int, float)) and not isinstance(raw_percent, bool):
                        last_fraction = staged_progress_fraction(index, len(order), raw_percent, last_fraction)
                        value["percent_done"] = last_fraction
                    value.setdefault("current_item", domain.value)
                    value["domain"] = domain.value
                    progress_cb(value)
                results[component.value] = method(
                    sources=policy["sources"], source_exclusions=policy["source_exclusions"],
                    exclude_rules=policy["exclude_rules"], packages=policy["packages"],
                    configs=policy["configs"], components=[component.value],
                    credentials=credentials, progress_cb=domain_progress,
                )
                if progress_cb is not None:
                    last_fraction = max(last_fraction, (stage_index + 1) / len(order))
                    progress_cb({
                        "message_type": "status",
                        "percent_done": last_fraction,
                        "current_files": [f"{component.value} complete"],
                        "current_item": f"{component.value} complete",
                        "domain": component.value,
                    })
            return results
        w=Worker(task); w.signals.progress.connect(self._restic_msg)
        w.signals.result.connect(lambda result:self._backup_done(result,dry_run))
        w.signals.error.connect(self._worker_error)
        self._start_worker(w, "Restic dry-run" if dry_run else "Restic backup")

    def _restic_msg(self,msg):
        typ=msg.get("message_type")
        if typ=="status":
            raw_percent = msg.get("percent_done")
            has_percent = isinstance(raw_percent, (int, float)) and not isinstance(raw_percent, bool)
            if has_percent:
                fraction = max(0.0, min(1.0, float(raw_percent)))
                self.progress.setRange(0, 1000)
                self.progress.setValue(int(round(fraction * 1000)))
                self.progress.setFormat(f"{fraction * 100.0:.1f}%")
                progress_text = f"{fraction * 100.0:.1f}%"
            else:
                self.progress.setRange(0, 0)
                self.progress.setFormat("Scanning…")
                progress_text = "Scanning backup set…"
            cur=(msg.get("current_files") or [""])[0]
            bytes_done = msg.get("bytes_done")
            total_bytes = msg.get("total_bytes")
            if isinstance(bytes_done, int) and isinstance(total_bytes, int) and total_bytes > 0:
                logical = f"{human_size(bytes_done)} / {human_size(total_bytes)} logical"
                self.live.setText(f"{progress_text} — {logical} — {cur}")
            else:
                self.live.setText(f"{progress_text} — {cur}")
        elif typ=="verbose_status":
            action = msg.get("action", ""); path = msg.get("item", "")
            if action == "scan_finished":
                self.live.setText("Filesystem scan complete; backing up…")
                return
            if path: self._seen_paths.add(path)
            self.live.setText(f"{action} — {path}")
            if action == "unchanged": self._update_visible_path_status(path, BackupState.BACKED_UP)
            elif action in ("new", "modified"): self._update_visible_path_status(path, BackupState.PENDING if self.active_dry_run else BackupState.BACKED_UP_NOW)
        elif typ=="excluded_item":
            path = msg.get("item", "")
            if path: self._seen_paths.add(path)
            self._update_visible_path_status(path, BackupState.PRECONFIGURED_EXCLUDED)
        elif typ in ("error","warning","text"): self.log(json.dumps(msg,ensure_ascii=False))

    def _update_visible_path_status(self, path: str, status: BackupState):
        if not path or not hasattr(self, "fs_tree"): return
        # Discovery/review is a higher-priority presentation concern than
        # Restic's transient per-file progress.  Do not let a live progress
        # event temporarily hide that a branch still contains new, unreviewed
        # content.
        status = self._display_backup_state(path, status)
        def walk(item):
            item_path = item.data(0, ROLE_PATH)
            if item_path == path:
                item.setData(0, ROLE_STATE, status.value)
                _set_text(item, 3, STATUS_LABELS[status])
                self._style_status(item, status)
                return item
            for i in range(item.childCount()):
                found = walk(item.child(i))
                if found is not None:
                    return found
            return None
        for i in range(self.fs_tree.topLevelItemCount()):
            found = walk(self.fs_tree.topLevelItem(i))
            if found is not None:
                self._sort_fs_children(found.parent())
                break

    def _backup_done(self, results, dry_run: bool):
        if not isinstance(results, dict):
            self._worker_error("Backup returned an invalid result")
            return
        summaries: dict[BackupComponent, DryRunSummary] = {}
        receipts: dict[BackupComponent, dict] = {}
        for component_name, raw in results.items():
            try:
                component = BackupComponent(component_name)
            except ValueError:
                continue
            receipt = raw.get("receipt", raw) if isinstance(raw, dict) else {}
            summary = receipt.get("summary", receipt) if isinstance(receipt, dict) else {}
            value = DryRunSummary(
                snapshot_id=receipt.get("snapshot_id", summary.get("snapshot_id", "")),
                total_bytes_processed=int(summary.get("total_bytes_processed", 0) or 0),
                data_added=int(summary.get("data_added", 0) or 0),
                data_added_packed=int(summary.get("data_added_packed", 0) or 0),
                files_new=int(summary.get("files_new", 0) or 0),
                files_changed=int(summary.get("files_changed", 0) or 0),
                files_unmodified=int(summary.get("files_unmodified", 0) or 0),
                partial=bool(receipt.get("partial", summary.get("partial", False))),
            )
            summaries[component] = value; receipts[component] = receipt
            if value.snapshot_id:
                self.cache.put_snapshot_stats(value.snapshot_id, {
                    "total_bytes_processed": value.total_bytes_processed, "data_added": value.data_added,
                    "data_added_packed": value.data_added_packed, "files_new": value.files_new,
                    "files_changed": value.files_changed, "files_unmodified": value.files_unmodified,
                }, component.value)
        self.progress.setRange(0,1000); self.progress.setValue(1000); self.progress.setFormat("100.0%")
        total_logical = sum(item.total_bytes_processed for item in summaries.values())
        total_delta = sum(item.estimated_repository_delta for item in summaries.values())
        self._last_estimated_delta = int(total_delta or 0) if dry_run else 0
        self.cache.put_kv("logical_selected_size", int(total_logical or 0))
        lines = []
        for component in (BackupComponent.FILESYSTEM, BackupComponent.CONFIGS, BackupComponent.PACKAGES):
            summary = summaries.get(component)
            if summary is None: continue
            lines.append(
                f"{component.value}: {human_size(summary.total_bytes_processed)} logical, "
                f"~{human_size(summary.estimated_repository_delta)} repository delta" +
                (" (partial)" if summary.partial else "")
            )
        if dry_run:
            text = "Dry-run complete.\n" + "\n".join(lines)
            QMessageBox.information(self, "Backup preview", text)
        else:
            text = "Independent snapshots created.\n" + "\n".join(lines)
            QMessageBox.information(self, "Backup complete", text)
            filesystem_summary = summaries.get(BackupComponent.FILESYSTEM)
            if filesystem_summary and filesystem_summary.snapshot_id:
                self.cache.mark_paths_known(self._seen_paths, filesystem_summary.snapshot_id)
                self.last_manifest = {
                    "selected_sources": self.selected_sources(),
                    "components": [BackupComponent.FILESYSTEM.value],
                    "snapshot_id": filesystem_summary.snapshot_id,
                }
                self.cache.put_kv("last_successful_manifest", self.last_manifest)
                self._seen_paths.clear()
            previous_repo = self.cache.get_kv("repository_size", None)
            if previous_repo is not None and total_delta:
                self.cache.put_kv("repository_size", int(previous_repo) + int(total_delta))
            self.refresh_snapshots(); self._populate_root(); self._schedule_review_refresh()
        self.live.setText(text); self.refresh_disk_usage(); self.update_cards()

    def refresh_snapshots(self, component: BackupComponent | None = None):
        # QPushButton.clicked(bool) passes its checked state to connected slots.
        # A refresh button is not a component selector, so never let that Qt
        # boolean leak into the domain loop and become ``domain.value``.
        if isinstance(component, bool):
            component = None
        credentials = self._credential_for_request()
        if credentials is None: return
        domains = [component] if component is not None else [
            BackupComponent.FILESYSTEM, BackupComponent.CONFIGS, BackupComponent.PACKAGES
        ]
        def task(progress_cb=None):
            result = {}
            for domain in domains:
                records, offset = [], 0
                while True:
                    page = self.client.snapshots(domain.value, credentials, offset=offset)
                    values, next_offset = _records_page(page); records.extend(values)
                    if next_offset is None:
                        break
                    offset = next_offset
                result[domain.value] = records
            return result
        w=Worker(task)
        w.signals.result.connect(self._snapshot_histories_loaded)
        w.signals.error.connect(self._worker_error)
        self._start_worker(w, "Load snapshot histories")

    def _snapshot_histories_loaded(self, histories):
        for value, snaps in histories.items():
            try:
                component = BackupComponent(value)
            except ValueError:
                continue
            self._snapshots_loaded(component, snaps)
        latest_times = []
        for history in getattr(self, "snap_lists", {}).values():
            if history.count():
                record = history.item(0).data(ROLE_PATH)
                if record is not None:
                    latest_times.append(record.time)
        self.card_snapshot.setText(max(latest_times)[:10] if latest_times else "none")
        self._update_snapshot_maintenance_actions()

    def _snapshots_loaded(self, component: BackupComponent, snaps):
        history = self.snap_lists[component]
        selected_id = ""
        current = history.currentItem()
        if current is not None and current.data(ROLE_PATH) is not None:
            selected_id = current.data(ROLE_PATH).id
        history.blockSignals(True); history.clear()
        selected_row = -1
        for row, raw in enumerate(snaps):
            partial = bool(raw.get("partial", False)) if isinstance(raw, dict) else False
            record = raw if isinstance(raw, SnapshotRecord) else SnapshotRecord(
                id=raw.get("id", ""), time=raw.get("time", ""), hostname=raw.get("hostname", ""),
                paths=raw.get("paths", []), tags=raw.get("tags", []), parent=raw.get("parent", ""),
                total_bytes_processed=int(raw.get("total_bytes_processed", 0) or 0),
                data_added=int(raw.get("data_added", 0) or 0),
                data_added_packed=int(raw.get("data_added_packed", 0) or 0),
            )
            cached = self.cache.get_snapshot_stats(record.id, component.value)
            if cached:
                record.total_bytes_processed = record.total_bytes_processed or int(cached.get("total_bytes_processed", 0))
                record.data_added = record.data_added or int(cached.get("data_added", 0))
                record.data_added_packed = record.data_added_packed or int(cached.get("data_added_packed", 0))
            text=f"{record.time[:19].replace('T',' ')}  {record.id[:8]}  {human_size(record.total_bytes_processed)}"
            if partial: text += "  ⚠ PARTIAL"
            item=QListWidgetItem(text); item.setToolTip(text); item.setData(ROLE_PATH,record); history.addItem(item)
            if record.id == selected_id:
                selected_row = row
        if selected_row >= 0:
            history.setCurrentRow(selected_row)
        history.blockSignals(False)
        if component == self.restore_domain and selected_row >= 0:
            self._snapshot_selected(component, history.currentItem(), None)

    def _active_snapshot_list(self) -> QListWidget:
        return self.snap_lists[self.restore_domain]

    def _update_snapshot_maintenance_actions(self):
        history = self._active_snapshot_list() if hasattr(self, "snap_lists") else None
        current = history.currentItem() if history is not None else None
        selected_latest = bool(current is not None and history.currentRow() == 0)
        delete_button = getattr(self, "btn_delete_latest_snapshot", None)
        if delete_button is not None:
            delete_button.setEnabled(selected_latest)
        consolidate_button = getattr(self, "btn_consolidate_history", None)
        if consolidate_button is not None:
            consolidate_button.setEnabled(selected_latest and history.count() > 1)

    def _snapshot_selected(self, component: BackupComponent, current, previous):
        if component != getattr(self, "restore_domain", component):
            return
        self.snap_list = self.snap_lists[component]
        self._update_snapshot_maintenance_actions()
        self._set_restore_actions(False)
        self.restore_tree.clear(); self.restore_packages.clear()
        self.restore_metadata_loaded = False
        self.restore_snapshot_id = ""
        self.restore_snapshot_component = component
        self.cache.put_kv("restore_snapshot", "")
        if not current:
            self.snap_info.setText("Select a snapshot")
            return
        snap=current.data(ROLE_PATH)
        snapshot_id = snap.id
        self.restore_snapshot_id = snapshot_id
        self.snap_info.setText(
            f"{component.value.title()} snapshot {snap.id[:12]}\n{snap.time}\n"
            f"Logical: {human_size(snap.total_bytes_processed)} — added: {human_size(snap.data_added_packed or snap.data_added)}"
        )
        credentials = self._credential_for_request()
        if credentials is None: return
        if not snap.total_bytes_processed:
            wstats=Worker(lambda progress_cb=None:self.client.snapshot_stats(component.value, snap.id, credentials))
            wstats.signals.result.connect(lambda stats,s=snap,sid=snapshot_id,c=component:self._snapshot_stats_loaded(c,s,sid,stats))
            wstats.signals.error.connect(lambda trace:self.log(trace))
            self._start_worker(wstats, f"Measure {component.value} snapshot size")
        if component != BackupComponent.PACKAGES:
            root = QTreeWidgetItem(["/", "", "directory"]); root.setData(0, ROLE_PATH, "/"); root.setData(0, ROLE_IS_DIR, True); root.setData(0, ROLE_LOADED, False)
            root.setFlags(root.flags() | Qt.ItemFlag.ItemIsUserCheckable); root.setCheckState(0, Qt.CheckState.Unchecked); root.addChild(QTreeWidgetItem(["…", "", ""]))
            self.restore_tree.addTopLevelItem(root); root.setExpanded(True)
            self._load_restore_children(root, snapshot_id)
        def task(progress_cb=None):
            manifest = self.client.snapshot_manifest(component.value, snap.id, credentials)
            packages = self.client.snapshot_packages(snap.id, credentials) if component == BackupComponent.PACKAGES else []
            return manifest, packages
        w=Worker(task)
        w.signals.result.connect(lambda value,sid=snapshot_id,c=component:self._manifest_loaded(c,sid,value[0],value[1]))
        w.signals.error.connect(self._worker_error)
        self._start_worker(w, f"Load {component.value} snapshot metadata")

    def _selected_latest_snapshot_id(self) -> str:
        history = self._active_snapshot_list() if hasattr(self, "snap_lists") else None
        if history is None or history.count() == 0:
            return ""
        current = history.currentItem()
        if current is None or history.currentRow() != 0:
            return ""
        record = current.data(ROLE_PATH)
        return getattr(record, "id", "") or ""

    def delete_latest_snapshot(self):
        snapshot_id = self._selected_latest_snapshot_id()
        if not snapshot_id:
            return
        domain = self.restore_domain
        answer = QMessageBox.warning(
            self, "Delete latest snapshot",
            f"This permanently forgets the latest {domain.value} snapshot and prunes data no longer referenced in that repository. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.btn_delete_latest_snapshot.setEnabled(False); self.btn_consolidate_history.setEnabled(False)
        def task(progress_cb=None):
            return self.client.delete_latest_snapshot(domain.value, snapshot_id, progress_cb=progress_cb)
        worker = Worker(task); worker.signals.progress.connect(self._restic_msg)
        worker.signals.result.connect(lambda result,c=domain: self._snapshot_maintenance_done(c, "Latest snapshot deleted", result))
        worker.signals.error.connect(self._snapshot_maintenance_error)
        self._start_worker(worker, f"Delete latest {domain.value} snapshot")

    def consolidate_snapshot_history(self):
        snapshot_id = self._selected_latest_snapshot_id()
        history = self._active_snapshot_list()
        if not snapshot_id or history.count() < 2:
            return
        domain = self.restore_domain
        answer = QMessageBox.warning(
            self, "Consolidate snapshot history",
            f"Keep the latest {domain.value} snapshot, forget all older snapshots in this independent repository, and prune unreferenced historical data? Historical versions will be permanently lost.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.btn_delete_latest_snapshot.setEnabled(False); self.btn_consolidate_history.setEnabled(False)
        def task(progress_cb=None):
            return self.client.consolidate_history(domain.value, snapshot_id, progress_cb=progress_cb)
        worker = Worker(task); worker.signals.progress.connect(self._restic_msg)
        worker.signals.result.connect(lambda result,c=domain:self._snapshot_maintenance_done(c, "Snapshot history consolidated", result))
        worker.signals.error.connect(self._snapshot_maintenance_error)
        self._start_worker(worker, f"Consolidate {domain.value} snapshot history")

    def _snapshot_maintenance_done(self, component: BackupComponent, message: str, result):
        deleted = result.get("deleted", []) if isinstance(result, dict) else []
        QMessageBox.information(self, "Snapshots", f"{message}.\nRemoved snapshots: {len(deleted)}")
        self.restore_snapshot_id = ""; self.restore_metadata_loaded = False
        self.restore_tree.clear(); self.restore_packages.clear()
        self.refresh_snapshots(component)

    def _snapshot_maintenance_error(self, trace):
        self._update_snapshot_maintenance_actions(); self._worker_error(trace)

    def _set_restore_actions(self, enabled):
        self.restore_state = RestoreState.READY if enabled else RestoreState.LOADING
        domain = getattr(self, "restore_domain", BackupComponent.FILESYSTEM)
        file_component = bool(enabled and domain in {BackupComponent.FILESYSTEM, BackupComponent.CONFIGS})
        package_component = bool(enabled and domain == BackupComponent.PACKAGES)
        for name in ("btn_restore_stage", "btn_restore_inplace"):
            button = getattr(self, name, None)
            if button is not None: button.setEnabled(file_component)
        for name in ("btn_apt_simulate", "btn_apt_install"):
            button = getattr(self, name, None)
            if button is not None: button.setEnabled(package_component)

    def _snapshot_is_current(self, snapshot_id, component: BackupComponent | None = None):
        component = component or getattr(self, "restore_domain", BackupComponent.FILESYSTEM)
        if component != getattr(self, "restore_domain", component):
            return False
        history = self.snap_lists.get(component) if hasattr(self, "snap_lists") else None
        current = history.currentItem() if history is not None else None
        return bool(snapshot_id) and snapshot_id == getattr(self, "restore_snapshot_id", "") and bool(current) and current.data(ROLE_PATH).id == snapshot_id

    def _snapshot_stats_loaded(self, component, snap, snapshot_id, stats):
        if not self._snapshot_is_current(snapshot_id, component):
            return
        total = int(stats.get("total_size", 0) or 0)
        if total:
            snap.total_bytes_processed = total
            cached = self.cache.get_snapshot_stats(snap.id, component.value) or {}; cached["total_bytes_processed"] = total; self.cache.put_snapshot_stats(snap.id, cached, component.value)
            current = self.snap_lists[component].currentItem()
            if current and current.data(ROLE_PATH).id == snap.id:
                self.snap_info.setText(
                    f"{component.value.title()} snapshot {snap.id[:12]}\n{snap.time}\n"
                    f"Logical: {human_size(total)} — added: {human_size(snap.data_added_packed or snap.data_added)}"
                )

    def _manifest_loaded(self, component: BackupComponent, snapshot_id, manifest, package_records):
        if not self._snapshot_is_current(snapshot_id, component):
            return
        if manifest.get("domain") not in {None, component.value}:
            self._worker_error(f"Snapshot metadata domain mismatch: expected {component.value}")
            return
        self.cache.put_kv("restore_snapshot", snapshot_id)
        if component == BackupComponent.PACKAGES:
            for rec in package_records:
                if not isinstance(rec, dict) or not rec.get("name"):
                    continue
                try:
                    package = PackageRecord(**rec)
                except (TypeError, ValueError):
                    continue
                original = bool(package.selected)
                detail = f"{package.name}  {package.version}  [{package.manager.value.upper()}]"
                if package.scope and package.scope != "system":
                    detail += f"  ({package.scope})"
                label = detail + ("  [included in plan]" if original else "  [excluded from plan]")
                selector = {"manager": package.manager.value, "scope": package.scope, "name": package.name}
                item=QListWidgetItem(label); item.setToolTip(label); item.setData(ROLE_PATH, selector)
                item.setFlags(item.flags()|Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Checked if original else Qt.CheckState.Unchecked)
                self.restore_packages.addItem(item)
        self.restore_metadata_loaded = True
        self._apply_restore_defaults()
        self._set_restore_actions(True)

    def _restore_component_enabled(self, component: BackupComponent) -> bool:
        return component == getattr(self, "restore_domain", BackupComponent.FILESYSTEM)

    @staticmethod
    def _paths_related(path: str, configured: str) -> bool:
        left = path.rstrip("/") or "/"
        right = configured.rstrip("/") or "/"
        if left == right:
            return True
        if right == "/":
            return left.startswith("/")
        if left == "/":
            return right.startswith("/")
        return left.startswith(right + "/") or right.startswith(left + "/")

    def _restore_path_component(self, path: str) -> BackupComponent | None:
        domain = getattr(self, "restore_domain", BackupComponent.FILESYSTEM)
        if domain == BackupComponent.PACKAGES:
            return None
        if not isinstance(path, str) or not path.startswith("/") or "/.ubackup/" in path:
            return None
        if domain == BackupComponent.CONFIGS and not (path == "/etc" or path.startswith("/etc/")):
            return None
        return domain

    def _restore_expand(self, item):
        if item.data(0, ROLE_IS_DIR):
            self._load_restore_children(item, getattr(self, "restore_snapshot_id", ""))

    def _load_restore_children(self, item, snapshot_id):
        if item.data(0, ROLE_LOADED):
            return
        sid = snapshot_id
        directory = item.data(0, ROLE_PATH)
        if not sid or not directory:
            return
        item.setData(0, ROLE_LOADED, True)
        credentials = self._credential_for_request()
        if credentials is None: return
        def task(progress_cb=None):
            records, offset = [], 0
            while True:
                page = self.client.snapshot_directory(self.restore_domain.value, sid, directory, credentials, offset=offset)
                values, next_offset = _records_page(page); records.extend(values)
                if next_offset is None: return records
                offset = next_offset
        w=Worker(task); w.signals.result.connect(lambda nodes, i=item, loaded_sid=sid:self._restore_children_loaded(i,loaded_sid,nodes)); w.signals.error.connect(self._worker_error); self._start_worker(w, f"Browse snapshot {directory}")

    def _restore_children_loaded(self, item, snapshot_id, nodes):
        if not self._snapshot_is_current(snapshot_id):
            return
        item.takeChildren()
        backup_root = str(self.paths.root).rstrip("/") or "/"
        for node in nodes:
            path = node.get("path", "")
            # Metadata is versioned inside each Restic snapshot under the
            # backup root, but it is implementation state rather than user
            # restore content. Hide the entire backup-root branch from the
            # restore browser so users only see domain data.
            if path == backup_root or (backup_root != "/" and path.startswith(backup_root + "/")):
                continue
            if "/.ubackup/" in path:
                continue
            is_dir = node.get("type") == "dir"
            child = QTreeWidgetItem([path, human_size(int(node.get("size",0) or 0)) if not is_dir else "", node.get("type", "")])
            for col in range(3): child.setToolTip(col, child.text(col))
            child.setData(0, ROLE_PATH, path); child.setData(0, ROLE_IS_DIR, is_dir); child.setData(0, ROLE_LOADED, False)
            child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            child.setCheckState(0, Qt.CheckState.Checked if self._restore_default_for(path) else Qt.CheckState.Unchecked)
            if is_dir:
                child.addChild(QTreeWidgetItem(["…", "", ""]))
            item.addChild(child)
        self._apply_restore_defaults(item)

    def _restore_default_for(self, path):
        component = self._restore_path_component(path)
        return component is not None and self._restore_component_enabled(component)

    def _apply_restore_defaults(self, parent=None):
        roots = [parent] if parent is not None else [self.restore_tree.topLevelItem(i) for i in range(self.restore_tree.topLevelItemCount())]
        self.restore_tree.blockSignals(True)
        def walk(item):
            path=item.data(0,ROLE_PATH)
            if path and path != "/":
                item.setCheckState(0, Qt.CheckState.Checked if self._restore_default_for(path) else Qt.CheckState.Unchecked)
            for j in range(item.childCount()): walk(item.child(j))
        for root in roots: walk(root)
        self.restore_tree.blockSignals(False)

    def _restore_tree_changed(self,item,column):
        if column != 0 or not item.data(0,ROLE_PATH):
            return
        state=item.checkState(0)
        self.restore_tree.blockSignals(True)
        def walk(ch):
            if ch.data(0,ROLE_PATH): ch.setCheckState(0,state)
            for j in range(ch.childCount()): walk(ch.child(j))
        for j in range(item.childCount()): walk(item.child(j))
        self.restore_tree.blockSignals(False)

    def _checked_restore_paths(self):
        selected=[]
        def walk(item):
            path=item.data(0,ROLE_PATH)
            if path and path != "/" and item.checkState(0)==Qt.CheckState.Checked:
                component = self._restore_path_component(path)
                if component is not None and self._restore_component_enabled(component):
                    selected.append(path); return
            for j in range(item.childCount()): walk(item.child(j))
        for i in range(self.restore_tree.topLevelItemCount()): walk(self.restore_tree.topLevelItem(i))
        return selected

    def _checked_package_selections(self):
        if not self._restore_component_enabled(BackupComponent.PACKAGES):
            return []
        return [self.restore_packages.item(i).data(ROLE_PATH) or self.restore_packages.item(i).text() for i in range(self.restore_packages.count()) if self.restore_packages.item(i).checkState()==Qt.CheckState.Checked]

    def restore_selected(self,in_place:bool):
        sid = getattr(self, "restore_snapshot_id", "")
        if not sid or not getattr(self, "restore_metadata_loaded", False): return
        paths=self._checked_restore_paths()
        if not paths:return
        if in_place:
            ans=QMessageBox.warning(self,"In-place restore","This operation may overwrite current files. Only selected paths are included, never the whole /etc tree. Continue?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
            if ans!=QMessageBox.StandardButton.Yes:return
        credentials = self._credential_for_request()
        if credentials is None: return
        self.restore_state = RestoreState.RUNNING
        def task(progress_cb=None):
            method = self.client.restore_inplace if in_place else self.client.restore_staging
            return method(self.restore_domain.value, sid, paths, credentials, progress_cb=progress_cb)
        w=Worker(task); w.signals.progress.connect(self._restic_msg); w.signals.result.connect(self._restore_done); w.signals.error.connect(self._worker_error); self._start_worker(w, "Restore in place" if in_place else "Restore to staging")

    def _restore_done(self, result):
        self.restore_state = RestoreState.COMPLETED
        target = result.get("target", "staging") if isinstance(result, dict) else str(result)
        QMessageBox.information(self, "Restore", f"Restore completed in {target}")

    def restore_selected_packages(self,dry_run:bool):
        pkgs=self._checked_package_selections()
        if not pkgs:return
        sid = getattr(self, "restore_snapshot_id", "")
        if not sid or not getattr(self, "restore_metadata_loaded", False): return
        if not dry_run:
            ans=QMessageBox.question(self,"Packages","Reinstall the selected packages using their recorded package managers? This operation modifies the system.")
            if ans!=QMessageBox.StandardButton.Yes:return
        credentials = self._credential_for_request()
        if credentials is None: return
        def task(progress_cb=None):
            method = self.client.package_simulate if dry_run else self.client.package_install
            return method(sid, pkgs, credentials, progress_cb=progress_cb)
        w=Worker(task); w.signals.progress.connect(lambda v: self.live.setText(str(v.get("current_item", v)) if isinstance(v, dict) else str(v))); w.signals.result.connect(lambda p:self._apt_done(p,dry_run)); w.signals.error.connect(self._worker_error); self._start_worker(w, "Simulate package restore" if dry_run else "Install packages")

    def _apt_done(self,p,dry):
        if isinstance(p, dict):
            output = (p.get("stdout", "") or "") + "\n" + (p.get("stderr", "") or "")
            code = p.get("returncode", p.get("exit_code", 0))
        else:
            output = (p.stdout or "") + "\n" + (p.stderr or "")
            code = p.returncode
        self.log(output); QMessageBox.information(self,"Packages",("Simulation" if dry else "Installation")+f" finished with exit code {code}")

    def update_cards(self):
        if hasattr(self,"card_sources"): self.card_sources.setText(str(len(self.selected_sources())))
        if hasattr(self,"card_configs"): self.card_configs.setText(str(sum(c.selected for c in self.configs)))
        if hasattr(self,"card_packages"): self.card_packages.setText(str(sum(p.selected for p in self.packages)))

    def _worker_error(self,trace):
        self.progress.setRange(0,100); self.log(trace); QMessageBox.critical(self,"Error",trace.splitlines()[-1] if trace else "Unknown error")
