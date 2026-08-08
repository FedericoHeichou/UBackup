from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QTreeWidget

from ubackup.gui.main_window import (
    FS_RENDER_CHUNK_SIZE,
    FilesystemTreeItem,
    MainWindow,
    _set_scan_status,
    ROLE_IS_DIR,
    ROLE_IS_SYMLINK,
    ROLE_LOADED,
    ROLE_PATH,
    ROLE_SIZE,
    ROLE_STATE,
    ROLE_TOTAL_SIZE,
    ROLE_SCANNED_AT,
    ROLE_CACHE_STALE,
    ROLE_SCAN_KEY,
    ROLE_RENDERED_CHECK,
)
from ubackup.cache import CacheDB
from ubackup.models import BackupState, ExclusionOrigin, SelectionPolicy
from ubackup.selection import SelectionResolver


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


class _SortHarness:
    _sort_fs_children = MainWindow._sort_fs_children

    def __init__(self, tree: QTreeWidget):
        self.fs_tree = tree

    def _sync_fs_action_widget(self):
        return None


def _item(path: str, *, size: int, state: BackupState) -> FilesystemTreeItem:
    item = FilesystemTreeItem([path.rsplit("/", 1)[-1] or "/", str(size), "—", state.value, "Calculated", ""])
    item.setData(0, ROLE_PATH, path)
    item.setData(0, ROLE_IS_DIR, True)
    item.setData(0, ROLE_SIZE, size)
    item.setData(0, ROLE_STATE, state.value)
    return item


def test_stale_cache_status_highlights_measurement_row(qapp):
    item = _item("/home", size=1024, state=BackupState.BACKED_UP)
    item.setData(0, ROLE_TOTAL_SIZE, 2048)

    _set_scan_status(item, 123.0, cached=True, stale=True)
    assert item.text(4).startswith("Cached (stale) · ")
    assert item.background(0).style() != Qt.BrushStyle.NoBrush
    assert item.foreground(1).style() != Qt.BrushStyle.NoBrush
    assert item.foreground(2).style() != Qt.BrushStyle.NoBrush
    assert item.foreground(4).style() != Qt.BrushStyle.NoBrush

    _set_scan_status(item, 123.0, cached=True, stale=False)
    assert item.text(4).startswith("Cached · ")
    assert item.background(0).style() == Qt.BrushStyle.NoBrush
    assert item.foreground(1).style() == Qt.BrushStyle.NoBrush




class _CountingFilesystemTreeItem(FilesystemTreeItem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.child_reads = 0

    def child(self, index):
        self.child_reads += 1
        return super().child(index)


def test_async_resort_keeps_expanded_descendants_attached(qapp):
    tree = QTreeWidget()
    tree.setColumnCount(6)
    root = _item("/", size=100, state=BackupState.BACKED_UP)
    home = _item("/home", size=20, state=BackupState.BACKED_UP)
    var = _item("/var", size=80, state=BackupState.PENDING)
    user = _item("/home/user", size=20, state=BackupState.BACKED_UP)
    home.addChild(user)
    root.addChildren([home, var])
    tree.addTopLevelItem(root)
    root.setExpanded(True)
    home.setExpanded(True)
    tree.setCurrentItem(user)

    # Simulate an asynchronous scan changing the sort key while a nested
    # branch is open. The old takeChildren()/addChildren() implementation
    # detached the branch here and Qt collapsed it.
    home.setData(0, ROLE_SIZE, 120)
    home.setText(1, "120")
    _SortHarness(tree)._sort_fs_children(root)

    assert root.isExpanded()
    assert home.isExpanded()
    assert home.parent() is root
    assert user.parent() is home
    assert tree.currentItem() is user


class _ReconcileHarness:
    _fs_children_loaded = MainWindow._fs_children_loaded
    _sort_fs_children = MainWindow._sort_fs_children
    _set_fs_size = MainWindow._set_fs_size
    _set_fs_total_size = MainWindow._set_fs_total_size

    def __init__(self, tree: QTreeWidget, parent: FilesystemTreeItem):
        self.fs_tree = tree
        self.parent = parent
        self._fs_children_inflight = {str(parent.data(0, ROLE_PATH))}
        self._fs_scan_after_browse = set()
        self._fs_size_inflight = set()
        self._new_unselected_paths = set()
        self._review_ancestors = set()
        self._fs_policy_revision = 0
        self._closing = False

    def _selection_context(self, _paths=None, *, known_paths_override=None):
        resolver = SelectionResolver(
            backup_root="/backup",
            policy_lookup=lambda _path: SelectionPolicy.DEFAULT,
            enabled_rules=(),
            is_known=(
                (lambda path: path in known_paths_override)
                if known_paths_override is not None
                else (lambda _path: False)
            ),
            has_previous_snapshot=False,
        )
        return resolver, []

    def _find_fs_item(self, path: str):
        if self.parent.data(0, ROLE_PATH) == path:
            return self.parent
        stack = [self.parent]
        while stack:
            current = stack.pop()
            if current.data(0, ROLE_PATH) == path:
                return current
            stack.extend(current.child(i) for i in range(current.childCount()))
        return None

    def _make_fs_item(self, *args, **kwargs):
        raise AssertionError("existing browse rows should be reconciled, not recreated")

    def _refresh_one_fs_item(self, item, **_kwargs):
        return None

    def _refresh_item_and_ancestors(self, item):
        return None

    def _refresh_item_and_ancestors_chunked(self, item, **_kwargs):
        return None

    def _recompute_loaded_size_and_ancestors(self, item):
        return None

    def _forget_fs_item(self, item):
        return None

    def _refresh_system_excluded_visibility(self):
        return None

    def _refresh_visible_fs_cache(self):
        return None

    def _queue_missing_child_scans(self, _records):
        return None

    def _current_fs_scan_key(self):
        return "test-profile"

    def _fs_item_needs_scan(self, item):
        return False

    def _sync_fs_action_widget(self):
        return None


def test_browse_completion_reuses_existing_expanded_subtree(qapp):
    tree = QTreeWidget()
    tree.setColumnCount(6)
    home = _item("/home", size=10, state=BackupState.BACKED_UP)
    user = _item("/home/user", size=10, state=BackupState.BACKED_UP)
    docs = _item("/home/user/Documents", size=5, state=BackupState.BACKED_UP)
    user.addChild(docs)
    home.addChild(user)
    tree.addTopLevelItem(home)
    home.setExpanded(True)
    user.setExpanded(True)
    tree.setCurrentItem(docs)

    original_user = user
    _ReconcileHarness(tree, home)._fs_children_loaded(
        "/home",
        [{
            "path": "/home/user",
            "type": "dir",
            "size": 42,
            "mtime_ns": 1,
            "scanned_at": 123.0,
            "cache_stale": False,
        }],
    )

    assert home.isExpanded()
    assert original_user.isExpanded()
    assert original_user.parent() is home
    assert original_user.child(0) is docs
    assert tree.currentItem() is docs
    assert original_user.data(0, ROLE_SIZE) == 42


def test_restore_page_exposes_three_independent_domain_histories(qapp):
    from PySide6.QtWidgets import QMainWindow
    from ubackup.models import BackupComponent

    class Harness(QMainWindow):
        _restore_page = MainWindow._restore_page
        _update_restore_domain_visibility = MainWindow._update_restore_domain_visibility
        def consolidate_snapshot_history(self): pass
        def delete_latest_snapshot(self): pass
        def refresh_snapshots(self): pass
        def _snapshot_selected(self, *args): pass
        def _snapshot_domain_changed(self, *args): pass
        def _restore_expand(self, *args): pass
        def _restore_tree_changed(self, *args): pass
        def restore_selected(self, *args): pass
        def restore_selected_packages(self, *args): pass
        def _set_restore_actions(self, enabled): pass

    window = Harness()
    page = window._restore_page()
    assert page is not None
    assert window.snap_domain_tabs.count() == 3
    assert [window.snap_domain_tabs.tabText(i) for i in range(3)] == [
        "Filesystem", "/etc configuration", "Packages"
    ]
    assert set(window.snap_lists) == {
        BackupComponent.FILESYSTEM, BackupComponent.CONFIGS, BackupComponent.PACKAGES
    }
    assert len({id(widget) for widget in window.snap_lists.values()}) == 3


def test_browse_reconciliation_removes_deleted_child(qapp):
    tree = QTreeWidget()
    tree.setColumnCount(6)
    home = _item("/home", size=10, state=BackupState.BACKED_UP)
    keep = _item("/home/keep", size=5, state=BackupState.BACKED_UP)
    deleted = _item("/home/deleted", size=5, state=BackupState.BACKED_UP)
    home.addChildren([keep, deleted])
    home.setData(0, ROLE_LOADED, True)
    tree.addTopLevelItem(home)

    _ReconcileHarness(tree, home)._fs_children_loaded(
        "/home",
        [{
            "path": "/home/keep", "type": "dir", "size": 5,
            "mtime_ns": 1, "scanned_at": 123.0, "cache_stale": False,
        }],
    )

    assert home.childCount() == 1
    assert home.child(0) is keep
    assert keep.parent() is home


def test_recalculate_directory_forces_authoritative_browse_before_size_scan(qapp):
    class Resolver:
        @staticmethod
        def is_hard_excluded(_path):
            return False

    class Harness:
        _recalculate_current_fs_item = MainWindow._recalculate_current_fs_item
        def __init__(self, tree):
            self.fs_tree = tree
            self._fs_scan_after_browse = set()
            self._fs_force_scan_after_browse = set()
            self.calls = []
        def _resolver(self):
            return Resolver()
        def _load_children(self, item, *, force=False):
            self.calls.append((item.data(0, ROLE_PATH), force))
        def _start_fs_size_scan(self, *args, **kwargs):
            raise AssertionError("directory recalculate must browse before scanning size")

    tree = QTreeWidget()
    tree.setColumnCount(6)
    home = _item("/home", size=10, state=BackupState.BACKED_UP)
    home.setData(0, ROLE_LOADED, True)
    tree.addTopLevelItem(home)
    tree.setCurrentItem(home)
    harness = Harness(tree)
    harness._recalculate_current_fs_item()

    assert harness.calls == [("/home", True)]
    assert harness._fs_scan_after_browse == {"/home"}
    assert harness._fs_force_scan_after_browse == {"/home"}


def test_visible_cache_refresh_skips_symlink_rows(qapp):
    class Resolver:
        @staticmethod
        def is_hard_excluded(_path):
            return False

    class Client:
        def __init__(self):
            self.calls = []

        def filesystem_cache(self, paths, *, exclude_patterns=None):
            self.calls.append((list(paths), list(exclude_patterns or [])))
            return {"records": [], "next_offset": None}

    class Harness:
        _refresh_visible_fs_cache = MainWindow._refresh_visible_fs_cache
        _visible_fs_items = MainWindow._visible_fs_items

        def __init__(self, tree):
            self.fs_tree = tree
            self.client = Client()
            self._closing = False
            self._startup_state = "success"
            self._fs_cache_refresh_inflight = False
            self._fs_cache_refresh_pending = False

        def _resolver(self):
            return Resolver()

        def _filesystem_scan_patterns(self):
            return ["/excluded/**"]

        def _apply_total_sizes(self, _records):
            return None

        def _fs_cache_loaded(self, _records):
            return None

        def _fs_cache_failed(self, _trace):
            raise AssertionError("cache refresh should not fail")

        def _start_worker(self, worker, _label, *, visible=False):
            worker.fn(progress_cb=None)

    tree = QTreeWidget(); tree.setColumnCount(6)
    regular = _item("/home/user/data", size=10, state=BackupState.PENDING)
    regular.setData(0, ROLE_IS_DIR, False)
    regular.setData(0, ROLE_IS_SYMLINK, False)
    link = _item("/home/user/link", size=0, state=BackupState.PENDING)
    link.setData(0, ROLE_IS_DIR, False)
    link.setData(0, ROLE_IS_SYMLINK, True)
    tree.addTopLevelItems([regular, link])

    harness = Harness(tree)
    harness._refresh_visible_fs_cache()

    assert harness.client.calls == [(["/home/user/data"], ["/excluded/**"])]


def test_total_size_uses_profile_independent_cached_total(qapp):
    class Resolver:
        @staticmethod
        def is_hard_excluded(_path):
            return False

    class Harness:
        _apply_total_sizes = MainWindow._apply_total_sizes
        _set_fs_total_size = MainWindow._set_fs_total_size

        def __init__(self, tree):
            self.fs_tree = tree

        def _visible_fs_items(self):
            return [self.fs_tree.topLevelItem(0)]

        def _resolver(self):
            return Resolver()

    tree = QTreeWidget()
    tree.setColumnCount(6)
    usr = _item("/usr", size=19 * 1024, state=BackupState.NOT_SELECTED)
    tree.addTopLevelItem(usr)
    Harness(tree)._apply_total_sizes({
        "/usr": {
            "path": "/usr", "exists": True, "size": 19 * 1024,
            "total_size": 17 * 1024**3, "cache_stale": False,
            "total_cache_stale": False, "scanned_at": 123.0,
        }
    })

    assert usr.text(1) == "19456"
    assert usr.text(2).endswith("GiB")
    assert usr.data(0, ROLE_TOTAL_SIZE) == 17 * 1024**3


def test_expanding_fresh_cached_directory_preserves_last_scan_label(qapp):
    class Resolver:
        @staticmethod
        def is_hard_excluded(_path):
            return False

    class StartupFlow:
        blocks_root_expansion = False

    class Harness:
        _expand_fs = MainWindow._expand_fs

        def __init__(self, tree):
            self.fs_tree = tree
            self._startup_flow = StartupFlow()
            self._fs_children_inflight = set()
            self._fs_scan_after_browse = set()

        def _resolver(self):
            return Resolver()

        def _fs_item_needs_scan(self, item):
            return False

        def _scan_expanded_item(self, path):
            raise AssertionError("fresh cache must not start a size scan")

        def _load_children(self, item, *, force=False):
            self.browse = (item.data(0, ROLE_PATH), force)

    tree = QTreeWidget()
    tree.setColumnCount(6)
    home = _item("/home", size=1024, state=BackupState.BACKED_UP)
    home.setData(0, ROLE_LOADED, True)
    home.setText(4, "Cached · 2026-08-08 12:00:00")
    tree.addTopLevelItem(home)

    harness = Harness(tree)
    harness._expand_fs(home)
    assert harness.browse == ("/home", True)
    assert home.text(4) == "Cached · 2026-08-08 12:00:00"


def test_stale_effective_size_still_uses_live_one_level_browse(qapp):
    class Resolver:
        @staticmethod
        def is_hard_excluded(_path):
            return False

    class Client:
        def __init__(self):
            self.calls = []

        def filesystem_children(self, _path, **kwargs):
            self.calls.append(kwargs)
            return {"records": [], "next_offset": None, "source": "filesystem"}

    class Harness:
        _load_children = MainWindow._load_children

        def __init__(self):
            self.client = Client()
            self._fs_children_inflight = set()
            self._closing = False
            self.last_manifest = {}
            self.started_visible = None

        def _resolver(self):
            return Resolver()

        @staticmethod
        def _filesystem_scan_patterns():
            return []

        def _start_worker(self, worker, _name, *, visible=True):
            self.started_visible = visible
            worker.fn(progress_cb=None)

    item = _item("/home", size=1024, state=BackupState.BACKED_UP)
    item.setData(0, ROLE_LOADED, False)
    item.setData(0, ROLE_SCANNED_AT, 123.0)
    item.setData(0, ROLE_CACHE_STALE, True)
    harness = Harness()

    harness._load_children(item)

    assert len(harness.client.calls) == 1
    assert harness.client.calls[0]["limit"] == 10_000
    assert "cache_only" not in harness.client.calls[0]
    assert harness.started_visible is True


def test_packages_page_unifies_managers_and_keeps_status_columns_distinct(qapp):
    from PySide6.QtWidgets import QMainWindow
    from ubackup.models import ConfigRecord

    class Cache:
        @staticmethod
        def get_selected(_kind, _key, default=False):
            return default

    class Harness(QMainWindow):
        _packages_page = MainWindow._packages_page
        _packages_loaded = MainWindow._packages_loaded
        _config_counts_by_package = MainWindow._config_counts_by_package
        def __init__(self):
            super().__init__()
            self._backup_action_buttons = []
            self.cache = Cache()
            self.configs = [ConfigRecord('/etc/curl.conf', 'unmanaged', package='curl')]
        def _start_backup(self, *args): pass
        def refresh_packages(self, *args): pass
        def _package_changed(self, *args): pass
        def update_cards(self): pass

    window = Harness()
    page = window._packages_page()
    assert page is not None
    assert [window.package_table.horizontalHeaderItem(i).text() for i in range(9)] == [
        'Keep', 'Package', 'Package manager', 'Version', 'Arch', 'Installation',
        'Status', 'Backup policy', 'Custom configs',
    ]
    window._packages_loaded([
        {'name':'curl','version':'1','architecture':'amd64','installed':True,'manual':True,'selected':True,'origin':'','manager':'apt','scope':'system','channel':'','reference':'','origin_url':'','classic':False},
        {'name':'firefox','version':'2','architecture':'','installed':True,'manual':True,'selected':True,'origin':'canonical','manager':'snap','scope':'system','channel':'latest/stable','reference':'','origin_url':'','classic':False},
        {'name':'org.example.App','version':'3','architecture':'x86_64','installed':True,'manual':True,'selected':True,'origin':'flathub','manager':'flatpak','scope':'user','channel':'stable','reference':'app/org.example.App/x86_64/stable','origin_url':'https://example.invalid/repo/','classic':False},
    ])
    rows = {
        window.package_table.item(row, 1).text(): row
        for row in range(window.package_table.rowCount())
    }
    assert window.package_table.item(rows['curl'], 2).text() == 'APT'
    assert window.package_table.item(rows['curl'], 5).text() == 'system'
    assert window.package_table.item(rows['curl'], 6).text() == 'Installed'
    assert window.package_table.item(rows['curl'], 8).text() == '1'
    assert window.package_table.item(rows['firefox'], 2).text() == 'Snap'
    assert window.package_table.item(rows['firefox'], 8).text() == '0'
    assert window.package_table.item(rows['org.example.App'], 2).text() == 'Flatpak'
    assert window.package_table.item(rows['org.example.App'], 5).text() == 'user'


class _SelectionHarness:
    _fs_changed = MainWindow._fs_changed
    _child_sizes_for_sum = MainWindow._child_sizes_for_sum
    _set_current_fs_policy = MainWindow._set_current_fs_policy
    _apply_manual_exclusion_size = MainWindow._apply_manual_exclusion_size
    _child_effective_size_for_sum = MainWindow._child_effective_size_for_sum
    _recompute_loaded_directory_size = MainWindow._recompute_loaded_directory_size
    _recompute_loaded_size_and_ancestors = MainWindow._recompute_loaded_size_and_ancestors
    _has_persisted_selected_descendant = MainWindow._has_persisted_selected_descendant
    _has_persisted_descendant_selection_mismatch = MainWindow._has_persisted_descendant_selection_mismatch
    _refresh_visible_fs = MainWindow._refresh_visible_fs
    _refresh_fs_subtree = MainWindow._refresh_fs_subtree
    _refresh_one_fs_item = MainWindow._refresh_one_fs_item
    _refresh_item_and_ancestors = MainWindow._refresh_item_and_ancestors
    _refresh_item_and_ancestors_chunked = MainWindow._refresh_item_and_ancestors_chunked
    _refresh_policy_branch = MainWindow._refresh_policy_branch
    _mark_policy_branch_size_stale = MainWindow._mark_policy_branch_size_stale
    _set_fs_size = MainWindow._set_fs_size
    _set_fs_total_size = MainWindow._set_fs_total_size
    _set_fs_check_state = MainWindow._set_fs_check_state
    _mark_fs_user_check_consumed = MainWindow._mark_fs_user_check_consumed
    _current_fs_scan_key = MainWindow._current_fs_scan_key

    def __init__(self, tree, cache, backup_root):
        self.fs_tree = tree
        self.cache = cache
        self.paths = SimpleNamespace(root=backup_root)
        self.last_manifest = {}
        self._review_ancestors = set()
        self._fs_children_inflight = set()
        self._fs_items_by_path = {}
        self._closing = False
        self._fs_policy_revision = 0
        self._fs_check_render_depth = 0
        self.refresh_cache_calls = 0

    def _selection_context(self, _paths=None, **_kwargs):
        rows = self.cache.path_policy_rows()
        policies = dict(rows)
        resolver = SelectionResolver(
            backup_root=str(self.paths.root),
            policy_lookup=lambda path: policies.get(str(Path(path)), SelectionPolicy.DEFAULT),
            enabled_rules=(),
            is_known=lambda _path: False,
            has_previous_snapshot=False,
        )
        return resolver, rows

    def _resolver(self):
        return self._selection_context()[0]

    def _filesystem_scan_patterns(self):
        return [
            ("/**" if path == "/" else path.rstrip("/") + "/**")
            for path, policy in self.cache.path_policy_rows()
            if policy is SelectionPolicy.EXCLUDE
        ]

    def _display_backup_state(self, _path, state):
        return state

    def _style_status(self, _item, _state=None):
        return None

    def _sort_fs_children(self, _item):
        return None

    def _refresh_visible_fs_cache(self):
        self.refresh_cache_calls += 1

    def _schedule_review_refresh(self):
        return None

    def update_cards(self):
        return None


def _set_total(item, value):
    item.setData(0, ROLE_TOTAL_SIZE, value)
    item.setText(2, str(value))


def test_unchecking_selected_child_recomputes_loaded_parents_from_child_sums(qapp, tmp_path):
    cache = CacheDB(tmp_path / "selection-sum.sqlite3")
    cache.set_path_policy("/home", SelectionPolicy.INCLUDE_RECURSIVE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        root = _item("/", size=9999, state=BackupState.NOT_SELECTED)
        home = _item("/home", size=8888, state=BackupState.PENDING)
        user = _item("/home/federico", size=7777, state=BackupState.PENDING)
        steam = _item("/home/federico/.steam", size=300, state=BackupState.PENDING)
        docs = _item("/home/federico/Documents", size=200, state=BackupState.PENDING)
        etc = _item("/etc", size=100, state=BackupState.NOT_SELECTED)
        for item, total in ((root, 1200), (home, 1100), (user, 1000), (steam, 450), (docs, 250), (etc, 140)):
            _set_total(item, total)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(0, Qt.CheckState.Checked)
            item.setData(0, ROLE_LOADED, True)
            item.setData(0, ROLE_SCANNED_AT, 123.0)
            item.setData(0, ROLE_CACHE_STALE, False)
        user.addChildren([steam, docs]); home.addChild(user); root.addChildren([home, etc]); tree.addTopLevelItem(root)

        harness = _SelectionHarness(tree, cache, tmp_path / "backup")
        key_before = harness._current_fs_scan_key()
        for item in (root, home, user, steam, docs, etc):
            item.setData(0, ROLE_SCAN_KEY, key_before)

        steam.setCheckState(0, Qt.CheckState.Unchecked)
        harness._fs_changed(steam, 0)

        assert cache.get_path_policy("/home/federico/.steam") is SelectionPolicy.EXCLUDE
        # These values prove the parents were rebuilt from children rather than
        # subtracting 300 from their deliberately bogus pre-change values.
        assert [item.data(0, ROLE_SIZE) for item in (root, home, user, steam)] == [300, 200, 200, 0]
        assert [item.data(0, ROLE_TOTAL_SIZE) for item in (root, home, user, steam)] == [840, 700, 700, 450]
        assert steam.data(0, ROLE_STATE) == BackupState.MANUALLY_EXCLUDED.value
        assert harness.refresh_cache_calls == 0
    finally:
        cache.close()


def test_large_parent_size_sum_yields_between_chunks(qapp):
    class Harness:
        _recompute_loaded_size_and_ancestors = MainWindow._recompute_loaded_size_and_ancestors
        _child_sizes_for_sum = MainWindow._child_sizes_for_sum
        _child_effective_size_for_sum = MainWindow._child_effective_size_for_sum
        _set_fs_size = MainWindow._set_fs_size
        _set_fs_total_size = MainWindow._set_fs_total_size

        def __init__(self):
            self._fs_children_inflight = set()
            self._fs_policy_revision = 0
            self._closing = False

        @staticmethod
        def _current_fs_scan_key():
            return "scan-key"

        @staticmethod
        def _sort_fs_children(_item):
            return None

    resolver = SelectionResolver(
        backup_root="/backup",
        policy_lookup=lambda _path: SelectionPolicy.DEFAULT,
        enabled_rules=(),
        is_known=lambda _path: False,
        has_previous_snapshot=False,
    )
    tree = QTreeWidget(); tree.setColumnCount(6)
    parent = _item("/home/federico", size=999999, state=BackupState.PENDING)
    parent.setData(0, ROLE_LOADED, True)
    child_count = FS_RENDER_CHUNK_SIZE * 3
    for index in range(child_count):
        child = _item(f"/home/federico/file-{index}", size=1, state=BackupState.PENDING)
        child.setData(0, ROLE_IS_DIR, False)
        child.setData(0, ROLE_TOTAL_SIZE, 1)
        parent.addChild(child)
    tree.addTopLevelItem(parent)

    Harness()._recompute_loaded_size_and_ancestors(parent, resolver=resolver)

    # Large child sums must yield rather than monopolize the initiating Qt
    # event. This directly protects expand/manual-exclude responsiveness.
    assert parent.data(0, ROLE_SIZE) == 999999
    for _ in range(10):
        qapp.processEvents()
    assert parent.data(0, ROLE_SIZE) == child_count
    assert parent.data(0, ROLE_TOTAL_SIZE) == child_count


def test_unchecking_partial_root_child_persists_manual_exclusion(qapp, tmp_path):
    cache = CacheDB(tmp_path / "partial-root.sqlite3")
    cache.set_path_policy("/usr/local/bin", SelectionPolicy.INCLUDE_RECURSIVE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        root = _item("/", size=100, state=BackupState.NOT_SELECTED)
        usr = _item("/usr", size=60, state=BackupState.NOT_SELECTED)
        var = _item("/var", size=40, state=BackupState.NOT_SELECTED)
        _set_total(root, 100); _set_total(usr, 60); _set_total(var, 40)
        for item in (root, usr, var):
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setData(0, ROLE_LOADED, True)
            item.setData(0, ROLE_SCANNED_AT, 123.0)
            item.setData(0, ROLE_CACHE_STALE, False)
        usr.setCheckState(0, Qt.CheckState.Unchecked)
        root.addChildren([usr, var]); tree.addTopLevelItem(root)

        harness = _SelectionHarness(tree, cache, tmp_path / "backup")
        key_before = harness._current_fs_scan_key()
        for item in (root, usr, var): item.setData(0, ROLE_SCAN_KEY, key_before)
        assert harness._resolver().resolve("/usr").selected is False
        assert harness._has_persisted_selected_descendant("/usr") is True

        harness._fs_changed(usr, 0)

        assert cache.get_path_policy("/usr") is SelectionPolicy.EXCLUDE
        assert usr.data(0, ROLE_STATE) == BackupState.MANUALLY_EXCLUDED.value
        assert usr.text(3) == "Manually excluded"
        assert root.data(0, ROLE_SIZE) == 40
        assert usr.data(0, ROLE_SIZE) == 0
    finally:
        cache.close()


def test_filesystem_page_labels_third_column_total_size(qapp):
    from PySide6.QtWidgets import QMainWindow

    class Cache:
        @staticmethod
        def get_selected(_kind, _key, default=False):
            return default

    class Harness(QMainWindow):
        _files_page = MainWindow._files_page

        def __init__(self):
            super().__init__()
            self._backup_action_buttons = []
            self.cache = Cache()

        def _start_backup(self, *args): pass
        def _show_system_excluded_changed(self, *args): pass
        def _expand_fs(self, *args): pass
        def _fs_changed(self, *args): pass
        def _fs_current_item_changed(self, *args): pass
        def _ensure_deferred_root(self): return None

    window = Harness()
    page = window._files_page()
    assert page is not None
    assert window.fs_tree.headerItem().text(1) == "Size"
    assert window.fs_tree.headerItem().text(2) == "Total size"


def test_repeated_unchecked_event_cannot_clear_existing_manual_exclusion(qapp, tmp_path):
    cache = CacheDB(tmp_path / "manual-sticky.sqlite3")
    cache.set_path_policy("/home/federico/.steam", SelectionPolicy.EXCLUDE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        steam = _item("/home/federico/.steam", size=0, state=BackupState.MANUALLY_EXCLUDED)
        steam.setFlags(steam.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        steam.setCheckState(0, Qt.CheckState.Unchecked)
        tree.addTopLevelItem(steam)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")

        # Models the harmless Unchecked event that can accompany a browse/
        # recalculate UI refresh. It must be idempotent for EXCLUDE.
        harness._fs_changed(steam, 0)

        assert cache.get_path_policy("/home/federico/.steam") is SelectionPolicy.EXCLUDE
        assert steam.data(0, ROLE_STATE) == BackupState.MANUALLY_EXCLUDED.value
        assert steam.text(3) == "Manually excluded"
    finally:
        cache.close()


def test_root_child_with_only_managed_descendants_aggregates_status(qapp, tmp_path):
    cache = CacheDB(tmp_path / "managed-root-status.sqlite3")
    cache.set_path_policy("/usr/local", SelectionPolicy.INCLUDE_RECURSIVE)
    cache.set_path_policy("/usr/share", SelectionPolicy.EXCLUDE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        usr = _item("/usr", size=300, state=BackupState.NOT_SELECTED)
        local = _item("/usr/local", size=200, state=BackupState.PENDING)
        share = _item("/usr/share", size=0, state=BackupState.MANUALLY_EXCLUDED)
        for item in (usr, local, share):
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        local.setCheckState(0, Qt.CheckState.Checked)
        share.setCheckState(0, Qt.CheckState.Unchecked)
        usr.addChildren([local, share]); tree.addTopLevelItem(usr)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")

        harness._refresh_one_fs_item(usr)

        assert usr.data(0, ROLE_STATE) == BackupState.PENDING.value
        assert usr.text(3) == "Pending backup"
        assert usr.checkState(0) == Qt.CheckState.PartiallyChecked
    finally:
        cache.close()


def test_parent_sum_treats_unscanned_hard_exclusions_as_known_zero(qapp):
    class Resolver:
        @staticmethod
        def resolve(path, is_dir=False):
            origin = ExclusionOrigin.SYSTEM if path == "/proc" else ExclusionOrigin.NONE
            return SimpleNamespace(exclusion_origin=origin)

    class Harness:
        _child_sizes_for_sum = MainWindow._child_sizes_for_sum
        _recompute_loaded_directory_size = MainWindow._recompute_loaded_directory_size
        _fs_children_inflight = set()
        _set_fs_size = MainWindow._set_fs_size
        _set_fs_total_size = MainWindow._set_fs_total_size

        @staticmethod
        def _current_fs_scan_key():
            return "profile"

    parent = _item("/", size=999, state=BackupState.NOT_SELECTED)
    parent.setData(0, ROLE_LOADED, True)
    home = _item("/home", size=100, state=BackupState.NOT_SELECTED)
    home.setData(0, ROLE_TOTAL_SIZE, 100)
    home.setData(0, ROLE_SCANNED_AT, 123.0)
    proc = _item("/proc", size=0, state=BackupState.SYSTEM_EXCLUDED)
    proc.setData(0, ROLE_TOTAL_SIZE, None)
    proc.setData(0, ROLE_SCANNED_AT, 0.0)
    parent.addChildren([home, proc])

    assert Harness()._recompute_loaded_directory_size(parent, resolver=Resolver()) is True
    assert parent.data(0, ROLE_SIZE) == 100
    assert parent.data(0, ROLE_TOTAL_SIZE) == 100


def test_root_size_is_aggregated_even_before_all_total_sizes_are_available(qapp, tmp_path):
    cache = CacheDB(tmp_path / "root-partial-total.sqlite3")
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        root = _item("/", size=None, state=BackupState.NOT_SELECTED)
        usr = _item("/usr", size=120, state=BackupState.NOT_SELECTED)
        home = _item("/home", size=80, state=BackupState.NOT_SELECTED)
        root.setData(0, ROLE_LOADED, True)
        for child in (usr, home):
            child.setData(0, ROLE_SCANNED_AT, 123.0)
            child.setData(0, ROLE_CACHE_STALE, False)
        _set_total(usr, 150)
        # /home has a valid effective Size but its Total size is not available yet.
        home.setData(0, ROLE_TOTAL_SIZE, None)
        root.addChildren([usr, home]); tree.addTopLevelItem(root)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")

        assert harness._recompute_loaded_directory_size(root) is True
        assert root.data(0, ROLE_SIZE) == 200
        assert root.data(0, ROLE_TOTAL_SIZE) is None

        _set_total(home, 90)
        assert harness._recompute_loaded_directory_size(root) is True
        assert root.data(0, ROLE_SIZE) == 200
        assert root.data(0, ROLE_TOTAL_SIZE) == 240
    finally:
        cache.close()


def test_expanded_directory_size_is_sum_of_scanned_children(qapp, tmp_path):
    cache = CacheDB(tmp_path / "child-sum.sqlite3")
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        parent = _item("/usr", size=9999, state=BackupState.NOT_SELECTED)
        first = _item("/usr/local", size=120, state=BackupState.NOT_SELECTED)
        second = _item("/usr/share", size=80, state=BackupState.NOT_SELECTED)
        parent.setData(0, ROLE_LOADED, True)
        parent.addChildren([first, second]); tree.addTopLevelItem(parent)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")
        current_key = harness._current_fs_scan_key()
        for child, total in ((first, 150), (second, 90)):
            child.setData(0, ROLE_TOTAL_SIZE, total)
            child.setData(0, ROLE_SCANNED_AT, 123.0)
            child.setData(0, ROLE_CACHE_STALE, False)
            child.setData(0, ROLE_SCAN_KEY, current_key)

        assert harness._recompute_loaded_directory_size(parent) is True
        assert parent.data(0, ROLE_SIZE) == 200
        assert parent.data(0, ROLE_TOTAL_SIZE) == 240
    finally:
        cache.close()


def test_manual_exclusion_does_not_trigger_global_visible_cache_refresh(qapp, tmp_path):
    cache = CacheDB(tmp_path / "manual-local-refresh.sqlite3")
    cache.set_path_policy("/home", SelectionPolicy.INCLUDE_RECURSIVE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        home = _item("/home", size=100, state=BackupState.PENDING)
        child = _item("/home/data", size=100, state=BackupState.PENDING)
        for node in (home, child):
            node.setFlags(node.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            node.setData(0, ROLE_LOADED, True)
            node.setData(0, ROLE_SCANNED_AT, 123.0)
            node.setData(0, ROLE_CACHE_STALE, False)
        home.addChild(child); tree.addTopLevelItem(home)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")
        key = harness._current_fs_scan_key()
        home.setData(0, ROLE_SCAN_KEY, key); child.setData(0, ROLE_SCAN_KEY, key)
        child.setCheckState(0, Qt.CheckState.Unchecked)

        harness._fs_changed(child, 0)

        assert cache.get_path_policy("/home/data") is SelectionPolicy.EXCLUDE
        assert harness.refresh_cache_calls == 0
        assert child.data(0, ROLE_SIZE) == 0
        assert child.data(0, ROLE_STATE) == BackupState.MANUALLY_EXCLUDED.value
    finally:
        cache.close()


def test_large_manual_exclusion_repaint_is_chunked_across_event_loop(qapp, tmp_path):
    cache = CacheDB(tmp_path / "manual-chunked-refresh.sqlite3")
    cache.set_path_policy("/home", SelectionPolicy.INCLUDE_RECURSIVE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        home = _CountingFilesystemTreeItem(["home", "450", "—", BackupState.PENDING.value, "Calculated", ""])
        home.setData(0, ROLE_PATH, "/home")
        home.setData(0, ROLE_IS_DIR, True)
        home.setData(0, ROLE_SIZE, 450)
        home.setData(0, ROLE_STATE, BackupState.PENDING.value)
        home.setFlags(home.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        home.setCheckState(0, Qt.CheckState.Checked)
        home.setData(0, ROLE_LOADED, True)
        home.setData(0, ROLE_SCANNED_AT, 123.0)
        home.setData(0, ROLE_CACHE_STALE, False)
        for index in range(450):
            child = _item(f"/home/item-{index}", size=1, state=BackupState.PENDING)
            child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            child.setCheckState(0, Qt.CheckState.Checked)
            child.setData(0, ROLE_LOADED, True)
            child.setData(0, ROLE_SCANNED_AT, 123.0)
            child.setData(0, ROLE_CACHE_STALE, False)
            home.addChild(child)
        tree.addTopLevelItem(home)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")
        key = harness._current_fs_scan_key()
        home.setData(0, ROLE_SCAN_KEY, key)
        for index in range(home.childCount()):
            home.child(index).setData(0, ROLE_SCAN_KEY, key)

        original_refresh = harness._refresh_one_fs_item
        refreshed: list[str] = []

        def counted_refresh(current, **kwargs):
            refreshed.append(str(current.data(0, ROLE_PATH)))
            return original_refresh(current, **kwargs)

        harness._refresh_one_fs_item = counted_refresh
        home.child_reads = 0
        home.setCheckState(0, Qt.CheckState.Unchecked)
        harness._fs_changed(home, 0)

        # The callback persists policy and updates the clicked row, but does
        # not synchronously traverse/repaint all 450 descendants.  Counting
        # child() reads catches the old hidden O(n) pre-collection regression.
        assert cache.get_path_policy("/home") is SelectionPolicy.EXCLUDE
        assert home.data(0, ROLE_STATE) == BackupState.MANUALLY_EXCLUDED.value
        assert len(refreshed) < 100
        assert home.child_reads < FS_RENDER_CHUNK_SIZE

        for _ in range(10):
            qapp.processEvents()
        assert all(
            home.child(index).data(0, ROLE_STATE) == BackupState.MANUALLY_EXCLUDED.value
            for index in range(home.childCount())
        )
    finally:
        cache.close()


def test_large_cached_child_refresh_is_chunked_and_not_global(qapp):
    class Harness:
        _fs_cached_children_loaded = MainWindow._fs_cached_children_loaded
        _find_fs_item = MainWindow._find_fs_item
        _set_fs_size = MainWindow._set_fs_size
        _set_fs_total_size = MainWindow._set_fs_total_size

        def __init__(self, tree, root):
            self.fs_tree = tree
            self._fs_items_by_path = {"/home": root}
            for index in range(root.childCount()):
                child = root.child(index)
                self._fs_items_by_path[str(child.data(0, ROLE_PATH))] = child
            self._fs_children_inflight = {"/home"}
            self._closing = False
            self.recomputed = 0

        @staticmethod
        def _current_fs_scan_key():
            return "scan-key"

        def _recompute_loaded_size_and_ancestors(self, _item):
            self.recomputed += 1

        @staticmethod
        def _sort_fs_children(_item):
            return None

    tree = QTreeWidget(); tree.setColumnCount(6)
    home = _item("/home", size=0, state=BackupState.PENDING)
    home.setData(0, ROLE_LOADED, True)
    for index in range(450):
        child = _item(f"/home/item-{index}", size=0, state=BackupState.PENDING)
        home.addChild(child)
    tree.addTopLevelItem(home)
    harness = Harness(tree, home)
    records = [
        {
            "path": f"/home/item-{index}", "size": index + 1,
            "total_size": index + 1, "scanned_at": 123.0, "cache_stale": False,
        }
        for index in range(450)
    ]

    harness._fs_cached_children_loaded("/home", records)

    # Only the first chunk is applied synchronously; no global refresh method
    # exists on this harness, so any regression that calls it fails the test.
    assert home.child(FS_RENDER_CHUNK_SIZE - 1).data(0, ROLE_SIZE) == FS_RENDER_CHUNK_SIZE
    assert home.child(FS_RENDER_CHUNK_SIZE).data(0, ROLE_SIZE) == 0

    for _ in range(10):
        qapp.processEvents()
    assert home.child(449).data(0, ROLE_SIZE) == 450
    # Cache refresh is separate from live browse inflight accounting.
    assert "/home" in harness._fs_children_inflight
    assert harness.recomputed == 1


def test_manual_exclude_action_survives_size_repaint_and_restart(qapp, tmp_path):
    """A passive Size update must never turn Manual exclude back into Include."""
    db = tmp_path / "manual-action-persistent.sqlite3"
    cache = CacheDB(db)
    cache.set_path_policy("/home", SelectionPolicy.INCLUDE_RECURSIVE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        bigfiles = _item("/home/federico/.bigfiles", size=4096, state=BackupState.PENDING)
        bigfiles.setFlags(bigfiles.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        bigfiles.setCheckState(0, Qt.CheckState.Checked)
        bigfiles.setData(0, ROLE_RENDERED_CHECK, int(Qt.CheckState.Checked.value))
        bigfiles.setData(0, ROLE_LOADED, True)
        bigfiles.setData(0, ROLE_SCANNED_AT, 123.0)
        bigfiles.setData(0, ROLE_CACHE_STALE, False)
        tree.addTopLevelItem(bigfiles)
        tree.setCurrentItem(bigfiles)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")
        bigfiles.setData(0, ROLE_SCAN_KEY, harness._current_fs_scan_key())
        tree.itemChanged.connect(harness._fs_changed)

        # This follows the real button path. _apply_manual_exclusion_size()
        # writes ROLE_SIZE on column 0, which emits QTreeWidget.itemChanged.
        # Before the render/user-intent guard that passive signal was treated
        # as a Checked user action and immediately overwrote EXCLUDE with INCLUDE.
        harness._set_current_fs_policy(SelectionPolicy.EXCLUDE)
        qapp.processEvents()

        assert cache.get_path_policy("/home/federico/.bigfiles") is SelectionPolicy.EXCLUDE
        assert bigfiles.checkState(0) == Qt.CheckState.Unchecked
        assert bigfiles.data(0, ROLE_STATE) == BackupState.MANUALLY_EXCLUDED.value
        assert bigfiles.data(0, ROLE_SIZE) == 0
    finally:
        cache.close()

    reopened = CacheDB(db)
    try:
        assert reopened.get_path_policy("/home/federico/.bigfiles") is SelectionPolicy.EXCLUDE
    finally:
        reopened.close()


def test_passive_checkbox_repaint_cannot_replace_persisted_exclude(qapp, tmp_path):
    cache = CacheDB(tmp_path / "passive-repaint.sqlite3")
    cache.set_path_policy("/home", SelectionPolicy.INCLUDE_RECURSIVE)
    cache.set_path_policy("/home/federico/.steam", SelectionPolicy.EXCLUDE)
    try:
        tree = QTreeWidget(); tree.setColumnCount(6)
        steam = _item("/home/federico/.steam", size=0, state=BackupState.MANUALLY_EXCLUDED)
        steam.setFlags(steam.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        steam.setCheckState(0, Qt.CheckState.Unchecked)
        steam.setData(0, ROLE_RENDERED_CHECK, int(Qt.CheckState.Unchecked.value))
        tree.addTopLevelItem(steam)
        harness = _SelectionHarness(tree, cache, tmp_path / "backup")
        tree.itemChanged.connect(harness._fs_changed)

        # Simulate a stale asynchronous renderer trying to paint Checked. Both
        # the marker setData() and setCheckState() can emit itemChanged; neither
        # is allowed to become a policy write.
        harness._set_fs_check_state(steam, Qt.CheckState.Checked)
        qapp.processEvents()
        assert cache.get_path_policy("/home/federico/.steam") is SelectionPolicy.EXCLUDE

        # A genuine user toggle is distinguishable because the last rendered
        # marker still contains the previous state. Voluntary inclusion works.
        harness._set_fs_check_state(steam, Qt.CheckState.Unchecked)
        steam.setCheckState(0, Qt.CheckState.Checked)
        qapp.processEvents()
        assert cache.get_path_policy("/home/federico/.steam") is SelectionPolicy.INCLUDE_RECURSIVE
    finally:
        cache.close()


def test_unmarked_startup_row_uses_live_one_level_browse(qapp):
    class Resolver:
        @staticmethod
        def is_hard_excluded(_path):
            return False

    class Client:
        def __init__(self):
            self.calls = []

        def filesystem_children(self, _path, **kwargs):
            self.calls.append(kwargs)
            return {"records": [], "next_offset": None, "source": "filesystem"}

    class Harness:
        _load_children = MainWindow._load_children

        def __init__(self):
            self.client = Client()
            self._fs_children_inflight = set()
            self._closing = False
            self.last_manifest = {}
            self.started_visible = None

        def _resolver(self):
            return Resolver()

        @staticmethod
        def _filesystem_scan_patterns():
            return []

        def _start_worker(self, worker, _name, *, visible=True):
            self.started_visible = visible
            worker.fn(progress_cb=None)

    item = _item("/home", size=None, state=BackupState.BACKED_UP)
    item.setData(0, ROLE_LOADED, False)
    item.setData(0, ROLE_SCANNED_AT, 0.0)  # startup has not repainted cache metadata yet
    harness = Harness()

    harness._load_children(item)

    assert len(harness.client.calls) == 1
    assert harness.client.calls[0]["limit"] == 10_000
    assert "cache_only" not in harness.client.calls[0]
    assert harness.started_visible is True


def test_missing_child_scan_queue_ignores_stale_cached_directories(qapp):
    class Resolver:
        @staticmethod
        def is_hard_excluded(_path):
            return False

    class Harness:
        _queue_missing_child_scans = MainWindow._queue_missing_child_scans

        def __init__(self):
            self._fs_size_inflight = set()
            self._fs_auto_scan_queue = []
            self._fs_auto_scan_queued = set()
            self.started = 0

        def _resolver(self):
            return Resolver()

        def _start_next_fs_auto_scan(self):
            self.started += 1

    harness = Harness()
    harness._queue_missing_child_scans([
        {"path": "/home/missing", "type": "dir", "cache_present": False},
        {
            "path": "/home/stale", "type": "dir", "cache_present": True,
            "cache_stale": True,
        },
        {"path": "/home/file.bin", "type": "file", "cache_present": False},
    ])

    assert harness._fs_auto_scan_queue == ["/home/missing"]
    assert harness._fs_auto_scan_queued == {"/home/missing"}
    assert harness.started == 1
