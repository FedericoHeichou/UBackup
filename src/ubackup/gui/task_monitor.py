from __future__ import annotations

import time
import uuid
from dataclasses import replace
from typing import Any

from PySide6.QtCore import QObject, Signal, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QDialog, QHeaderView, QTableWidget, QTableWidgetItem, QVBoxLayout

from ..models import TaskRecord, TaskState
from ..telemetry import human_bytes
from .semantic_style import semantic_color, semantic_label


class TaskRegistry(QObject):
    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._records: dict[str, TaskRecord] = {}
        self._last_progress_emit: dict[str, float] = {}

    def create(self, name: str) -> str:
        task_id = str(uuid.uuid4())
        now = time.time()
        self._records[task_id] = TaskRecord(task_id, name, TaskState.QUEUED, now, now)
        self.changed.emit()
        return task_id

    def start(self, task_id: str) -> None:
        record = self._records.get(task_id)
        if record:
            record.state = TaskState.RUNNING
            record.updated_at = time.time()
            self.changed.emit()

    def progress(self, task_id: str, value: Any) -> None:
        record = self._records.get(task_id)
        if not record or record.state not in {TaskState.QUEUED, TaskState.RUNNING}:
            return
        record.state = TaskState.RUNNING
        record.updated_at = time.time()
        if isinstance(value, dict):
            percent = value.get("percent_done")
            if isinstance(percent, (int, float)) and not isinstance(percent, bool):
                normalized = max(0.0, min(100.0, float(percent) * 100.0 if float(percent) <= 1 else float(percent)))
                record.percent = max(float(record.percent or 0.0), normalized)
            current = value.get("current_item") or value.get("item")
            if not current:
                files = value.get("current_files")
                if isinstance(files, list) and files:
                    current = files[0]
            if current:
                record.current_item = str(current)
            for key, attr in (("items_processed", "items_processed"), ("files_done", "items_processed"), ("bytes_done", "bytes_processed")):
                raw = value.get(key)
                if isinstance(raw, int) and raw >= 0:
                    # Progress counters are cumulative by contract. Guard the
                    # UI against a buggy/legacy producer resetting a subtree
                    # counter so task telemetry never appears to run backwards.
                    setattr(record, attr, max(int(getattr(record, attr, 0) or 0), raw))
            raw_total = value.get("total_bytes")
            if isinstance(raw_total, int) and raw_total >= 0:
                # Restic's scan can refine its expected logical total while the
                # backup is already running. Keep the largest observed value so
                # the task monitor exposes the denominator behind percent_done.
                record.bytes_total = max(int(record.bytes_total or 0), raw_total)
        elif isinstance(value, (tuple, list)) and value:
            record.current_item = str(value[0])
            if len(value) > 1 and isinstance(value[1], int):
                record.bytes_processed = value[1]
            if len(value) > 2 and isinstance(value[2], int):
                record.items_processed = value[2]
        elif value is not None:
            record.current_item = str(value)
        # Keep worker-side state current, but do not repaint the GUI for every
        # filesystem/Restic event.  The dialog also has a 1 s timer.
        last = self._last_progress_emit.get(task_id, 0.0)
        now = time.monotonic()
        if now - last >= 0.5:
            self._last_progress_emit[task_id] = now
            self.changed.emit()

    def complete(self, task_id: str) -> None:
        record = self._records.get(task_id)
        if record and record.state not in {TaskState.FAILED, TaskState.CANCELLED}:
            record.state = TaskState.COMPLETED
            record.updated_at = time.time()
            if record.percent is not None:
                record.percent = 100.0
            self.changed.emit()

    def fail(self, task_id: str, error: str) -> None:
        record = self._records.get(task_id)
        if record:
            record.state = TaskState.FAILED
            record.error = error.splitlines()[-1] if error else "Unknown error"
            record.updated_at = time.time()
            self.changed.emit()

    def records(self) -> list[TaskRecord]:
        return sorted(self._records.values(), key=lambda item: item.started_at, reverse=True)

    def running_count(self) -> int:
        return sum(r.state in {TaskState.QUEUED, TaskState.RUNNING} for r in self._records.values())


class TaskMonitorDialog(QDialog):
    def __init__(self, registry: TaskRegistry, parent=None):
        super().__init__(parent)
        self.registry = registry
        self.setWindowTitle("Background tasks")
        self.resize(980, 480)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Task", "State", "Elapsed", "Progress", "Current item", "Items", "Bytes"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)
        registry.changed.connect(self.refresh)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.refresh()

    def refresh(self) -> None:
        records = self.registry.records()
        self.table.setRowCount(len(records))
        now = time.time()
        for row, record in enumerate(records):
            elapsed = max(0, int((record.updated_at if record.state in {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED} else now) - record.started_at))
            values = [
                record.name,
                semantic_label(record.state),
                f"{elapsed // 60:02d}:{elapsed % 60:02d}",
                "—" if record.percent is None else f"{record.percent:.1f}%",
                record.current_item or record.error,
                str(record.items_processed or "—"),
                str(record.bytes_processed or "—"),
            ]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 6 and record.bytes_processed:
                    tooltip = f"Processed: {human_bytes(record.bytes_processed)}"
                    if record.bytes_total:
                        tooltip += f"\nRestic total: {human_bytes(record.bytes_total)}"
                    item.setToolTip(tooltip)
                else:
                    item.setToolTip(text)
                if col == 1:
                    item.setForeground(QColor(semantic_color(record.state)))
                self.table.setItem(row, col, item)
