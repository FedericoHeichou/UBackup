from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication

from ubackup.gui.task_monitor import TaskMonitorDialog, TaskRegistry


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def test_background_task_bytes_keep_raw_value_and_show_human_tooltip(qapp):
    registry = TaskRegistry()
    task_id = registry.create("Backup")
    registry.progress(task_id, {"bytes_done": 3 * 1024**3, "total_bytes": 5 * 1024**3})
    dialog = TaskMonitorDialog(registry)
    dialog.refresh()

    cell = dialog.table.item(0, 6)
    assert cell.text() == str(3 * 1024**3)
    assert cell.toolTip() == "Processed: 3.0 GiB\nRestic total: 5.0 GiB"
    assert registry.records()[0].bytes_total == 5 * 1024**3
    dialog.close()


def test_background_task_percentage_never_moves_backwards(qapp):
    registry = TaskRegistry()
    task_id = registry.create("Backup")
    registry.progress(task_id, {"percent_done": 0.50})
    registry.progress(task_id, {"percent_done": 0.42})
    assert registry.records()[0].percent == 50.0

    dialog = TaskMonitorDialog(registry)
    dialog.refresh()
    assert dialog.table.item(0, 3).text() == "50.0%"
    dialog.close()
