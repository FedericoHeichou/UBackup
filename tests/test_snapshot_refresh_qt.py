from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from ubackup.gui.main_window import MainWindow
from ubackup.models import BackupComponent


class _Client:
    def __init__(self):
        self.components: list[str] = []

    def snapshots(self, component, _credentials, *, offset=0):
        self.components.append(component)
        return []


class _RefreshHarness:
    refresh_snapshots = MainWindow.refresh_snapshots

    def __init__(self):
        self.client = _Client()
        self.worker = None

    @staticmethod
    def _credential_for_request():
        return object()

    def _start_worker(self, worker, _name):
        self.worker = worker

    @staticmethod
    def _snapshot_histories_loaded(_histories):
        pass

    @staticmethod
    def _worker_error(_trace):
        pass


def test_refresh_histories_ignores_qpushbutton_checked_boolean():
    harness = _RefreshHarness()

    # QPushButton.clicked(bool) used to pass False here.  The worker then tried
    # to evaluate ``False.value`` and failed with AttributeError.
    harness.refresh_snapshots(False)
    assert harness.worker is not None
    result = harness.worker.fn(progress_cb=None)

    expected = [
        BackupComponent.FILESYSTEM.value,
        BackupComponent.CONFIGS.value,
        BackupComponent.PACKAGES.value,
    ]
    assert harness.client.components == expected
    assert list(result) == expected
