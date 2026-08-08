from __future__ import annotations

import traceback
from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    started = Signal()
    result = Signal(object)
    error = Signal(str)
    progress = Signal(object)
    finished = Signal()


class Worker(QRunnable):
    """Run a callable with the explicit ``progress_cb`` contract.

    Callables must accept ``progress_cb``.  We intentionally never retry a
    callable after an exception: a TypeError may have been raised after a
    side effect already happened.
    """
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

    @Slot()
    def run(self):
        self.signals.started.emit()
        try:
            result = self.fn(*self.args, progress_cb=self.signals.progress.emit, **self.kwargs)
        except Exception:
            self.signals.error.emit(traceback.format_exc())
            self.signals.finished.emit()
            return
        self.signals.result.emit(result)
        self.signals.finished.emit()
