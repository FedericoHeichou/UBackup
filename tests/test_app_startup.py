import sys
import types
import os
from types import SimpleNamespace

import pytest

from ubackup import app
from ubackup.paths import GuiPaths


def _fake_qt(monkeypatch, events):
    qt = types.ModuleType("PySide6")
    widgets = types.ModuleType("PySide6.QtWidgets")

    class QApplication:
        def __init__(self, argv):
            events.append("qt")

        def setApplicationName(self, value):
            pass

        def setOrganizationName(self, value):
            pass

        def setStyleSheet(self, value):
            pass

        def exec(self):
            return 0

    setattr(widgets, "QApplication", QApplication)
    setattr(qt, "QtWidgets", widgets)
    monkeypatch.setitem(sys.modules, "PySide6", qt)
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", widgets)


def _fake_gui_modules(monkeypatch, received, window_events=None):
    main_window = types.ModuleType("ubackup.gui.main_window")

    class MainWindow:
        def __init__(self, *args):
            received.append(args)

        def show(self):
            pass

        def showMaximized(self):
            if window_events is not None:
                window_events.append("maximized")

    setattr(main_window, "MainWindow", MainWindow)
    monkeypatch.setitem(sys.modules, "ubackup.gui.main_window", main_window)

    theme = types.ModuleType("ubackup.gui.theme")
    setattr(theme, "APP_QSS", "")
    monkeypatch.setitem(sys.modules, "ubackup.gui.theme", theme)


def test_root_invocation_rejects_before_broker_or_qt(monkeypatch):
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    monkeypatch.setattr(app, "PrivilegeBroker", lambda: pytest.fail("broker must not be created"))

    assert app.main(["--backup-root", "/unused"]) == 77


def test_startup_precedes_environment_and_qt(monkeypatch, tmp_path):
    events = []
    uid = 1000
    paths = GuiPaths.for_user(tmp_path, uid)

    class Broker:
        def begin_startup(self, backup_root):
            events.append("startup")
            return SimpleNamespace(uid=uid, user_root=str(paths.user_root)), SimpleNamespace(close=lambda: events.append("close"))

        def configure(self, *_args, **_kwargs):
            raise AssertionError("automatic configure is forbidden")

        def inspect(self, *_args, **_kwargs):
            raise AssertionError("automatic inspect is forbidden")

    monkeypatch.setattr(app.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(app.os, "getuid", lambda: uid)
    monkeypatch.setattr(app, "PrivilegeBroker", Broker)
    original_prepare = GuiPaths.prepare_environment

    def prepare(self):
        events.append("environment")
        return original_prepare(self, base={})

    monkeypatch.setattr(GuiPaths, "prepare_environment", prepare)
    _fake_qt(monkeypatch, events)
    window_events = []
    _fake_gui_modules(monkeypatch, [], window_events)

    assert app.main(["--backup-root", str(tmp_path)]) == 0
    assert events[:3] == ["startup", "environment", "qt"]
    assert window_events == ["maximized"]


def test_startup_identity_mismatch_fails_closed(monkeypatch, tmp_path):
    class Broker:
        def begin_startup(self, backup_root):
            return SimpleNamespace(uid=1001, user_root="/wrong/leaf"), SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(app.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(app.os, "getuid", lambda: 1000)
    monkeypatch.setattr(app, "PrivilegeBroker", Broker)
    monkeypatch.setattr(GuiPaths, "prepare_environment", lambda self: pytest.fail("must not prepare env"))

    assert app.main(["--backup-root", str(tmp_path)]) == 78


def test_main_window_receives_client_credentials_and_sanitized_environment(monkeypatch, tmp_path):
    uid = 1000
    paths = GuiPaths.for_user(tmp_path, uid)
    received = []
    events = []

    class Broker:
        def begin_startup(self, backup_root):
            return SimpleNamespace(uid=uid, user_root=str(paths.user_root)), SimpleNamespace(close=lambda: None)

    monkeypatch.setattr(app.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(app.os, "getuid", lambda: uid)
    monkeypatch.setattr(app, "PrivilegeBroker", Broker)
    monkeypatch.setattr(app, "PrivilegedClient", lambda broker, root: "client")
    monkeypatch.setenv("RESTIC_REPOSITORY", "/secret/repository")
    monkeypatch.setenv("RESTIC_CACHE_DIR", "/secret/cache")
    monkeypatch.setenv("RESTIC_PASSWORD_FILE", "/secret/password")
    _fake_qt(monkeypatch, events)
    _fake_gui_modules(monkeypatch, received)
    password_file = tmp_path / "password"
    password_file.write_text("not inspected")

    assert app.main(["--backup-root", str(tmp_path), "--password-file", str(password_file)]) == 0
    assert len(received) == 1
    window_paths, env, client, credentials, startup_session = received[0]
    assert window_paths == paths
    assert client == "client"
    assert credentials.password_file == str(password_file.resolve())
    assert startup_session is not None
    assert "RESTIC_REPOSITORY" not in env
    assert "RESTIC_CACHE_DIR" not in env
    assert not any(key.startswith("RESTIC_PASSWORD") for key in env)
    assert "RESTIC_REPOSITORY" not in os.environ
    assert "RESTIC_CACHE_DIR" not in os.environ
    assert not any(key.startswith("RESTIC_PASSWORD") for key in os.environ)


def test_window_construction_failure_closes_transferred_session(monkeypatch, tmp_path):
    uid = 1000; paths = GuiPaths.for_user(tmp_path, uid); closed = []

    class Broker:
        def begin_startup(self, _root):
            return SimpleNamespace(uid=uid, user_root=str(paths.user_root)), SimpleNamespace(close=lambda: closed.append(True))

    monkeypatch.setattr(app.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(app.os, "getuid", lambda: uid)
    monkeypatch.setattr(app, "PrivilegeBroker", Broker)
    monkeypatch.setattr(GuiPaths, "prepare_environment", lambda self: {})
    _fake_qt(monkeypatch, [])
    failing = types.ModuleType("ubackup.gui.main_window")
    class MainWindow:
        def __init__(self, *args):
            raise RuntimeError("construction failed")
    setattr(failing, "MainWindow", MainWindow)
    monkeypatch.setitem(sys.modules, "ubackup.gui.main_window", failing)
    theme = types.ModuleType("ubackup.gui.theme"); setattr(theme, "APP_QSS", "")
    monkeypatch.setitem(sys.modules, "ubackup.gui.theme", theme)
    with pytest.raises(RuntimeError):
        app.main(["--backup-root", str(tmp_path)])
    assert closed == [True]
