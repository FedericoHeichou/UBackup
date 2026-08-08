from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .paths import GuiPaths
from .privilege_broker import PrivilegeBroker
from .gui.privileged_client import CredentialDescriptor, PrivilegedClient


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Curated Ubuntu backup GUI powered by restic")
    p.add_argument("--backup-root", default="/backup", help="Only directory used for UBackup runtime/state/repository writes (default: /backup)")
    p.add_argument("--password-file", help="Existing restic password file to read; UBackup never modifies it")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() == 0:
        print("UBackup GUI must not be started as root.", file=sys.stderr)
        return 77
    # This is intentionally before the Qt import: one fixed startup session
    # provisions the caller leaf and retains the private pipe for automatic
    # inspection after the GUI has initialized.
    broker = PrivilegeBroker()
    startup_session = None
    try:
        configured, startup_session = broker.begin_startup(args.backup_root)
    except Exception as exc:
        print(f"Could not prepare the privileged startup session: {exc}", file=sys.stderr)
        return 78
    return _run_gui(args, broker, configured, startup_session)


def _safe_close(session, context="startup"):
    if session is None:
        return
    try:
        session.close()
    except Exception as exc:
        print(f"Could not close {context} session: {exc}", file=sys.stderr)


def _run_gui(args, broker, configured, startup_session):
    """Own the retained session until a successfully built window takes it."""
    try:
        caller_uid = os.getuid()
        paths = GuiPaths.for_user(args.backup_root, caller_uid)
        if configured.uid != caller_uid or configured.user_root != str(paths.user_root):
            raise RuntimeError("privileged configuration does not match the GUI user")
    except Exception as exc:
        _safe_close(startup_session, "startup")
        print(f"Invalid GUI configuration: {exc}", file=sys.stderr)
        return 78
    try:
        env = paths.prepare_environment()
        credentials = None
        if args.password_file:
            pf = Path(args.password_file).expanduser().resolve()
            if not pf.is_file():
                print(f"Password file not found: {pf}", file=sys.stderr)
                return 66
            credentials = CredentialDescriptor(password_file=str(pf))
        for key in tuple(os.environ):
            if key == "RESTIC_REPOSITORY" or key == "RESTIC_CACHE_DIR" or key.startswith("RESTIC_PASSWORD"):
                os.environ.pop(key, None)
        os.environ.update(env)
        # Import Qt only after redirecting XDG/cache/temp paths.
        from PySide6.QtWidgets import QApplication
        from .gui.main_window import MainWindow
        from .gui.theme import APP_QSS

        app = QApplication(sys.argv[:1])
        app.setApplicationName("UBackup")
        app.setOrganizationName("UBackup")
        app.setStyleSheet(APP_QSS)
        client = PrivilegedClient(broker, args.backup_root)
        if hasattr(client, "set_broker_fallback_enabled"):
            client.set_broker_fallback_enabled(False)
        if hasattr(client, "attach_session"):
            client.attach_session(startup_session)
        win = MainWindow(paths, env, client, credentials, startup_session)
        about_to_quit = getattr(app, "aboutToQuit", None)
        if about_to_quit is not None and hasattr(win, "shutdown"):
            about_to_quit.connect(lambda: win.shutdown(close_cache=False))
        win.showMaximized()
        result = app.exec()
        # No queued Qt callbacks can run past this point. It is now safe to
        # release SQLite after the window has drained its dedicated workers.
        if hasattr(win, "shutdown"):
            win.shutdown(close_cache=True)
        _safe_close(startup_session, "startup")
        return result
    finally:
        _safe_close(startup_session, "startup")


if __name__ == "__main__":
    raise SystemExit(main())
