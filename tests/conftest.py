from __future__ import annotations

from pathlib import Path

import pytest

from ubackup.paths import PrivilegedPaths


@pytest.fixture
def unprivileged_privileged_runtime(monkeypatch):
    """Run privileged handler orchestration tests without requiring UID 0.

    Handler tests exercise validation, planning, Restic dispatch and result
    shaping.  Ownership enforcement belongs to the dedicated privileged-path
    security tests.  Requiring these orchestration tests to create genuinely
    root-owned ``tmp_path`` trees would make the normal pytest suite depend on
    being run as root, which is both unsafe and unlike the supported developer
    workflow.

    This fixture replaces only ``PrivilegedPaths.prepare_environment`` for the
    requesting test.  Production code and the ownership checks themselves are
    not modified.
    """

    def prepare_environment(self: PrivilegedPaths, base: dict[str, str] | None = None) -> dict[str, str]:
        directories: tuple[tuple[Path, int], ...] = (
            (self.internal, 0o711),
            (self.state, 0o700),
            (self.current, 0o700),
            (self.cache, 0o700),
            (self.runtime, 0o700),
            (self.sandbox_home, 0o700),
            (self.tmp, 0o700),
            (self.logs, 0o700),
            (self.secrets, 0o700),
            (self.restores, 0o700),
            (self.cache / "xdg", 0o700),
            (self.internal / "xdg-config", 0o700),
            (self.internal / "xdg-data", 0o700),
            (self.cache / "restic", 0o700),
            (self.plans, 0o700),
        )
        for directory, mode in directories:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(mode)

        source = {} if base is None else base
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
        for key in ("LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LANGUAGE"):
            value = source.get(key)
            if isinstance(value, str) and value:
                env[key] = value
        env.update(
            {
                "HOME": str(self.sandbox_home),
                "XDG_CACHE_HOME": str(self.cache / "xdg"),
                "XDG_CONFIG_HOME": str(self.internal / "xdg-config"),
                "XDG_DATA_HOME": str(self.internal / "xdg-data"),
                "TMPDIR": str(self.tmp),
                "TEMP": str(self.tmp),
                "TMP": str(self.tmp),
                "RESTIC_CACHE_DIR": str(self.cache / "restic"),
                "RESTIC_REPOSITORY": str(self.repository),
                "RESTIC_PASSWORD_FILE": str(self.password_file),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return env

    monkeypatch.setattr(PrivilegedPaths, "prepare_environment", prepare_environment)
