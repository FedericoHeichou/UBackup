from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from ubackup.models import DryRunSummary
from ubackup.paths import PrivilegedPaths
from ubackup.privileged import backup as backup_mod
from ubackup.privileged import restore as restore_mod
from ubackup.privileged import startup as startup_mod
from ubackup.privileged.protocol import (
    BACKUP_OPERATION,
    INSPECT_OPERATION,
    MAINTENANCE_OPERATION,
    PACKAGES_INSTALL_OPERATION,
    RESTORE_INPLACE_OPERATION,
    RESTORE_STAGING_OPERATION,
)


class _Admission:
    def __init__(self, root: Path):
        self.root = root

    def revalidate(self, ops=None):
        return None


@pytest.mark.parametrize(
    ("operation", "payload", "handler_name"),
    [
        (INSPECT_OPERATION, {"kind": "repository-size"}, "handle_inspect"),
        (
            BACKUP_OPERATION,
            {
                "sources": [],
                "source_exclusions": [],
                "exclude_rules": [],
                "packages": [],
                "configs": [],
                "components": ["packages"],
                "dry_run": True,
            },
            "handle_backup",
        ),
        (
            RESTORE_STAGING_OPERATION,
            {"component": "filesystem", "snapshot_id": "abcdef12", "includes": ["/home/user/file"]},
            "handle_restore_staging",
        ),
        (
            RESTORE_INPLACE_OPERATION,
            {"component": "filesystem", "snapshot_id": "abcdef12", "includes": ["/home/user/file"]},
            "handle_restore_inplace",
        ),
        (
            PACKAGES_INSTALL_OPERATION,
            {"snapshot_id": "abcdef12", "packages": [{"manager": "apt", "scope": "system", "name": "curl"}], "simulate": True},
            "handle_packages_install",
        ),
        (
            MAINTENANCE_OPERATION,
            {"action": "delete-latest", "component": "filesystem", "snapshot_id": "abcdef12"},
            "handle_maintenance",
        ),
    ],
)
def test_authenticated_session_dispatches_every_supported_privileged_operation(
    tmp_path, monkeypatch, operation, payload, handler_name
):
    calls = []

    def fake_handler(request, uid, environment, ops, progress_cb=None):
        calls.append((request.operation, request.payload, uid))
        return {"ok": request.operation}

    monkeypatch.setattr(startup_mod, handler_name, fake_handler)
    admission = _Admission(tmp_path)
    result = startup_mod._dispatch_session_request(
        admission,
        1000,
        {},
        {"password": "secret", "password_file": None},
        {
            "operation": operation,
            "request_id": "11111111-1111-4111-8111-111111111111",
            "payload": payload,
        },
    )

    assert result == {"ok": operation}
    assert calls and calls[0][0] == operation
    if operation != INSPECT_OPERATION or payload["kind"] not in {"repository-size"}:
        assert calls[0][1]["credentials"] == {"password": "secret", "password_file": None}


def test_backup_handler_builds_plan_and_invokes_restic_engine(tmp_path, monkeypatch, unprivileged_privileged_runtime):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component("packages")
    for directory in (
        paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime, paths.plans,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(backup_mod, "admit_backup_root", lambda *a, **k: _Admission(root))
    monkeypatch.setattr(backup_mod, "_merge_discovery", lambda policy, env, uid, progress=None: dict(policy))
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})

    @contextlib.contextmanager
    def no_lock(_paths):
        yield
    monkeypatch.setattr(backup_mod, "_backup_lock", no_lock)

    calls = []
    class Engine:
        def backup(self, sources_file, excludes_file, dry_run, on_message=None):
            calls.append((Path(sources_file), Path(excludes_file), dry_run))
            return DryRunSummary(snapshot_id="abcdef12", total_bytes_processed=12, data_added=3, data_added_packed=2)

    @contextlib.contextmanager
    def fake_credentials(*args, **kwargs):
        yield Engine()
    monkeypatch.setattr(backup_mod, "credentialed_engine", fake_credentials)

    request = SimpleNamespace(
        backup_root=str(root),
        request_id="11111111-1111-4111-8111-111111111111",
        payload={
            "sources": [], "source_exclusions": [], "exclude_rules": [],
            "packages": [], "configs": [], "components": ["packages"], "dry_run": False,
            "credentials": {"password": "secret", "password_file": None},
        },
    )
    result = backup_mod.handle_backup(request, 1000, {}, None)
    assert result["receipt"]["snapshot_id"] == "abcdef12"
    assert paths.manifest_file.exists()
    assert (paths.current / "packages-apt.json").exists()
    assert (paths.current / "packages-snap.json").exists()
    assert (paths.current / "packages-flatpak.json").exists()
    assert not paths.packages_file.exists()
    assert calls and calls[0][0] == paths.sources_file

def test_restore_handlers_invoke_restic_for_staging_and_inplace(tmp_path, monkeypatch, unprivileged_privileged_runtime):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component("filesystem")
    paths.restores.mkdir(parents=True)
    monkeypatch.setattr(restore_mod, "admit_backup_root", lambda *a, **k: _Admission(root))
    monkeypatch.setattr(restore_mod, "_staging_target", lambda _paths, request_id: tmp_path / "stage")

    calls = []
    class Engine:
        def restore(self, snapshot_id, target, includes, on_message=None):
            calls.append((snapshot_id, Path(target), list(includes)))

    @contextlib.contextmanager
    def fake_credentials(*args, **kwargs):
        yield Engine()
    monkeypatch.setattr(restore_mod, "credentialed_engine", fake_credentials)

    base = {
        "component": "filesystem", "snapshot_id": "abcdef12", "includes": ["/home/user/file"],
        "credentials": {"password": "secret", "password_file": None},
    }
    request = SimpleNamespace(backup_root=str(root), request_id="11111111-1111-4111-8111-111111111111", payload=base)
    staged = restore_mod.handle_restore_staging(request, 1000, {}, None)
    assert staged["target"] == str(tmp_path / "stage")
    assert calls[-1][2] == ["/home/user/file"]

    restore_mod.handle_restore_inplace(request, 1000, {}, None)
    assert calls[-1][1] == Path("/")

def test_packages_install_handler_uses_snapshot_allowlist_and_restore_engine(tmp_path, monkeypatch, unprivileged_privileged_runtime):
    from ubackup.privileged import restore as restore_module

    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root)
    for directory in (
        paths.internal,
        paths.state,
        paths.current,
        paths.cache,
        paths.runtime,
        paths.plans,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(restore_module, "admit_backup_root", lambda *a, **k: _Admission(root))
    monkeypatch.setattr(
        restore_module,
        "load_snapshot_metadata",
        lambda *a, **k: ([
            {"name": "curl", "version": "1", "architecture": "amd64", "installed": True, "manual": True, "selected": True, "origin": "", "manager": "apt", "scope": "system", "channel": "", "reference": "", "classic": False},
            {"name": "git", "version": "1", "architecture": "amd64", "installed": True, "manual": True, "selected": False, "origin": "", "manager": "apt", "scope": "system", "channel": "", "reference": "", "classic": False},
        ], False),
    )

    @contextlib.contextmanager
    def fake_credentials(*args, **kwargs):
        yield object()

    monkeypatch.setattr(restore_module, "credentialed_engine", fake_credentials)
    calls = []

    class FakeRestoreEngine:
        def __init__(self, engine, env, desktop_uid=None):
            self.desktop_uid = desktop_uid

        def restore_packages(self, packages, dry_run=False, progress=None):
            calls.append(([(p.manager.value, p.scope, p.name) for p in packages], dry_run, self.desktop_uid))
            return SimpleNamespace(returncode=0, stdout="ok", stderr="", output_truncated=False)

    monkeypatch.setattr(restore_module, "RestoreEngine", FakeRestoreEngine)
    request = SimpleNamespace(
        backup_root=str(root),
        request_id="11111111-1111-4111-8111-111111111111",
        payload={
            "snapshot_id": "abcdef12",
            "packages": [{"manager": "apt", "scope": "system", "name": "curl"}],
            "simulate": True,
            "credentials": {"password": "secret", "password_file": None},
        },
    )

    result = restore_module.handle_packages_install(request, 1000, {}, None)
    assert result["returncode"] == 0
    assert calls == [([("apt", "system", "curl")], True, 1000)]

    request.payload["packages"] = [{"manager": "apt", "scope": "system", "name": "not-recorded"}]
    with pytest.raises(Exception) as excinfo:
        restore_module.handle_packages_install(request, 1000, {}, None)
    assert getattr(excinfo.value, "code", None) == "package_not_recorded"
