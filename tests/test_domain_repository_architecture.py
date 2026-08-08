from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from ubackup.models import DryRunSummary
from ubackup.restic_engine import ResticError
from ubackup.privileged.runtime import Phase2Error
from ubackup.paths import PrivilegedPaths
from ubackup.privileged import backup as backup_mod
from ubackup.privileged import inspect as inspect_mod
from ubackup.privileged.configure import ConfigureError
from ubackup.privileged.startup import _repository_initialized


class _Admission:
    def __init__(self, root: Path): self.root = root
    def revalidate(self, ops=None): return None


@pytest.mark.parametrize("component", ["filesystem", "configs", "packages"])
def test_backup_handler_routes_each_domain_to_its_repository(
    tmp_path, monkeypatch, unprivileged_privileged_runtime, component
):
    root = tmp_path / "backup"
    captured = []
    monkeypatch.setattr(backup_mod, "admit_backup_root", lambda *a, **k: _Admission(root))
    monkeypatch.setattr(backup_mod, "_merge_discovery", lambda policy, env, uid, progress=None: dict(policy))
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})

    @contextlib.contextmanager
    def no_lock(_paths): yield
    monkeypatch.setattr(backup_mod, "_backup_lock", no_lock)

    class Engine:
        def backup(self, sources_file, excludes_file, dry_run, on_message=None):
            return DryRunSummary(snapshot_id="abcdef12", total_bytes_processed=1, data_added=1, data_added_packed=1)

    @contextlib.contextmanager
    def credentials(paths, *args, **kwargs):
        captured.append(paths)
        yield Engine()
    monkeypatch.setattr(backup_mod, "credentialed_engine", credentials)

    payload = {
        "sources": [], "source_exclusions": [], "exclude_rules": [], "packages": [], "configs": [],
        "components": [component], "dry_run": True,
        "credentials": {"password": "secret", "password_file": None},
    }
    request = SimpleNamespace(
        backup_root=str(root), request_id="11111111-1111-4111-8111-111111111111", payload=payload,
    )
    result = backup_mod.handle_backup(request, 1000, {}, None)
    assert result["receipt"]["snapshot_id"] == "abcdef12"
    assert captured[0].repository == root / "repositories" / component
    assert captured[0].current == root / ".ubackup" / "state" / component / "current"


def test_backup_handler_surfaces_restic_failure_as_structured_error(
    tmp_path, monkeypatch, unprivileged_privileged_runtime
):
    root = tmp_path / "backup"
    monkeypatch.setattr(backup_mod, "admit_backup_root", lambda *a, **k: _Admission(root))
    monkeypatch.setattr(backup_mod, "_merge_discovery", lambda policy, env, uid, progress=None: dict(policy))
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})

    @contextlib.contextmanager
    def no_lock(_paths):
        yield
    monkeypatch.setattr(backup_mod, "_backup_lock", no_lock)

    class Engine:
        def backup(self, sources_file, excludes_file, dry_run, on_message=None):
            raise ResticError("Restic archival for /home/user/private: permission denied")

    @contextlib.contextmanager
    def credentials(*args, **kwargs):
        yield Engine()
    monkeypatch.setattr(backup_mod, "credentialed_engine", credentials)

    request = SimpleNamespace(
        backup_root=str(root), request_id="11111111-1111-4111-8111-111111111111",
        payload={
            "sources": [], "source_exclusions": [], "exclude_rules": [], "packages": [], "configs": [],
            "components": ["filesystem"], "dry_run": False,
            "credentials": {"password": "secret", "password_file": None},
        },
    )
    with pytest.raises(Phase2Error) as exc:
        backup_mod.handle_backup(request, 1000, {}, None)
    assert exc.value.code == "restic_error"
    assert "permission denied" in exc.value.message



@pytest.mark.parametrize(
    ("component", "filename", "record_factory"),
    [
        ("packages", "packages.json", lambda i: {"name": f"pkg-{i}"}),
        ("configs", "configs.json", lambda i: {"path": f"/etc/example/{i}"}),
    ],
)
def test_snapshot_metadata_list_is_paged_inside_privileged_helper(
    tmp_path, monkeypatch, unprivileged_privileged_runtime, component, filename, record_factory
):
    root = tmp_path / "backup"
    values = [record_factory(i) for i in range(1200)]
    class Engine:
        def dump_json(self, snapshot_id, path):
            if component == "packages":
                if path.endswith("/.ubackup/state/packages/current/packages-apt.json"):
                    return values
                if path.endswith("/.ubackup/state/packages/current/packages-snap.json"):
                    return []
                if path.endswith("/.ubackup/state/packages/current/packages-flatpak.json"):
                    return []
                raise AssertionError(path)
            assert path.endswith(f"/.ubackup/state/{component}/current/{filename}")
            return values
    @contextlib.contextmanager
    def credentials(*args, **kwargs): yield Engine()
    monkeypatch.setattr(inspect_mod, "admit_backup_root", lambda *a, **k: _Admission(root))
    monkeypatch.setattr(inspect_mod, "credentialed_engine", credentials)

    def call(offset):
        request = SimpleNamespace(
            backup_root=str(root), request_id="11111111-1111-4111-8111-111111111111",
            payload={
                "kind": "metadata", "component": component, "snapshot_id": "abcdef12",
                "filename": filename, "limit": 500, "offset": offset,
                "credentials": {"password": "secret", "password_file": None},
            },
        )
        return inspect_mod.handle_inspect(request, 1000, {}, None)

    first = call(0); second = call(first["next_offset"]); third = call(second["next_offset"])
    assert [len(first["value"]), len(second["value"]), len(third["value"])] == [500, 500, 200]
    assert first["truncated"] is True and second["truncated"] is True and third["truncated"] is False
    assert third["next_offset"] is None


def test_existing_any_domain_repository_avoids_new_repository_confirmation(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path)
    package_config = paths.for_component("packages").repository / "config"
    package_config.parent.mkdir(parents=True)
    package_config.write_text("restic-config")
    package_config.chmod(0o644)
    assert _repository_initialized(paths, expected_uid=package_config.stat().st_uid) is True


def test_legacy_single_repository_layout_is_rejected_explicitly(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path)
    legacy = paths.root / "repository"
    legacy.mkdir(parents=True)
    with pytest.raises(ConfigureError) as exc:
        _repository_initialized(paths, expected_uid=legacy.stat().st_uid)
    assert exc.value.code == "legacy_repository_layout"


def test_snapshot_stats_cache_is_namespaced_by_repository_domain(tmp_path):
    from ubackup.cache import CacheDB

    cache = CacheDB(tmp_path / "cache.sqlite3")
    try:
        cache.put_snapshot_stats("same-id", {"total_bytes_processed": 10}, "filesystem")
        cache.put_snapshot_stats("same-id", {"total_bytes_processed": 20}, "configs")
        assert cache.get_snapshot_stats("same-id", "filesystem")["total_bytes_processed"] == 10
        assert cache.get_snapshot_stats("same-id", "configs")["total_bytes_processed"] == 20
        assert cache.get_snapshot_stats("same-id", "packages") is None
    finally:
        cache.close()
