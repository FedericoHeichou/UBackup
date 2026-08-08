from __future__ import annotations

import contextlib
import os
from types import SimpleNamespace

import pytest

from ubackup.paths import PrivilegedPaths
from ubackup.restic_engine import ResticError
from ubackup.privileged import inspect as privileged_inspect
from ubackup.privileged.metadata import load_snapshot_metadata
from ubackup.privileged.runtime import Phase2Error


class _Admission:
    def __init__(self, root):
        self.root = root
    def revalidate(self, ops=None):
        return None


def _request(root, payload):
    return SimpleNamespace(
        backup_root=str(root),
        request_id="11111111-1111-4111-8111-111111111111",
        payload=payload,
    )


def test_snapshot_directory_privileged_handler_returns_bounded_gui_nodes(tmp_path, monkeypatch, unprivileged_privileged_runtime):
    class Engine:
        def list_directory(self, snapshot_id, directory, limit, offset, probe=False):
            assert snapshot_id == "abcdef12"
            assert directory == "/"
            assert probe is True
            return [
                {"struct_type": "node", "path": "/etc", "name": "etc", "type": "dir", "size": 0},
                {"struct_type": "node", "path": "/home", "name": "home", "type": "dir", "size": 0},
            ]

    @contextlib.contextmanager
    def fake_credentials(*args, **kwargs):
        yield Engine()

    monkeypatch.setattr(privileged_inspect, "admit_backup_root", lambda *a, **k: _Admission(tmp_path))
    monkeypatch.setattr(privileged_inspect, "credentialed_engine", fake_credentials)

    result = privileged_inspect.handle_inspect(
        _request(tmp_path, {
            "kind": "snapshot-directory", "component": "filesystem", "snapshot_id": "abcdef12",
            "directory": "/", "limit": 100, "offset": 0,
            "credentials": {"password": "secret", "password_file": None},
        }), 1000, {}, None,
    )
    assert result == {
        "kind": "snapshot-directory",
        "records": [
            {"path": "/etc", "name": "etc", "type": "dir", "size": 0},
            {"path": "/home", "name": "home", "type": "dir", "size": 0},
        ],
        "next_offset": None,
        "truncated": False,
    }


def test_domain_metadata_load_uses_deterministic_current_path(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path).for_component("configs")
    snapshot_id = "abcdef12"
    manifest = {"schema": 2, "domain": "configs", "components": ["configs"]}

    class Engine:
        def dump_json(self, sid, path):
            assert sid == snapshot_id
            assert path == str(paths.current / "manifest.json")
            return manifest

    value, recovered = load_snapshot_metadata(Engine(), paths, snapshot_id, "manifest.json")
    assert recovered is False
    assert value == manifest


def test_missing_domain_metadata_returns_typed_not_found(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path).for_component("packages")

    class Engine:
        def dump_json(self, sid, path):
            raise ResticError(f'Fatal: cannot dump file: path "{path}" not found in snapshot')

    with pytest.raises(Phase2Error) as exc:
        load_snapshot_metadata(Engine(), paths, "abcdef12", "packages.json")
    assert exc.value.code == "metadata_not_found"
    assert "packages repository" in str(exc.value)


def test_filesystem_cache_handler_reuses_profile_and_detects_identity_change(tmp_path, monkeypatch, unprivileged_privileged_runtime):
    from ubackup.cache import CacheDB
    from ubackup.fs_scan import scan_cache_key

    backup_root = tmp_path / "backup"
    data = tmp_path / "data"
    data.mkdir()
    (data / "payload").write_bytes(b"x" * 19)
    paths = PrivilegedPaths.for_root(backup_root)
    paths.cache.mkdir(parents=True, exist_ok=True)
    info = os.lstat(data)
    key = scan_cache_key(["**/node_modules/**"])
    cache = CacheDB(paths.cache / "filesystem.sqlite3")
    try:
        cache.put_fs(
            str(data), 19, info.st_mtime_ns, info.st_ino, info.st_dev, 1,
            scanned_at=123.0, scan_key=key, total_size=119, total_file_count=2,
        )
    finally:
        cache.close()

    monkeypatch.setattr(privileged_inspect, "admit_backup_root", lambda *a, **k: _Admission(backup_root))
    request = _request(backup_root, {
        "kind": "filesystem-cache", "paths": [str(data)],
        "exclude_patterns": ["**/node_modules/**"],
    })
    result = privileged_inspect.handle_inspect(request, 1000, {}, None)
    assert result["records"] == [{
        "path": str(data), "exists": True, "size": 19, "file_count": 1,
        "scanned_at": 123.0, "cache_stale": False,
        "total_size": 119, "total_file_count": 2,
        "total_cache_stale": False, "identity_stale": False,
        "profile_stale": False, "cache_present": True,
    }]

    # A profile change keeps cached values visible but explicitly stale. It
    # must not turn a cache lookup into an implicit recursive rescan.
    other_request = _request(backup_root, {
        "kind": "filesystem-cache", "paths": [str(data)],
        "exclude_patterns": ["/different/**"],
    })
    other = privileged_inspect.handle_inspect(other_request, 1000, {}, None)["records"][0]
    assert other["size"] == 19
    assert other["total_size"] == 119
    assert other["cache_stale"] is True
    assert other["profile_stale"] is True
    assert other["total_cache_stale"] is False

    # A direct directory identity change deterministically invalidates the row.
    current = os.lstat(data)
    os.utime(data, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000))
    result = privileged_inspect.handle_inspect(request, 1000, {}, None)
    assert result["records"][0]["cache_stale"] is True


def test_filesystem_cache_direct_file_respects_manual_exclusion_profile(
    tmp_path, monkeypatch, unprivileged_privileged_runtime
):
    backup_root = tmp_path / "backup"
    data = tmp_path / "data"
    data.mkdir()
    payload = data / "payload.bin"
    payload.write_bytes(b"x" * 23)

    monkeypatch.setattr(
        privileged_inspect, "admit_backup_root", lambda *a, **k: _Admission(backup_root)
    )
    result = privileged_inspect.handle_inspect(
        _request(backup_root, {
            "kind": "filesystem-cache",
            "paths": [str(payload)],
            "exclude_patterns": [str(payload)],
        }),
        1000,
        {},
        None,
    )

    record = result["records"][0]
    assert record["size"] == 0
    assert record["file_count"] == 0
    assert record["total_size"] == 23
    assert record["total_file_count"] == 1


def test_filesystem_children_keeps_manually_excluded_file_at_zero_size(
    tmp_path, monkeypatch, unprivileged_privileged_runtime
):
    backup_root = tmp_path / "backup"
    data = tmp_path / "data"
    data.mkdir()
    payload = data / "payload.bin"
    payload.write_bytes(b"x" * 29)

    monkeypatch.setattr(
        privileged_inspect, "admit_backup_root", lambda *a, **k: _Admission(backup_root)
    )
    result = privileged_inspect.handle_inspect(
        _request(backup_root, {
            "kind": "filesystem-children",
            "path": str(data),
            "limit": 100,
            "offset": 0,
            "exclude_patterns": [str(payload)],
        }),
        1000,
        {},
        None,
    )

    assert len(result["records"]) == 1
    assert result["records"][0]["path"] == str(payload)
    assert result["records"][0]["size"] == 0


def test_filesystem_children_always_browses_live_and_enriches_only_direct_children_from_cache(
    tmp_path, monkeypatch, unprivileged_privileged_runtime
):
    from ubackup.cache import CacheDB
    from ubackup.fs_scan import SizeScanner

    backup_root = tmp_path / "backup"
    data = tmp_path / "data"
    child = data / "child"
    data.mkdir(mode=0o755)
    child.mkdir(mode=0o755)
    os.chmod(data, 0o755)
    os.chmod(child, 0o755)
    payload = child / "payload.bin"
    payload.write_bytes(b"abc")
    os.chmod(payload, 0o644)

    paths = PrivilegedPaths.for_root(backup_root)
    paths.cache.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.cache, 0o700)
    cache = CacheDB(paths.cache / "filesystem.sqlite3")
    try:
        scanner = SizeScanner(cache, backup_root)
        scanner.scan(data, force=True)
    finally:
        cache.close()

    monkeypatch.setattr(
        privileged_inspect, "admit_backup_root", lambda *a, **k: _Admission(backup_root)
    )

    calls = []
    original_children = privileged_inspect._children

    def counted_live_browse(*args, **kwargs):
        calls.append((args, kwargs))
        return original_children(*args, **kwargs)

    monkeypatch.setattr(privileged_inspect, "_children", counted_live_browse)
    first = privileged_inspect.handle_inspect(
        _request(backup_root, {
            "kind": "filesystem-children", "path": str(data), "limit": 100, "offset": 0,
            "exclude_patterns": [],
        }),
        1000,
        {},
        None,
    )
    assert len(calls) == 1
    assert first["source"] == "filesystem"
    assert [record["path"] for record in first["records"]] == [str(child)]
    assert first["records"][0]["size"] == 3
    assert first["records"][0]["cache_present"] is True

    # A later expansion lists the directory again instead of replaying a
    # persisted dirtree. New direct membership is therefore visible at once.
    newcomer = data / "new.bin"
    newcomer.write_bytes(b"new")
    os.chmod(newcomer, 0o644)
    second = privileged_inspect.handle_inspect(
        _request(backup_root, {
            "kind": "filesystem-children", "path": str(data), "limit": 100, "offset": 0,
            "exclude_patterns": [],
        }),
        1000,
        {},
        None,
    )
    assert len(calls) == 2
    assert {record["path"] for record in second["records"]} == {str(child), str(newcomer)}
    by_path = {record["path"]: record for record in second["records"]}
    assert by_path[str(child)]["size"] == 3
    assert by_path[str(newcomer)]["total_size"] == 3
    assert second["directory_cache"]["cache_stale"] is True
    assert second["directory_cache"]["identity_stale"] is True
