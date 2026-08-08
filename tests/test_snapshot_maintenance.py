from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from ubackup.models import SnapshotRecord
from ubackup.restic_engine import ResticEngine
from ubackup.privileged.maintenance import (
    ACTION_CONSOLIDATE_HISTORY,
    ACTION_DELETE_LATEST,
    handle_maintenance,
)
from ubackup.privileged.runtime import Phase2Error


def _record(snapshot_id: str, *, paths=None, time="2026-08-08T00:00:00Z") -> SnapshotRecord:
    return SnapshotRecord(
        id=snapshot_id,
        time=time,
        hostname="host",
        paths=list(paths or []),
        tags=["ubackup"],
        parent="",
    )


def _engine(tmp_path: Path) -> ResticEngine:
    paths = SimpleNamespace(
        repository=tmp_path / "repository",
        password_file=tmp_path / "password",
        cache=tmp_path / "cache",
    )
    return ResticEngine(paths, {})


def test_manifest_locator_uses_current_domain_metadata_source(tmp_path):
    engine = _engine(tmp_path)
    sid = "a" * 64
    manifest = "/backup/.ubackup/state/configs/current/manifest.json"
    engine.snapshots = lambda *args, **kwargs: [_record(sid, paths=[manifest])]  # type: ignore[method-assign]

    def forbidden(*args, **kwargs):
        raise AssertionError("recursive restic ls should not be needed")

    engine._stream_process = forbidden  # type: ignore[method-assign]
    assert engine.find_manifest_path(sid) == manifest


def test_manifest_locator_derives_current_domain_manifest_from_sibling_metadata(tmp_path):
    engine = _engine(tmp_path)
    sid = "9" * 64
    sibling = "/backup/.ubackup/state/packages/current/packages.json"
    engine.snapshots = lambda *args, **kwargs: [_record(sid, paths=[sibling])]  # type: ignore[method-assign]
    engine._stream_process = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("ls fallback not expected"))  # type: ignore[method-assign]
    assert engine.find_manifest_path(sid) == "/backup/.ubackup/state/packages/current/manifest.json"


def test_manifest_locator_does_not_accept_legacy_plan_layout(tmp_path):
    engine = _engine(tmp_path)
    sid = "8" * 64
    legacy = "/backup/.ubackup/plans/request/manifest.json"
    engine.snapshots = lambda *args, **kwargs: [_record(sid, paths=[legacy])]  # type: ignore[method-assign]
    engine._stream_process = lambda *args, **kwargs: (0, "")  # type: ignore[method-assign]
    assert engine.find_manifest_path(sid) is None


def test_snapshot_root_listing_uses_bounded_root_filter_with_flags_first(tmp_path):
    engine = _engine(tmp_path)
    sid = "b" * 64
    calls = []

    def stream(cmd, env, callback, *, timeout):
        calls.append(cmd)
        return 0, ""

    engine._stream_process = stream  # type: ignore[method-assign]
    assert engine.list_directory(sid, "/", limit=10) == []
    assert calls
    ls_index = calls[0].index("ls")
    assert calls[0][ls_index + 1 :] == ["--json", sid, "/"]


def test_delete_latest_is_rechecked_inside_privileged_handler(monkeypatch, tmp_path):
    latest = _record("e" * 64)
    older = _record("f" * 64, time="2026-08-07T00:00:00Z")
    forgotten = []

    class Admission:
        root = tmp_path / "backup"
        def revalidate(self, ops=None):
            return None

    class Paths:
        def for_component(self, component):
            assert component == "configs"
            return self
        def prepare_environment(self, env):
            return env
        def cleanup_stale_request_artifacts(self, **kwargs):
            return []

    class Engine:
        def snapshots(self):
            return [latest, older]
        def forget_snapshots(self, ids, **kwargs):
            forgotten.extend(ids)

    @contextlib.contextmanager
    def credentials(*args, **kwargs):
        yield Engine()

    import ubackup.privileged.maintenance as module
    monkeypatch.setattr(module, "admit_backup_root", lambda *args, **kwargs: Admission())
    monkeypatch.setattr(module.PrivilegedPaths, "for_root", classmethod(lambda cls, root: Paths()))
    monkeypatch.setattr(module, "credentialed_engine", credentials)

    request = SimpleNamespace(
        backup_root=str(Admission.root),
        request_id="11111111-1111-1111-1111-111111111111",
        payload={"action": ACTION_DELETE_LATEST, "component": "configs", "snapshot_id": older.id, "credentials": {}},
    )
    with pytest.raises(Phase2Error) as exc:
        handle_maintenance(request, 1000, {}, None)
    assert exc.value.code == "not_latest_snapshot"
    assert forgotten == []

    request.payload["snapshot_id"] = latest.id
    result = handle_maintenance(request, 1000, {}, None)
    assert result["deleted"] == [latest.id]
    assert forgotten == [latest.id]


def test_consolidate_history_forgets_all_older_snapshots_in_same_domain(monkeypatch, tmp_path):
    latest = _record("a" * 64)
    older1 = _record("b" * 64, time="2026-08-07T00:00:00Z")
    older2 = _record("c" * 64, time="2026-08-06T00:00:00Z")
    calls = []

    class Admission:
        root = tmp_path / "backup"
        def revalidate(self, ops=None): return None
    class Paths:
        def for_component(self, component):
            assert component == "packages"
            return self
        def prepare_environment(self, env): return env
        def cleanup_stale_request_artifacts(self, **kwargs): return []
    class Engine:
        def snapshots(self): return [latest, older1, older2]
        def forget_snapshots(self, ids, **kwargs): calls.append((list(ids), kwargs))
    @contextlib.contextmanager
    def credentials(*args, **kwargs): yield Engine()

    import ubackup.privileged.maintenance as module
    monkeypatch.setattr(module, "admit_backup_root", lambda *args, **kwargs: Admission())
    monkeypatch.setattr(module.PrivilegedPaths, "for_root", classmethod(lambda cls, root: Paths()))
    monkeypatch.setattr(module, "credentialed_engine", credentials)

    request = SimpleNamespace(
        backup_root=str(Admission.root), request_id="11111111-1111-1111-1111-111111111111",
        payload={"action": ACTION_CONSOLIDATE_HISTORY, "component": "packages", "snapshot_id": latest.id, "credentials": {}},
    )
    result = handle_maintenance(request, 1000, {}, None)
    assert result == {"action": ACTION_CONSOLIDATE_HISTORY, "kept": latest.id, "deleted": [older1.id, older2.id]}
    assert calls == [([older1.id, older2.id], {"prune": True, "on_message": None})]
