from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from ubackup.paths import PrivilegedPaths
from ubackup.restic_engine import ResticEngine


pytestmark = pytest.mark.skipif(shutil.which("restic") is None, reason="restic executable is not installed")


def _engine_for_domain(tmp_path: Path, component: str) -> tuple[PrivilegedPaths, ResticEngine]:
    base = PrivilegedPaths.for_root(tmp_path / "backup")
    paths = base.for_component(component)
    paths.current.mkdir(parents=True, exist_ok=True)
    (paths.cache / "restic").mkdir(parents=True, exist_ok=True)
    paths.runtime.mkdir(parents=True, exist_ok=True)
    paths.password_file.parent.mkdir(parents=True, exist_ok=True)
    if not paths.password_file.exists():
        paths.password_file.write_text("integration-secret\n")
        paths.password_file.chmod(0o600)
    env = os.environ.copy()
    env["HOME"] = str(tmp_path / "home")
    Path(env["HOME"]).mkdir(exist_ok=True)
    return paths, ResticEngine(paths, env)


def _write_domain_metadata(paths: PrivilegedPaths, component: str, *, extra_sources: list[str]) -> dict:
    manifest = {
        "schema": 2,
        "domain": component,
        "components": [component],
        "selected_sources": extra_sources if component == "filesystem" else [],
        "selected_package_count": 1 if component == "packages" else 0,
        "selected_config_count": 1 if component == "configs" else 0,
    }
    paths.manifest_file.write_text(json.dumps(manifest))
    paths.packages_file.write_text(json.dumps([{"name": "example", "selected": True}]) if component == "packages" else "[]")
    paths.configs_file.write_text(json.dumps([{"path": extra_sources[0], "selected": True}]) if component == "configs" and extra_sources else "[]")
    paths.system_file.write_text("{}")
    paths.excludes_file.write_text("")
    metadata = [
        str(paths.manifest_file), str(paths.packages_file), str(paths.configs_file),
        str(paths.system_file), str(paths.excludes_file), str(paths.sources_file),
    ]
    sources = list(extra_sources) + metadata
    paths.sources_file.write_text("\n".join(dict.fromkeys(sources)) + "\n")
    return manifest


def test_real_restic_configs_snapshot_contains_metadata_browses_and_restores(tmp_path):
    """Exercise real Restic for the curated /etc-domain command shape."""
    paths, engine = _engine_for_domain(tmp_path, "configs")
    curated = tmp_path / "curated-config"
    curated.write_text("custom=true\n")
    manifest = _write_domain_metadata(paths, "configs", extra_sources=[str(curated)])

    summary = engine.backup(paths.sources_file, paths.excludes_file, False)
    assert summary.snapshot_id
    snapshot_id = summary.snapshot_id
    located = engine.find_manifest_path(snapshot_id)
    assert located == str(paths.manifest_file)
    assert engine.dump_json(snapshot_id, located) == manifest

    root_nodes = engine.list_directory(snapshot_id, "/", limit=100, offset=0, probe=True)
    assert root_nodes

    restore_target = tmp_path / "restore"
    engine.restore(snapshot_id, restore_target, [str(curated), str(paths.manifest_file)])
    assert (restore_target / str(curated).lstrip("/")).read_text() == "custom=true\n"
    restored_manifest = restore_target / str(paths.manifest_file).lstrip("/")
    assert json.loads(restored_manifest.read_text()) == manifest


def test_real_restic_domain_repositories_have_independent_histories(tmp_path):
    """One domain snapshot must never appear in another domain repository."""
    snapshot_ids: dict[str, str] = {}
    for component in ("filesystem", "configs", "packages"):
        paths, engine = _engine_for_domain(tmp_path, component)
        data = tmp_path / f"{component}-data"
        data.write_text(component)
        extra = [str(data)] if component != "packages" else []
        _write_domain_metadata(paths, component, extra_sources=extra)
        summary = engine.backup(paths.sources_file, paths.excludes_file, False)
        snapshot_ids[component] = summary.snapshot_id
        records = engine.snapshots()
        assert [record.id for record in records] == [summary.snapshot_id]
        assert engine.dump_json(summary.snapshot_id, str(paths.manifest_file))["domain"] == component

    assert len(set(snapshot_ids.values())) == 3
    base = PrivilegedPaths.for_root(tmp_path / "backup")
    assert len({base.for_component(c).repository for c in snapshot_ids}) == 3
