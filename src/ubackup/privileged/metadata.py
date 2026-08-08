from __future__ import annotations

"""Trusted versioned UBackup metadata loading for one repository domain.

The current architecture uses three independent Restic repositories and a
stable metadata path per domain under ``.ubackup/state/<domain>/current``.
There is intentionally no compatibility fallback to the old single-repository
layout: callers are expected to start with a fresh backup root after the
repository split migration.
"""

from typing import Any

from ubackup.models import PackageManager
from ubackup.paths import PrivilegedPaths
from ubackup.restic_engine import ResticError
from ubackup.privileged.runtime import Phase2Error

_ALLOWED_METADATA = frozenset({"manifest.json", "packages.json", "configs.json", "system.json"})


def load_snapshot_metadata(
    engine,
    paths: PrivilegedPaths,
    snapshot_id: str,
    filename: str,
    *,
    expected_uid: int = 0,
) -> tuple[Any, bool]:
    """Load one metadata file from its deterministic domain-specific path."""
    del expected_uid  # Metadata bytes are authenticated by the Restic repository.
    if filename not in _ALLOWED_METADATA:
        raise Phase2Error("invalid_metadata", "metadata filename is not allowed")
    if filename == "packages.json":
        combined: list[Any] = []
        found = False
        for manager in PackageManager:
            target = str(paths.current / f"packages-{manager.value}.json")
            try:
                value = engine.dump_json(snapshot_id, target)
            except ResticError:
                continue
            if not isinstance(value, list):
                raise Phase2Error("invalid_metadata", f"{manager.value} package metadata has an invalid shape")
            combined.extend(value)
            found = True
        if found:
            return combined, False
        # Read compatibility for package snapshots created immediately before
        # manager-specific metadata files were introduced. New snapshots never
        # write this combined file.
        try:
            legacy = engine.dump_json(snapshot_id, str(paths.current / "packages.json"))
        except ResticError:
            legacy = None
        if isinstance(legacy, list):
            return legacy, False
        raise Phase2Error(
            "metadata_not_found",
            f"package metadata was not found in the {paths.repository.name} repository",
        )

    target = str(paths.current / filename)
    try:
        return engine.dump_json(snapshot_id, target), False
    except ResticError as exc:
        raise Phase2Error(
            "metadata_not_found",
            f"snapshot metadata {filename} was not found in the {paths.repository.name} repository",
        ) from exc
