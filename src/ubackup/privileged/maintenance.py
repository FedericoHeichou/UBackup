from __future__ import annotations

"""Destructive repository maintenance available only through the authenticated startup session.

The GUI cannot supply arbitrary Restic argv.  It can request one of the small,
typed actions below; this helper re-validates snapshot identity and repository
state immediately before the destructive Restic command is executed.
"""

from typing import Any, Callable, Mapping

from ubackup.paths import PrivilegedPaths
from ubackup.restic_engine import ResticError
from ubackup.privileged.configure import FilesystemOps, admit_backup_root
from ubackup.privileged.credentials import credentialed_engine
from ubackup.privileged.runtime import Phase2Error, ensure_not_cancelled
from ubackup.privileged.validation import backup_component, exact_fields, snapshot_id, validate_credentials

ACTION_DELETE_LATEST = "delete-latest"
ACTION_CONSOLIDATE_HISTORY = "consolidate-history"
ACTIONS = frozenset({ACTION_DELETE_LATEST, ACTION_CONSOLIDATE_HISTORY})


def validate_maintenance_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    exact_fields(payload, {"action", "component", "snapshot_id", "credentials"})
    action = payload.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        raise Phase2Error("invalid_action", "repository maintenance action is not allowed")
    return {
        "action": action,
        "component": backup_component(payload.get("component")),
        "snapshot_id": snapshot_id(payload.get("snapshot_id")),
        "credentials": validate_credentials(payload.get("credentials")),
    }


def handle_maintenance(
    request,
    uid: int,
    environment: Mapping[str, str],
    ops: FilesystemOps | None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    admission = admit_backup_root(request.backup_root, ops=ops)
    paths = PrivilegedPaths.for_root(admission.root).for_component(request.payload["component"])
    admission.revalidate(ops)
    env = paths.prepare_environment(dict(environment))
    paths.cleanup_stale_request_artifacts(active_request_id=request.request_id)

    try:
        with credentialed_engine(paths, env, request.request_id, request.payload["credentials"], uid) as engine:
            snapshots = engine.snapshots()
            if not snapshots:
                raise Phase2Error("snapshot_not_found", "repository contains no UBackup snapshots")
            latest = snapshots[0]
            requested = request.payload["snapshot_id"]
            if requested != latest.id:
                raise Phase2Error("not_latest_snapshot", "only the latest UBackup snapshot can be modified")
            ensure_not_cancelled()
            if request.payload["action"] == ACTION_DELETE_LATEST:
                engine.forget_snapshots([requested], prune=True, on_message=progress)
                return {"action": ACTION_DELETE_LATEST, "deleted": [requested]}

            # Each backup domain owns an independent repository, so every
            # older snapshot belongs to the same logical history. Consolidation
            # therefore always means retaining latest and forgetting older
            # versions; no cross-component coverage proof is necessary.
            older_ids = [item.id for item in snapshots[1:]]
            if older_ids:
                engine.forget_snapshots(older_ids, prune=True, on_message=progress)
            return {
                "action": ACTION_CONSOLIDATE_HISTORY,
                "kept": requested,
                "deleted": older_ids,
            }
    except ResticError as exc:
        raise Phase2Error("restic_error", str(exc)) from exc
