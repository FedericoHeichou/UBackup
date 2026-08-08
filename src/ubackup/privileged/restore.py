from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping

from ..models import PackageManager, PackageRecord
from ..paths import PrivilegedPaths
from ..restic_engine import ResticEngine
from ..restore_engine import PackageCommandError, RestoreEngine
from .configure import FilesystemOps, admit_backup_root
from .credentials import credentialed_engine
from .metadata import load_snapshot_metadata
from .runtime import ChildProcessError, Phase2Error
from .validation import backup_component, bounded_list, exact_fields, include_path, snapshot_id, validate_credentials, package_name


def _includes(payload: Any, *, root: Path, inplace: bool) -> list[str]:
    items = bounded_list(payload, "includes")
    return [include_path(item, backup_root=root, inplace=inplace) for item in items]


def validate_restore_payload(payload: Mapping[str, Any], *, inplace: bool) -> dict[str, Any]:
    exact_fields(payload, {"component", "snapshot_id", "includes", "credentials"})
    # The root is supplied to the operation handler; syntax is checked again
    # there against the admitted root before Restic is invoked.
    sid = snapshot_id(payload["snapshot_id"])
    includes = bounded_list(payload["includes"], "includes")
    if not includes:
        raise Phase2Error("invalid_include", "restore requires explicit includes")
    for item in includes:
        if not isinstance(item, str):
            raise Phase2Error("invalid_include", "includes must contain strings")
        if inplace and item == "/etc":
            raise Phase2Error("invalid_include", "in-place restore of /etc is prohibited")
    return {"component": backup_component(payload["component"], allow_packages=False), "snapshot_id": sid, "includes": includes, "credentials": validate_credentials(payload["credentials"]), "inplace": inplace}


def validate_staging_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = validate_restore_payload(payload, inplace=False)
    value.pop("inplace")
    return value


def validate_inplace_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = validate_restore_payload(payload, inplace=True)
    value.pop("inplace")
    return value


def _package_selector(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise Phase2Error("invalid_package", "package selection must be an object")
    exact_fields(value, {"manager", "scope", "name"})
    manager = value["manager"]
    if manager not in {item.value for item in PackageManager}:
        raise Phase2Error("invalid_package", "package manager is invalid")
    name = value["name"]
    if manager == PackageManager.APT.value:
        package_name(name)
    elif not isinstance(name, str) or not name or len(name) > 256 or not name[0].isalnum():
        raise Phase2Error("invalid_package", "package name is invalid")
    scope = value["scope"]
    if (
        not isinstance(scope, str) or not scope or len(scope) > 128
        or any(not (ch.isalnum() or ch in "._-") for ch in scope)
    ):
        raise Phase2Error("invalid_package", "package scope is invalid")
    return {"manager": manager, "scope": scope, "name": name}


def validate_packages_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    exact_fields(payload, {"snapshot_id", "packages", "simulate", "credentials"})
    simulate = payload["simulate"]
    if not isinstance(simulate, bool):
        raise Phase2Error("invalid_schema", "simulate must be boolean")
    packages = [_package_selector(item) for item in bounded_list(payload["packages"], "packages")]
    return {
        "snapshot_id": snapshot_id(payload["snapshot_id"]),
        "packages": packages,
        "simulate": simulate,
        "credentials": validate_credentials(payload["credentials"]),
    }


def _recorded_package_map(recorded: Any) -> dict[tuple[str, str, str], PackageRecord]:
    if not isinstance(recorded, list):
        raise Phase2Error("invalid_metadata", "snapshot package inventory has an invalid shape")
    allowed: dict[tuple[str, str, str], PackageRecord] = {}
    for item in recorded:
        if not isinstance(item, dict):
            continue
        try:
            record = PackageRecord(**item)
            selector = _package_selector({"manager": record.manager.value, "scope": record.scope, "name": record.name})
        except (TypeError, ValueError, Phase2Error):
            continue
        allowed[(selector["manager"], selector["scope"], selector["name"])] = record
    return allowed


def _paths_environment(admission, environment: Mapping[str, str], ops: FilesystemOps | None, request_id: str, component: str):
    paths = PrivilegedPaths.for_root(admission.root).for_component(component)
    admission.revalidate(ops)
    env = paths.prepare_environment(dict(environment))
    paths.cleanup_stale_request_artifacts(active_request_id=request_id)
    return paths, env


def _staging_target(paths: PrivilegedPaths, request_id: str) -> Path:
    root = paths.restores / "staging"
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        root.mkdir(mode=0o700, parents=False)
        info = os.lstat(root)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise Phase2Error("invalid_staging", "staging root is not privileged")
    os.chmod(root, 0o700, follow_symlinks=False)
    target = root / request_id
    if target.exists() or target.is_symlink():
        raise Phase2Error("staging_exists", "staging request id already exists")
    target.mkdir(mode=0o700)
    os.chmod(target, 0o700, follow_symlinks=False)
    if Path(os.path.realpath(target)) != target or paths.restores not in target.parents:
        raise Phase2Error("invalid_staging", "staging destination escaped restore root")
    return target


def handle_restore_staging(
    request, uid: int, environment: Mapping[str, str], ops: FilesystemOps | None,
    progress: Callable[[dict[str, Any]], None] | None = None,
):
    admission = admit_backup_root(request.backup_root, ops=ops)
    includes = _includes(request.payload["includes"], root=admission.root, inplace=False)
    paths, env = _paths_environment(admission, environment, ops, request.request_id, request.payload["component"])
    admission.revalidate(ops)
    target = _staging_target(paths, request.request_id)
    try:
        with credentialed_engine(paths, env, request.request_id, request.payload["credentials"], uid) as engine:
            engine.restore(request.payload["snapshot_id"], target, includes, on_message=progress)
    except ChildProcessError:
        # Keep cancellation and child deadlines visible to the fixed runtime;
        # it owns the structured response mapping for those outcomes.
        raise
    except Phase2Error as exc:
        if exc.code in {"cancelled", "timeout"}:
            raise
        raise Phase2Error("restore_failed", "staging restore failed") from exc
    except Exception as exc:
        raise Phase2Error("restore_failed", "staging restore failed") from exc
    return {"snapshot_id": request.payload["snapshot_id"], "target": str(target), "includes": includes}


def handle_restore_inplace(
    request, uid: int, environment: Mapping[str, str], ops: FilesystemOps | None,
    progress: Callable[[dict[str, Any]], None] | None = None,
):
    admission = admit_backup_root(request.backup_root, ops=ops)
    includes = _includes(request.payload["includes"], root=admission.root, inplace=True)
    if not includes:
        raise Phase2Error("invalid_include", "in-place restore requires explicit includes")
    paths, env = _paths_environment(admission, environment, ops, request.request_id, request.payload["component"])
    admission.revalidate(ops)
    try:
        with credentialed_engine(paths, env, request.request_id, request.payload["credentials"], uid) as engine:
            engine.restore(request.payload["snapshot_id"], Path("/"), includes, on_message=progress)
    except ChildProcessError:
        raise
    except Phase2Error as exc:
        if exc.code in {"cancelled", "timeout"}:
            raise
        raise Phase2Error("restore_failed", "in-place restore failed") from exc
    except Exception as exc:
        raise Phase2Error("restore_failed", "in-place restore failed") from exc
    return {"snapshot_id": request.payload["snapshot_id"], "target": "/", "includes": includes}


def handle_packages_install(
    request, uid: int, environment: Mapping[str, str], ops: FilesystemOps | None,
    progress: Callable[[dict[str, Any]], None] | None = None,
):
    admission = admit_backup_root(request.backup_root, ops=ops)
    paths, env = _paths_environment(admission, environment, ops, request.request_id, "packages")
    with credentialed_engine(paths, env, request.request_id, request.payload["credentials"], uid) as engine:
        recorded, _recovered = load_snapshot_metadata(
            engine, paths, request.payload["snapshot_id"], "packages.json"
        )
        allowed = _recorded_package_map(recorded)
        requested_keys = [
            (item["manager"], item["scope"], item["name"]) for item in request.payload["packages"]
        ]
        if any(key not in allowed for key in requested_keys):
            raise Phase2Error("package_not_recorded", "package selection is not present in the snapshot plan")
        selected_records = [allowed[key] for key in requested_keys]
        try:
            if progress is not None:
                progress({
                    "current_item": ("Simulating package restore: " if request.payload["simulate"] else "Installing packages: ")
                    + ", ".join(record.name for record in selected_records[:12]),
                    "items_processed": 0,
                })
            result = RestoreEngine(engine, env, desktop_uid=uid).restore_packages(
                selected_records, dry_run=request.payload["simulate"], progress=progress
            )
        except ChildProcessError:
            raise
        except PackageCommandError as exc:
            raise Phase2Error(exc.code, "package manager operation failed") from exc
    return {
        "simulate": request.payload["simulate"],
        "returncode": int(result.returncode),
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
        "output_truncated": bool(getattr(result, "output_truncated", False)),
    }
