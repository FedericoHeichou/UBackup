from __future__ import annotations

import os
import stat
import time
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

if __name__ == "__main__" and __package__ in {None, ""}:
    sys.path.insert(0, "/usr/lib/ubackup")

from ubackup.cache import CacheDB
from ubackup.fs_scan import SizeScanner, scan_cache_key
from ubackup.models import BackupComponent, SnapshotRecord
from ubackup.paths import PrivilegedPaths
from ubackup.restic_engine import MAX_DIRECTORY_NODES, ResticEngine, ResticError
from ubackup.system_scan import cached_config_inventory, cached_package_inventory
from ubackup.privileged.configure import FilesystemOps, admit_backup_root
from ubackup.privileged.credentials import credentialed_engine
from ubackup.privileged.metadata import load_snapshot_metadata
from ubackup.privileged.runtime import (
    Phase2Error,
    ensure_not_cancelled,
    handle_fixed_request,
    run_fixed_helper,
)
from ubackup.privileged.validation import absolute_path, backup_component, exact_fields, snapshot_id, validate_credentials

KIND_CONFIGS = "config-inventory"
KIND_PACKAGES = "package-inventory"
KIND_SNAPSHOTS = "snapshots"
KIND_STATS = "snapshot-stats"
KIND_DIRECTORY = "snapshot-directory"
KIND_METADATA = "metadata"
KIND_FS_CHILDREN = "filesystem-children"
KIND_FS_SIZE = "filesystem-size"
KIND_FS_CACHE = "filesystem-cache"
KIND_STAGING_CHILDREN = "staging-children"
KIND_REPOSITORY_SIZE = "repository-size"
MAX_INSPECT_ITEMS = 500
MAX_INSPECT_OFFSET = 1_000_000
MAX_FS_CACHE_PATHS = 500
MAX_FS_CHILDREN = MAX_DIRECTORY_NODES


def _snapshot_node(item: Any) -> dict[str, Any]:
    """Return the small, validated snapshot node shape exposed to the GUI."""
    if not isinstance(item, Mapping):
        raise Phase2Error("invalid_snapshot_node", "Restic snapshot node has an invalid shape")
    path = item.get("path")
    kind = item.get("type")
    if not isinstance(path, str) or not path.startswith("/") or len(path.encode("utf-8", "strict")) > 8192:
        raise Phase2Error("invalid_snapshot_node", "Restic snapshot node path is invalid")
    if not isinstance(kind, str) or not kind or len(kind) > 32:
        raise Phase2Error("invalid_snapshot_node", "Restic snapshot node type is invalid")
    raw_size = item.get("size", 0)
    if raw_size is None:
        raw_size = 0
    if isinstance(raw_size, bool) or not isinstance(raw_size, int) or raw_size < 0:
        raise Phase2Error("invalid_snapshot_node", "Restic snapshot node size is invalid")
    name = item.get("name")
    if not isinstance(name, str) or not name:
        name = PurePosixPath(path).name or "/"
    return {"path": path, "name": name, "type": kind, "size": raw_size}


def _page(value: Any, name: str, maximum: int) -> int:
    minimum = 1 if name == "limit" else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise Phase2Error("invalid_schema", f"{name} is out of bounds")
    return value


def _page_window(limit: int, offset: int) -> tuple[int, int]:
    if offset + limit > MAX_DIRECTORY_NODES:
        raise Phase2Error("invalid_schema", "pagination window exceeds the directory limit")
    return limit, offset




def _scan_exclude_patterns(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 512:
        raise Phase2Error("invalid_schema", "exclude_patterns must be a bounded list")
    result: list[str] = []
    for pattern in value:
        if not isinstance(pattern, str) or not pattern or len(pattern.encode("utf-8", "strict")) > 4096:
            raise Phase2Error("invalid_schema", "exclude pattern is invalid")
        if any(ord(char) < 0x20 or ord(char) == 0x7f for char in pattern):
            raise Phase2Error("invalid_schema", "exclude pattern contains control characters")
        result.append(pattern)
    return result


def _cache_paths(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_FS_CACHE_PATHS:
        raise Phase2Error("invalid_schema", "paths must be a bounded list")
    result: list[str] = []
    for raw in value:
        result.append(absolute_path(raw, "path"))
    return result

def _inspect_credentials(payload: Mapping[str, Any]) -> dict[str, str | None]:
    """Keep old callers parseable; handlers still reject absent credentials."""
    if "credentials" not in payload:
        return {"password": None, "password_file": None}
    return validate_credentials(payload["credentials"])


def _staging_relative(value: Any) -> str:
    if not isinstance(value, str):
        raise Phase2Error("invalid_path", "staging path is invalid")
    try:
        if len(value.encode("utf-8", "strict")) > 4096:
            raise Phase2Error("invalid_path", "staging path is invalid")
    except UnicodeEncodeError as exc:
        raise Phase2Error("invalid_path", "staging path is invalid") from exc
    if value in {"", "."}:
        return ""
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise Phase2Error("invalid_path", "staging path must be relative and normalized")
    if pure.as_posix() != value:
        raise Phase2Error("invalid_path", "staging path must be relative and normalized")
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise Phase2Error("invalid_path", "staging path contains forbidden control characters")
    return pure.as_posix()


def _staging_id(value: Any) -> str:
    if not isinstance(value, str):
        raise Phase2Error("invalid_path", "staging id is invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise Phase2Error("invalid_path", "staging id is invalid") from exc
    if str(parsed) != value:
        raise Phase2Error("invalid_path", "staging id is invalid")
    return value


def _staging_path(paths: PrivilegedPaths, staging_id: str, relative: str) -> Path:
    try:
        parsed = uuid.UUID(staging_id)
    except (ValueError, AttributeError, TypeError) as exc:
        raise Phase2Error("invalid_path", "staging id is invalid") from exc
    if str(parsed) != staging_id:
        raise Phase2Error("invalid_path", "staging id is invalid")
    target = paths.restores / "staging" / staging_id
    try:
        info = os.lstat(target)
    except OSError as exc:
        raise Phase2Error("invalid_path", "staging target is not available") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Phase2Error("invalid_path", "staging target is not privileged")
    candidate = target / relative if relative else target
    resolved_target = Path(os.path.realpath(target))
    resolved = Path(os.path.realpath(candidate))
    if resolved != candidate or resolved != resolved_target and resolved_target not in resolved.parents:
        raise Phase2Error("invalid_path", "staging path escaped its target")
    return candidate


def validate_inspect_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    kind = payload.get("kind")
    if kind == KIND_REPOSITORY_SIZE:
        exact_fields(payload, {"kind"})
        return {"kind": kind}
    if kind in {KIND_CONFIGS, KIND_PACKAGES}:
        allowed = {"kind", "limit", "offset", "force"}
        unexpected = set(payload) - allowed
        if unexpected:
            raise Phase2Error("invalid_schema", "inspect payload contains unexpected fields")
        limit, offset = _page_window(
            _page(payload.get("limit", MAX_INSPECT_ITEMS), "limit", MAX_INSPECT_ITEMS),
            _page(payload.get("offset", 0), "offset", MAX_INSPECT_OFFSET),
        )
        force = payload.get("force", False)
        if not isinstance(force, bool):
            raise Phase2Error("invalid_schema", "force must be boolean")
        return {
            "kind": kind,
            "limit": limit,
            "offset": offset,
            "force": force,
        }
    if kind == KIND_SNAPSHOTS:
        exact_fields(payload, {"kind", "component", "limit", "offset", "credentials"} if "credentials" in payload else {"kind", "component", "limit", "offset"})
        limit, offset = _page_window(_page(payload["limit"], "limit", MAX_INSPECT_ITEMS), _page(payload["offset"], "offset", MAX_INSPECT_OFFSET))
        return {"kind": kind, "component": backup_component(payload["component"]), "limit": limit, "offset": offset, "credentials": _inspect_credentials(payload)}
    if kind == KIND_STATS:
        exact_fields(payload, {"kind", "component", "snapshot_id", "credentials"} if "credentials" in payload else {"kind", "component", "snapshot_id"})
        return {"kind": kind, "component": backup_component(payload["component"]), "snapshot_id": snapshot_id(payload["snapshot_id"]), "credentials": _inspect_credentials(payload)}
    if kind == KIND_DIRECTORY:
        exact_fields(payload, {"kind", "component", "snapshot_id", "directory", "limit", "offset", "credentials"} if "credentials" in payload else {"kind", "component", "snapshot_id", "directory", "limit", "offset"})
        limit, offset = _page_window(_page(payload["limit"], "limit", MAX_INSPECT_ITEMS), _page(payload["offset"], "offset", MAX_INSPECT_OFFSET))
        return {
            "kind": kind,
            "component": backup_component(payload["component"]),
            "snapshot_id": snapshot_id(payload["snapshot_id"]),
            "directory": absolute_path(payload["directory"], "directory"),
            "limit": limit,
            "offset": offset,
            "credentials": _inspect_credentials(payload),
        }
    if kind == KIND_METADATA:
        allowed = {"kind", "component", "snapshot_id", "filename", "limit", "offset"}
        if "credentials" in payload:
            allowed.add("credentials")
        unexpected = set(payload) - allowed
        if unexpected:
            raise Phase2Error("invalid_schema", "metadata inspect payload contains unexpected fields")
        required = {"kind", "component", "snapshot_id", "filename"}
        if not required.issubset(payload):
            raise Phase2Error("invalid_schema", "metadata inspect payload is incomplete")
        filename = payload["filename"]
        if filename not in {"manifest.json", "packages.json", "configs.json", "system.json"}:
            raise Phase2Error("invalid_metadata", "metadata filename is not allowed")
        limit, offset = _page_window(
            _page(payload.get("limit", MAX_INSPECT_ITEMS), "limit", MAX_INSPECT_ITEMS),
            _page(payload.get("offset", 0), "offset", MAX_INSPECT_OFFSET),
        )
        return {
            "kind": kind, "component": backup_component(payload["component"]),
            "snapshot_id": snapshot_id(payload["snapshot_id"]), "filename": filename,
            "limit": limit, "offset": offset, "credentials": _inspect_credentials(payload),
        }
    if kind == KIND_FS_CHILDREN:
        allowed = {"kind", "path", "limit", "offset", "exclude_patterns"}
        unexpected = set(payload) - allowed
        if unexpected:
            raise Phase2Error("invalid_schema", "filesystem-children payload contains unexpected fields")
        limit, offset = _page_window(
            _page(payload.get("limit", MAX_FS_CHILDREN), "limit", MAX_FS_CHILDREN),
            _page(payload.get("offset", 0), "offset", MAX_INSPECT_OFFSET),
        )
        return {
            "kind": kind,
            "path": absolute_path(payload["path"], "path"),
            "limit": limit,
            "offset": offset,
            "exclude_patterns": _scan_exclude_patterns(payload.get("exclude_patterns")),
        }
    if kind == KIND_FS_SIZE:
        unexpected = set(payload) - {"kind", "path", "exclude_patterns", "force"}
        if unexpected:
            raise Phase2Error("invalid_schema", "filesystem-size payload contains unexpected fields")
        return {
            "kind": kind,
            "path": absolute_path(payload["path"], "path"),
            "exclude_patterns": _scan_exclude_patterns(payload.get("exclude_patterns")),
            "force": bool(payload.get("force", False)),
        }
    if kind == KIND_FS_CACHE:
        unexpected = set(payload) - {"kind", "paths", "exclude_patterns"}
        if unexpected:
            raise Phase2Error("invalid_schema", "filesystem-cache payload contains unexpected fields")
        return {
            "kind": kind,
            "paths": _cache_paths(payload.get("paths", [])),
            "exclude_patterns": _scan_exclude_patterns(payload.get("exclude_patterns")),
        }
    if kind == KIND_STAGING_CHILDREN:
        exact_fields(payload, {"kind", "staging_id", "path", "limit", "offset"})
        limit, offset = _page_window(_page(payload["limit"], "limit", MAX_INSPECT_ITEMS), _page(payload["offset"], "offset", MAX_INSPECT_OFFSET))
        return {
            "kind": kind,
            "staging_id": _staging_id(payload["staging_id"]),
            "path": _staging_relative(payload["path"]),
            "limit": limit,
            "offset": offset,
        }
    raise Phase2Error("unknown_inspect_kind", "inspect kind is not allowed")


from ubackup.privileged.filesystem_navigation import (
    protected_path as _protected_path,
    children as _navigation_children,
)


def _children(path: Path, limit: int, offset: int, *, probe: bool = False) -> list[dict[str, Any]]:
    """Inspection wrapper with a monkeypatchable/runtime cancellation hook."""
    return _navigation_children(
        path, limit, offset, probe=probe, checkpoint=ensure_not_cancelled
    )


def enrich_filesystem_cache(
    records: list[dict[str, Any]], cache: CacheDB, scan_key: str | None = None,
    *, skip_path: Callable[[str], bool] | None = None,
) -> list[dict[str, Any]]:
    """Attach per-path cached aggregates to one live directory listing.

    Navigation is always a one-level live ``scandir``. SQLite is queried only
    for the paths returned by that listing, in bounded bulk SELECTs; no cached
    dirtree is materialized. A cache row remains displayable when filesystem
    identity or the exclusion profile changed, but is marked stale so the user
    can choose ``Recalculate``. Direct non-directory entries are cheap to size
    from lstat and are persisted immediately when no cache row exists.
    """
    paths = [str(record.get("path", "")) for record in records if record.get("path")]
    cached_rows = cache.get_fs_many(paths)
    now = time.time()
    direct_rows: list[dict[str, Any]] = []

    for record in records:
        path = str(record.get("path", ""))
        if not path:
            continue
        cached = cached_rows.get(path)
        if cached is not None and cached.get("total_size") is not None:
            identity_stale = (
                int(cached.get("mtime_ns", -1)) != int(record.get("mtime_ns", -2))
                or int(cached.get("inode", -1)) != int(record.get("inode", -2))
                or int(cached.get("dev", -1)) != int(record.get("dev", -2))
            )
            profile_stale = scan_key is not None and str(cached.get("scan_key", "") or "") != str(scan_key)
            record.update({
                "size": int(cached.get("size", 0) or 0),
                "cached_size": int(cached.get("size", 0) or 0),
                "file_count": int(cached.get("file_count", 0) or 0),
                "total_size": int(cached.get("total_size", 0) or 0),
                "total_file_count": int(cached.get("total_file_count", 0) or 0),
                "scanned_at": float(cached.get("scanned_at", 0.0) or 0.0),
                "cache_stale": bool(identity_stale or profile_stale),
                "total_cache_stale": bool(identity_stale),
                "identity_stale": bool(identity_stale),
                "profile_stale": bool(profile_stale),
                "cache_present": True,
            })
            continue

        record["cache_present"] = False
        is_dir = record.get("type") in {"dir", "blocked-dir"}
        if is_dir:
            continue
        total_size = max(0, int(record.get("size", 0) or 0))
        excluded = bool(skip_path(path)) if skip_path is not None else False
        effective_size = 0 if excluded else total_size
        total_count = 1
        effective_count = 0 if excluded else 1
        direct_rows.append({
            "path": path, "size": effective_size, "total_size": total_size,
            "mtime_ns": int(record.get("mtime_ns", 0) or 0),
            "inode": int(record.get("inode", 0) or 0), "dev": int(record.get("dev", 0) or 0),
            "file_count": effective_count, "total_file_count": total_count,
            "scanned_at": now, "scan_key": str(scan_key or ""),
        })
        record.update({
            "size": effective_size, "file_count": effective_count,
            "total_size": total_size, "total_file_count": total_count,
            "scanned_at": now, "cache_stale": False, "identity_stale": False,
            "profile_stale": False, "total_cache_stale": False,
            "cache_present": True, "direct": True,
        })

    if direct_rows:
        cache.put_fs_many(direct_rows)
    return records


def _repository_tree_size(root: Path, progress: Callable[[dict[str, Any]], None] | None = None) -> tuple[int, int]:
    total = 0
    count = 0
    try:
        iterator = os.walk(root, topdown=True, followlinks=False)
        for directory, dirs, files in iterator:
            ensure_not_cancelled()
            # Refuse symlinked directories even inside the root-owned repository.
            safe_dirs = []
            for name in dirs:
                candidate = Path(directory) / name
                try:
                    if not stat.S_ISLNK(os.lstat(candidate).st_mode):
                        safe_dirs.append(name)
                except OSError:
                    continue
            dirs[:] = safe_dirs
            for name in files:
                candidate = Path(directory) / name
                try:
                    info = os.lstat(candidate)
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
                    count += 1
                    if count % 1024 == 0:
                        ensure_not_cancelled()
                        if progress is not None:
                            progress({"current_item": str(candidate), "items_processed": count, "bytes_done": total})
    except FileNotFoundError:
        return 0, 0
    except OSError as exc:
        raise Phase2Error("filesystem_error", "repository size cannot be read") from exc
    return total, count


def handle_inspect(
    request, uid: int, environment: Mapping[str, str], ops: FilesystemOps | None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any] | list[Any]:
    admission = admit_backup_root(request.backup_root, ops=ops)
    payload = request.payload
    kind = payload["kind"]
    protected_path = None
    if kind in {KIND_FS_CHILDREN, KIND_FS_SIZE}:
        protected_path = _protected_path(payload["path"], admission.root)
    paths = PrivilegedPaths.for_root(admission.root)
    admission.revalidate(ops)
    env = paths.prepare_environment(dict(environment))
    paths.cleanup_stale_request_artifacts(active_request_id=request.request_id)
    if kind == KIND_CONFIGS:
        inventory_cache = CacheDB(paths.cache / "system-inventory.sqlite3")
        try:
            records = cached_config_inventory(
                inventory_cache, env, bool(payload.get("force", False)),
                progress=(lambda text: progress({"current_item": text}) if progress is not None else None),
                checkpoint=ensure_not_cancelled,
            )
        finally:
            inventory_cache.close()
        page = records[payload["offset"]:payload["offset"] + payload["limit"] + 1]
        truncated = len(page) > payload["limit"]
        page = page[:payload["limit"]]
        return {"kind": kind, "records": page, "next_offset": payload["offset"] + len(page) if truncated else None, "truncated": truncated}
    if kind == KIND_PACKAGES:
        if progress is not None:
            progress({"current_item": "Reading APT, Snap and Flatpak package inventories…"})
        inventory_cache = CacheDB(paths.cache / "system-inventory.sqlite3")
        try:
            records = cached_package_inventory(
                inventory_cache, env, uid, bool(payload.get("force", False))
            )
        finally:
            inventory_cache.close()
        page = records[payload["offset"]:payload["offset"] + payload["limit"] + 1]
        truncated = len(page) > payload["limit"]
        page = page[:payload["limit"]]
        return {"kind": kind, "records": page, "next_offset": payload["offset"] + len(page) if truncated else None, "truncated": truncated}
    if kind == KIND_REPOSITORY_SIZE:
        total_size = 0
        total_count = 0
        by_component: dict[str, dict[str, int]] = {}
        for component in (BackupComponent.FILESYSTEM.value, BackupComponent.CONFIGS.value, BackupComponent.PACKAGES.value):
            component_paths = paths.for_component(component)
            size, count = _repository_tree_size(component_paths.repository, progress)
            by_component[component] = {"size": size, "file_count": count}
            total_size += size
            total_count += count
        return {"kind": kind, "size": total_size, "file_count": total_count, "by_component": by_component}
    if kind == KIND_STAGING_CHILDREN:
        path = _staging_path(paths, payload["staging_id"], payload["path"])
        records = _children(path, payload["limit"], payload["offset"], probe=True)
        truncated = len(records) > payload["limit"]
        records = records[:payload["limit"]]
        return {"kind": kind, "path": str(path), "records": records, "next_offset": payload["offset"] + len(records) if truncated else None, "truncated": truncated}
    if kind == KIND_FS_CACHE:
        cache = CacheDB(paths.cache / "filesystem.sqlite3")
        try:
            patterns = payload.get("exclude_patterns", [])
            scanner = SizeScanner(cache, admission.root, patterns)
            requested: list[tuple[str, Path]] = []
            for raw in payload.get("paths", []):
                ensure_not_cancelled()
                requested.append((str(raw), _protected_path(raw, admission.root)))
            cached_rows = cache.get_fs_many(str(path) for _raw, path in requested)
            records: list[dict[str, Any]] = []
            direct_rows: list[dict[str, Any]] = []
            now = time.time()
            for _raw, path in requested:
                cached = cached_rows.get(str(path))
                try:
                    info = os.lstat(path)
                except OSError:
                    record: dict[str, Any] = {"path": str(path), "exists": False}
                    if cached is not None:
                        profile_stale = str(cached.get("scan_key", "") or "") != scanner.scan_key
                        record.update({
                            "size": int(cached.get("size", 0) or 0),
                            "file_count": int(cached.get("file_count", 0) or 0),
                            "total_size": int(cached.get("total_size", 0) or 0),
                            "total_file_count": int(cached.get("total_file_count", 0) or 0),
                            "scanned_at": float(cached.get("scanned_at", 0.0) or 0.0),
                            "cache_stale": True, "identity_stale": True,
                            "total_cache_stale": True,
                            "profile_stale": profile_stale, "cache_present": True,
                        })
                    else:
                        record["cache_present"] = False
                    records.append(record)
                    continue

                if cached is not None and cached.get("total_size") is not None:
                    identity_stale = not (
                        int(cached.get("mtime_ns", -1)) == int(info.st_mtime_ns)
                        and int(cached.get("inode", -1)) == int(info.st_ino)
                        and int(cached.get("dev", -1)) == int(info.st_dev)
                    )
                    profile_stale = str(cached.get("scan_key", "") or "") != scanner.scan_key
                    records.append({
                        "path": str(path), "exists": True,
                        "size": int(cached.get("size", 0) or 0),
                        "file_count": int(cached.get("file_count", 0) or 0),
                        "total_size": int(cached.get("total_size", 0) or 0),
                        "total_file_count": int(cached.get("total_file_count", 0) or 0),
                        "scanned_at": float(cached.get("scanned_at", 0.0) or 0.0),
                        "cache_stale": bool(identity_stale or profile_stale),
                        "total_cache_stale": bool(identity_stale),
                        "identity_stale": bool(identity_stale), "profile_stale": bool(profile_stale),
                        "cache_present": True,
                    })
                    continue

                is_regular = stat.S_ISREG(info.st_mode)
                is_symlink = stat.S_ISLNK(info.st_mode)
                if not stat.S_ISDIR(info.st_mode) or is_symlink:
                    total_size = int(info.st_size) if is_regular and not is_symlink else 0
                    excluded = scanner._skip_text(str(path))
                    direct_rows.append({
                        "path": str(path), "size": 0 if excluded else total_size,
                        "total_size": total_size, "mtime_ns": int(info.st_mtime_ns),
                        "inode": int(info.st_ino), "dev": int(info.st_dev),
                        "file_count": 0 if excluded else 1, "total_file_count": 1,
                        "scanned_at": now, "scan_key": scanner.scan_key,
                    })
                    records.append({
                        "path": str(path), "exists": True, "size": 0 if excluded else total_size,
                        "file_count": 0 if excluded else 1, "total_size": total_size,
                        "total_file_count": 1, "scanned_at": now, "cache_stale": False,
                        "total_cache_stale": False,
                        "identity_stale": False, "profile_stale": False,
                        "cache_present": True, "direct": True,
                    })
                else:
                    records.append({"path": str(path), "exists": True, "cache_present": False})
            if direct_rows:
                cache.put_fs_many(direct_rows)
            return {"kind": kind, "records": records}
        finally:
            cache.close()
    engine = None
    if kind in {KIND_SNAPSHOTS, KIND_STATS, KIND_DIRECTORY, KIND_METADATA}:
        repo_paths = paths.for_component(payload["component"])
        env = repo_paths.prepare_environment(dict(environment))
        try:
            with credentialed_engine(repo_paths, env, request.request_id, payload["credentials"], uid) as engine:
                if kind == KIND_SNAPSHOTS:
                    records = engine.snapshots(limit=payload["limit"] + 1, offset=payload["offset"])
                    truncated = len(records) > payload["limit"]
                    records = records[:payload["limit"]]
                    next_offset = payload["offset"] + len(records) if truncated else None
                    return {"kind": kind, "records": [record.to_gui_dict() for record in records], "next_offset": next_offset, "truncated": truncated}
                if kind == KIND_STATS:
                    stats = engine.stats(payload["snapshot_id"])
                    if not isinstance(stats, dict):
                        raise Phase2Error("invalid_stats", "snapshot stats have an invalid shape")
                    return {"kind": kind, "stats": stats}
                if kind == KIND_DIRECTORY:
                    records = engine.list_directory(payload["snapshot_id"], payload["directory"], payload["limit"], payload["offset"], probe=True)
                    truncated = len(records) > payload["limit"]
                    records = records[:payload["limit"]]
                    next_offset = payload["offset"] + len(records) if truncated else None
                    return {"kind": kind, "records": [_snapshot_node(item) for item in records], "next_offset": next_offset, "truncated": truncated}
                value, recovered = load_snapshot_metadata(
                    engine, repo_paths, payload["snapshot_id"], payload["filename"]
                )
                if recovered and progress is not None:
                    progress({
                        "current_item": "Recovered metadata for a legacy snapshot from trusted local state",
                        "warning": True,
                    })
                if not isinstance(value, (dict, list)):
                    raise Phase2Error("invalid_metadata", "snapshot metadata has an invalid shape")
                if isinstance(value, list):
                    page = value[payload["offset"]:payload["offset"] + payload["limit"] + 1]
                    truncated = len(page) > payload["limit"]
                    page = page[:payload["limit"]]
                    next_offset = payload["offset"] + len(page) if truncated else None
                    return {
                        "kind": kind, "filename": payload["filename"], "value": page,
                        "next_offset": next_offset, "truncated": truncated,
                    }
                if payload["offset"] != 0:
                    raise Phase2Error("invalid_metadata", "object metadata does not support a non-zero offset")
                return {"kind": kind, "filename": payload["filename"], "value": value, "next_offset": None, "truncated": False}
        except ResticError as exc:
            raise Phase2Error("restic_error", str(exc)) from exc
    assert protected_path is not None
    path = protected_path
    if kind == KIND_FS_CHILDREN:
        limit = payload["limit"]
        offset = payload["offset"]
        fs_cache = CacheDB(paths.cache / "filesystem.sqlite3")
        try:
            patterns = payload.get("exclude_patterns", [])
            scanner = SizeScanner(fs_cache, admission.root, patterns)
            records = _children(path, limit, offset, probe=True)
            enrich_filesystem_cache(
                records, fs_cache, scanner.scan_key, skip_path=scanner._skip_text,
            )
            directory_row = fs_cache.get_fs(str(path), max_age=None)
            directory_cache = None
            if directory_row is not None and directory_row.get("total_size") is not None:
                try:
                    directory_info = os.lstat(path)
                except OSError:
                    identity_stale = True
                else:
                    identity_stale = not (
                        int(directory_row.get("mtime_ns", -1)) == int(directory_info.st_mtime_ns)
                        and int(directory_row.get("inode", -1)) == int(directory_info.st_ino)
                        and int(directory_row.get("dev", -1)) == int(directory_info.st_dev)
                    )
                profile_stale = str(directory_row.get("scan_key", "") or "") != scanner.scan_key
                directory_cache = {
                    "size": int(directory_row.get("size", 0) or 0),
                    "file_count": int(directory_row.get("file_count", 0) or 0),
                    "total_size": int(directory_row.get("total_size", 0) or 0),
                    "total_file_count": int(directory_row.get("total_file_count", 0) or 0),
                    "scanned_at": float(directory_row.get("scanned_at", 0.0) or 0.0),
                    "cache_stale": bool(identity_stale or profile_stale),
                    "total_cache_stale": bool(identity_stale),
                    "identity_stale": bool(identity_stale), "profile_stale": bool(profile_stale),
                    "cache_present": True,
                }
        finally:
            fs_cache.close()
        truncated = len(records) > limit
        records = records[:limit]
        next_offset = offset + len(records) if truncated and offset + len(records) < MAX_FS_CHILDREN else None
        return {
            "kind": kind, "records": records,
            "next_offset": next_offset,
            "truncated": truncated, "source": "filesystem",
            "directory_cache": directory_cache,
        }
    cache = CacheDB(paths.cache / "filesystem.sqlite3")
    try:
        scan_root = str(path)
        last_cache_emit = [0.0]

        def scan_progress(current: str, bytes_done: int, items_done: int) -> None:
            if progress is not None:
                progress({
                    "current_item": current,
                    "bytes_done": bytes_done,
                    "items_processed": items_done,
                })

        def cache_committed(current: str, subtree_size: int, subtree_count: int,
                            bytes_done: int, items_done: int) -> None:
            if progress is None:
                return
            # Only visible immediate children (plus the requested root) need
            # progressive UI notifications. Every nested directory is still
            # written to SQLite, but emitting thousands of frames here would
            # throttle the scan and starve Qt repaint/navigation.
            current_path = Path(current)
            if current != scan_root and str(current_path.parent) != scan_root:
                return
            now = time.monotonic()
            if current != scan_root and now - last_cache_emit[0] < 0.15:
                return
            last_cache_emit[0] = now
            cached_row = cache.get_fs(current, max_age=None)
            progress({
                "current_item": current,
                "bytes_done": bytes_done,
                "items_processed": items_done,
                "calculated_path": current,
                "calculated_size": subtree_size,
                "calculated_file_count": subtree_count,
                "calculated_total_size": int(cached_row.get("total_size", 0) or 0) if cached_row else 0,
                "calculated_total_file_count": int(cached_row.get("total_file_count", 0) or 0) if cached_row else 0,
            })

        scanner = SizeScanner(cache, admission.root, payload.get("exclude_patterns", []))
        size, count = scanner.scan(
            path,
            force=bool(payload.get("force", False)),
            progress=scan_progress,
            checkpoint=ensure_not_cancelled,
            cache_progress_detailed=cache_committed,
        )
        root_cache = cache.get_fs(str(path), max_age=None, scan_key=scanner.scan_key)
        total_size = int(root_cache.get("total_size", size) or 0) if root_cache else int(size)
        total_count = int(root_cache.get("total_file_count", count) or 0) if root_cache else int(count)
    finally:
        cache.close()
    return {
        "kind": kind, "path": str(path), "size": size, "file_count": count,
        "total_size": total_size, "total_file_count": total_count,
        "source": scanner.last_source,
        "scanned_at": float(root_cache.get("scanned_at", 0.0) or 0.0) if root_cache else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    return run_fixed_helper(
        sys.argv[1:] if argv is None else argv,
        operation="inspect",
        payload_validator=validate_inspect_payload,
        handler=handle_inspect,
    )


if __name__ == "__main__":
    raise SystemExit(main())
