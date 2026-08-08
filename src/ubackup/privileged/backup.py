from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

if __name__ == "__main__" and __package__ in {None, ""}:
    sys.path.insert(0, "/usr/lib/ubackup")

from ubackup.manifest import build_privileged_state
from ubackup.models import BackupComponent, ConfigRecord, PackageManager, PackageRecord
from ubackup.paths import PrivilegedPaths
from ubackup.profiles import ExcludeRule, is_system_hard_path, matches_resticish
from ubackup.restic_engine import ResticError
from ubackup.system_scan import discover_configs, discover_package_inventory
from ubackup.privileged.configure import FilesystemOps, RootAdmission, admit_backup_root
from ubackup.privileged.credentials import credentialed_engine
from ubackup.privileged.runtime import Phase2Error, ensure_not_cancelled, run_fixed_helper
from ubackup.privileged.validation import MAX_INVENTORY_ITEMS, MAX_LIST_ITEMS, absolute_path, bounded_list, exact_fields, line_value, package_name, validate_credentials


BACKUP_PAYLOAD_FIELDS = {
    "sources",
    "source_exclusions",
    "exclude_rules",
    "packages",
    "configs",
    "components",
    "dry_run",
    "credentials",
}
LEGACY_BACKUP_PAYLOAD_FIELDS = BACKUP_PAYLOAD_FIELDS - {"components"}
RECORD_FIELDS = {"name", "version", "architecture", "installed", "manual", "selected", "origin", "manager", "scope", "channel", "reference", "origin_url", "classic"}
CONFIG_FIELDS = {"path", "kind", "package", "selected", "size", "mtime_ns"}
RULE_FIELDS = {"pattern", "category", "reason", "default_enabled", "caution"}


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise Phase2Error("invalid_schema", f"{name} must be boolean")
    return value


def _records(payload: Any, fields: set[str], kind: str, *, maximum: int = MAX_LIST_ITEMS) -> list[dict[str, Any]]:
    records = bounded_list(payload, kind, maximum=maximum)
    out: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, Mapping):
            raise Phase2Error("invalid_schema", f"{kind} records must be objects")
        exact_fields(item, fields)
        out.append(dict(item))
    return out


def validate_backup_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    fields = set(payload)
    if "components" in fields:
        exact_fields(payload, BACKUP_PAYLOAD_FIELDS)
    else:
        exact_fields(payload, LEGACY_BACKUP_PAYLOAD_FIELDS)
    sources = [absolute_path(item, "source") for item in bounded_list(payload["sources"], "sources")]
    exclusions = [
        absolute_path(item, "source_exclusion")
        for item in bounded_list(payload["source_exclusions"], "source_exclusions")
    ]
    rules: list[dict[str, Any]] = []
    for item in bounded_list(payload["exclude_rules"], "exclude_rules"):
        if not isinstance(item, Mapping):
            raise Phase2Error("invalid_schema", "exclude_rules must contain objects")
        exact_fields(item, RULE_FIELDS)
        line_value(item["pattern"], "exclude rule pattern")
        if not all(isinstance(item[key], str) for key in ("category", "reason", "caution")):
            raise Phase2Error("invalid_rule", "exclude rule text is invalid")
        for key in ("category", "reason", "caution"):
            if key == "caution" and item[key] == "":
                continue
            line_value(item[key], f"exclude rule {key}", maximum=1024)
        _bool(item["default_enabled"], "exclude_rule.default_enabled")
        rules.append(dict(item))

    packages = _records(payload["packages"], RECORD_FIELDS, "packages", maximum=MAX_INVENTORY_ITEMS)
    for record in packages:
        manager = record["manager"]
        if manager not in {item.value for item in PackageManager}:
            raise Phase2Error("invalid_package", "package manager is invalid")
        if manager == PackageManager.APT.value:
            package_name(record["name"])
        elif not isinstance(record["name"], str) or not record["name"] or len(record["name"]) > 256:
            raise Phase2Error("invalid_package", "package name is invalid")
        for key in ("version", "architecture", "origin", "scope", "channel", "reference", "origin_url"):
            value = record[key]
            if not isinstance(value, str) or len(value) > 1024:
                raise Phase2Error("invalid_package", "package record text is invalid")
            if value:
                line_value(value, f"package.{key}", maximum=1024)
        scope = record["scope"]
        if not scope or any(not (char.isalnum() or char in "._-") for char in scope):
            raise Phase2Error("invalid_package", "package scope is invalid")
        if manager == PackageManager.FLATPAK.value:
            origin = record["origin"]
            if (
                not origin or not origin[0].isalnum()
                or any(not (char.isalnum() or char in "._-") for char in origin)
            ):
                raise Phase2Error("invalid_package", "Flatpak remote name is invalid")
            reference = record["reference"]
            if reference and not reference.startswith("app/"):
                raise Phase2Error("invalid_package", "Flatpak application reference is invalid")
            if record["origin_url"].startswith("-"):
                raise Phase2Error("invalid_package", "Flatpak remote URL is invalid")
        for key in ("installed", "manual", "selected", "classic"):
            _bool(record[key], f"package.{key}")

    configs = _records(payload["configs"], CONFIG_FIELDS, "configs", maximum=MAX_INVENTORY_ITEMS)
    for record in configs:
        path = absolute_path(record["path"], "config.path")
        if not (path == "/etc" or path.startswith("/etc/")):
            raise Phase2Error("invalid_config", "configuration records must be under /etc")
        if not isinstance(record["kind"], str) or record["kind"] not in {"modified-conffile", "unmanaged"}:
            raise Phase2Error("invalid_config", "configuration kind is invalid")
        if not isinstance(record["package"], str) or len(record["package"]) > 256:
            raise Phase2Error("invalid_config", "configuration package is invalid")
        _bool(record["selected"], "config.selected")
        if isinstance(record["size"], bool) or not isinstance(record["size"], int) or record["size"] < 0:
            raise Phase2Error("invalid_config", "configuration size is invalid")
        if isinstance(record["mtime_ns"], bool) or not isinstance(record["mtime_ns"], int) or record["mtime_ns"] < 0:
            raise Phase2Error("invalid_config", "configuration mtime is invalid")

    _bool(payload["dry_run"], "dry_run")
    credentials = validate_credentials(payload["credentials"])
    raw_components = payload.get(
        "components",
        [BackupComponent.FILESYSTEM.value, BackupComponent.CONFIGS.value, BackupComponent.PACKAGES.value],
    )
    components = bounded_list(raw_components, "components")
    allowed_components = {item.value for item in BackupComponent}
    if len(components) != 1:
        raise Phase2Error("invalid_components", "exactly one backup component is required per repository snapshot")
    if any(not isinstance(item, str) or item not in allowed_components for item in components):
        raise Phase2Error("invalid_components", "backup component is invalid")
    if len(set(components)) != len(components):
        raise Phase2Error("invalid_components", "backup components must be unique")

    return {
        "sources": sources,
        "source_exclusions": exclusions,
        "exclude_rules": rules,
        "packages": packages,
        "configs": configs,
        "components": components,
        "dry_run": payload["dry_run"],
        "credentials": credentials,
    }


def _reject_backup_root_paths(admission: RootAdmission, paths: list[str], label: str) -> None:
    root = str(admission.root).rstrip("/")
    for path in paths:
        if path == root or path.startswith(root + "/"):
            raise Phase2Error("backup_root_recursion", f"{label} may not enter the backup root")


def validate_backup_payload_for_root(
    payload: Mapping[str, Any], backup_root: str | Path
) -> dict[str, Any]:
    value = validate_backup_payload(payload)
    root = str(backup_root).rstrip("/")
    for label in ("sources", "source_exclusions"):
        for path in value[label]:
            if is_system_hard_path(path):
                raise Phase2Error("invalid_source", f"{label} may not enter a hard system exclusion")
            if path == root or path.startswith(root + "/"):
                raise Phase2Error("backup_root_recursion", f"{label} may not enter the backup root")
            resolved = os.path.realpath(path)
            if resolved == root or resolved.startswith(root + "/"):
                raise Phase2Error("backup_root_recursion", f"{label} may not resolve into the backup root")
    for exclusion in value["source_exclusions"]:
        if not any(
            exclusion.startswith(source.rstrip("/") + "/")
            for source in value["sources"]
            if source != "/"
        ) and "/" not in value["sources"]:
            raise Phase2Error("invalid_exclusion", "source exclusions must be nested under a source")
    return value


def _split_source_around_excluded_root(
    source: str, excluded_root: Path, *, reject_equal: bool = False
) -> list[str]:
    """Expand an ancestor source without descending into excluded_root.

    This is used for the backup repository itself and for curated roots such
    as ``/etc`` when the normal filesystem policy excludes that tree. It makes
    the exclusion structural instead of relying on Restic to walk into a
    directory that must later be re-included for explicit metadata/config files.
    """
    source_path = Path(source)
    root = Path(excluded_root)
    if source_path == root:
        if reject_equal:
            raise Phase2Error("backup_root_recursion", "backup source may not be the backup root")
        return []
    if source_path not in root.parents:
        return [source]

    result: list[str] = []

    def walk_branch(current: Path) -> None:
        try:
            next_name = root.relative_to(current).parts[0]
        except (ValueError, IndexError) as exc:
            raise Phase2Error("invalid_source", "filesystem source split is invalid") from exc
        try:
            with os.scandir(current) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as exc:
            raise Phase2Error("filesystem_error", f"cannot enumerate filesystem source ancestor: {current}") from exc
        for entry in entries:
            candidate = current / entry.name
            if entry.name == next_name:
                if candidate == root:
                    continue
                walk_branch(candidate)
                continue
            candidate_text = str(candidate)
            if is_system_hard_path(candidate_text):
                continue
            resolved = Path(os.path.realpath(candidate))
            if resolved == root or root in resolved.parents:
                continue
            result.append(candidate_text)

    walk_branch(source_path)
    return result


def _effective_filesystem_sources(
    sources: list[str], backup_root: Path, *, structural_excludes: list[Path] | None = None
) -> list[str]:
    result = list(sources)
    protected = [(Path(backup_root), True)]
    protected.extend((Path(path), False) for path in (structural_excludes or []))
    for excluded, reject_equal in protected:
        next_result: list[str] = []
        for source in result:
            next_result.extend(
                _split_source_around_excluded_root(source, excluded, reject_equal=reject_equal)
            )
        result = next_result
    return list(dict.fromkeys(result))


def _rules_exclude_directory(rules: list[ExcludeRule], directory: str) -> bool:
    excluded = False
    matched = False
    for rule in rules:
        if matches_resticish(directory, rule.pattern):
            matched = True
            excluded = not rule.pattern.startswith("!")
    return matched and excluded


def build_plan(paths: PrivilegedPaths, env: dict[str, str], policy: Mapping[str, Any]) -> dict[str, Any]:
    """Build the exact metadata/source/exclude plan used by backup and dry-run."""
    for source in policy["sources"]:
        absolute_path(source, "source")
    for exclusion in policy["source_exclusions"]:
        absolute_path(exclusion, "source_exclusion")
    for config in policy["configs"]:
        config_path = absolute_path(config["path"], "config.path")
        if not (config_path == "/etc" or config_path.startswith("/etc/")):
            raise Phase2Error("invalid_config", "configuration records must be under /etc")
    packages = [PackageRecord(**record) for record in policy["packages"]]
    configs = [ConfigRecord(**record) for record in policy["configs"]]
    rules = [ExcludeRule(**record) for record in policy["exclude_rules"]]
    filesystem_enabled = BackupComponent.FILESYSTEM.value in set(policy["components"])
    structural_excludes: list[Path] = []
    etc_structural = filesystem_enabled and _rules_exclude_directory(rules, "/etc")
    if etc_structural:
        structural_excludes.append(Path("/etc"))
    effective_sources = _effective_filesystem_sources(
        policy["sources"] if filesystem_enabled else [],
        paths.root,
        structural_excludes=structural_excludes,
    )
    # When filesystem data is not part of the snapshot, no generic filesystem
    # exclusion rule should be allowed to filter explicitly selected config or
    # metadata files. For combined filesystem+config snapshots, /etc is split
    # out structurally, so remove rules that exclude the /etc directory itself;
    # exact selected config files remain explicit sources and get final !rules.
    if not filesystem_enabled:
        restic_rules: list[ExcludeRule] = []
    elif etc_structural:
        restic_rules = [
            rule for rule in rules
            if rule.pattern.startswith("!") or not matches_resticish("/etc", rule.pattern)
        ]
    else:
        restic_rules = rules
    manifest = build_privileged_state(
        paths,
        env,
        policy["sources"],
        policy["source_exclusions"],
        restic_rules,
        packages,
        configs,
        components=policy["components"],
        effective_filesystem_sources=effective_sources,
    )
    return {
        "manifest": manifest,
        "sources_file": paths.sources_file,
        "excludes_file": paths.excludes_file,
    }


def _merge_discovery(
    policy: Mapping[str, Any], env: dict[str, str], uid: int,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Refresh inventory in the helper while retaining caller policy choices."""
    component_set = set(policy["components"])
    package_policy = {
        (record.get("manager", PackageManager.APT.value), record.get("scope", "system"), record["name"]): record["selected"]
        for record in policy["packages"]
    }
    packages: list[dict[str, Any]] = []
    if BackupComponent.PACKAGES.value in component_set:
        if progress is not None:
            progress({"current_item": "Refreshing APT, Snap and Flatpak package inventory…"})
        discovered_packages = discover_package_inventory(env, uid)
        if len(discovered_packages) > MAX_INVENTORY_ITEMS:
            raise Phase2Error("inventory_too_large", "package inventory exceeds the plan limit")
        for record in discovered_packages:
            value = dict(record)
            value["selected"] = package_policy.get((value.get("manager", PackageManager.APT.value), value.get("scope", "system"), value["name"]), True)
            packages.append(value)

    config_policy = {record["path"]: record["selected"] for record in policy["configs"]}
    configs: list[dict[str, Any]] = []
    if BackupComponent.CONFIGS.value in component_set:
        discovered_configs = discover_configs(
            env,
            progress=(lambda text: progress({"current_item": text}) if progress is not None else None),
            checkpoint=ensure_not_cancelled,
        )
        if len(discovered_configs) > MAX_INVENTORY_ITEMS:
            raise Phase2Error("inventory_too_large", "configuration inventory exceeds the plan limit")
        for record in discovered_configs:
            value = dict(record)
            value["path"] = absolute_path(value.get("path"), "discovered config path")
            if not (value["path"] == "/etc" or value["path"].startswith("/etc/")):
                raise Phase2Error("invalid_config", "discovered configuration path is outside /etc")
            value["selected"] = config_policy.get(value["path"], True)
            configs.append(value)
    merged = dict(policy)
    merged["packages"] = packages
    merged["configs"] = configs
    return merged


@contextlib.contextmanager
def _backup_lock(paths: PrivilegedPaths):
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(paths.lock_file, flags, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise Phase2Error("invalid_plan", "backup lock is not root-private")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _request_paths(paths: PrivilegedPaths, request_id: str) -> tuple[PrivilegedPaths, Path]:
    # Request-private storage is still used for ephemeral credentials and
    # cancellation cleanup. Snapshot metadata itself lives at the stable,
    # root-owned ``.ubackup/state/<domain>/current`` paths so every newly-created
    # snapshot contains a deterministic metadata location. The backup lock
    # serializes writers, so no two plans can update this state concurrently.
    plan_dir = paths.plans / request_id
    if plan_dir.exists() or plan_dir.is_symlink():
        raise Phase2Error("invalid_plan", "request plan already exists")
    plan_dir.mkdir(mode=0o700)
    return paths, plan_dir


def _backup_receipt(manifest: Mapping[str, Any], summary: Mapping[str, Any], dry_run: bool) -> dict[str, Any]:
    return {
        "schema": 1,
        "created_at": manifest.get("created_at", ""),
        "metadata_suffix": manifest.get("metadata_suffix", ""),
        "dry_run": dry_run,
        "snapshot_id": summary.get("snapshot_id", ""),
        "partial": bool(summary.get("partial", False)),
        "components": list(manifest.get("components", [])),
        "effective_source_count": len(manifest.get("effective_sources", [])),
        "selected_package_count": len(manifest.get("selected_packages", [])),
        "selected_config_count": len(manifest.get("selected_configs", [])),
        "summary": dict(summary),
    }


def handle_backup(
    request,
    uid: int,
    environment: Mapping[str, str],
    ops: FilesystemOps | None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    admission = admit_backup_root(request.backup_root, ops=ops)
    base_paths = PrivilegedPaths.for_root(admission.root)
    policy = validate_backup_payload_for_root(request.payload, admission.root)
    paths = base_paths.for_component(policy["components"][0])
    admission.revalidate(ops)
    env = paths.prepare_environment(dict(environment))
    paths.cleanup_stale_request_artifacts(active_request_id=request.request_id)
    try:
        with _backup_lock(paths):
            isolated_policy = _merge_discovery(policy, env, uid, progress)
            request_paths, plan_dir = _request_paths(paths, request.request_id)
            try:
                plan = build_plan(request_paths, env, isolated_policy)
                manifest = plan["manifest"]
                admission.revalidate(ops)
                with credentialed_engine(
                    paths,
                    env,
                    request.request_id,
                    isolated_policy["credentials"],
                    uid,
                    request_dir=plan_dir,
                ) as engine:
                    summary = engine.backup(
                        plan["sources_file"], plan["excludes_file"], isolated_policy["dry_run"],
                        on_message=progress,
                    )
            finally:
                shutil.rmtree(plan_dir, ignore_errors=True)
    except ResticError as exc:
        message = str(exc).strip() or "Restic backup failed"
        raise Phase2Error("restic_error", message) from exc
    summary_data = dataclasses.asdict(summary)
    receipt = _backup_receipt(manifest, summary_data, policy["dry_run"])
    return {
        "dry_run": policy["dry_run"],
        "receipt": receipt,
    }


def main(argv: list[str] | None = None) -> int:
    return run_fixed_helper(
        sys.argv[1:] if argv is None else argv,
        operation="backup",
        payload_validator=validate_backup_payload,
        handler=handle_backup,
    )


if __name__ == "__main__":
    raise SystemExit(main())
