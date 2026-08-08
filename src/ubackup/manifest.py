from __future__ import annotations

import json
import os
import platform
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .models import BackupComponent, ConfigRecord, PackageManager, PackageRecord
from .paths import AppPaths, PrivilegedPaths
from .profiles import ExcludeRule, system_hard_exclude_patterns
from .system_scan import collect_system_inventory


def _atomic_text(path: Path, value: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_json(path: Path, value) -> None:
    _atomic_text(path, json.dumps(value, indent=2, ensure_ascii=False))


def build_state(paths: AppPaths | PrivilegedPaths, env: dict[str, str], selected_sources: list[str],
                source_exclusions: list[str], rules: list[ExcludeRule],
                packages: list[PackageRecord], configs: list[ConfigRecord],
                components: list[str] | None = None,
                effective_filesystem_sources: list[str] | None = None) -> dict:
    component_values = list(components or [item.value for item in BackupComponent])
    if len(component_values) != 1 or component_values[0] not in {item.value for item in BackupComponent}:
        raise ValueError("a snapshot must contain exactly one backup component")
    domain = component_values[0]
    filesystem_enabled = domain == BackupComponent.FILESYSTEM.value
    configs_enabled = domain == BackupComponent.CONFIGS.value
    packages_enabled = domain == BackupComponent.PACKAGES.value

    chosen_packages = [p for p in packages if p.selected] if packages_enabled else []
    chosen_configs = [c for c in configs if c.selected] if configs_enabled else []
    requested_selected_sources = list(selected_sources) if filesystem_enabled else []
    effective_selected_sources = (
        list(effective_filesystem_sources)
        if filesystem_enabled and effective_filesystem_sources is not None
        else list(requested_selected_sources)
    )

    excludes: list[str] = []
    if filesystem_enabled:
        excludes.extend(system_hard_exclude_patterns())
        excludes.extend(r.pattern for r in rules)
        for value in source_exclusions:
            excludes.extend([value, value.rstrip("/") + "/**"])

    _atomic_text(paths.excludes_file, "\n".join(dict.fromkeys(excludes)) + "\n")
    package_metadata_files: list[Path] = []
    if packages_enabled:
        # Keep one physical metadata file per package manager while exposing a
        # unified logical inventory through the privileged metadata API.
        try:
            paths.packages_file.unlink()
        except FileNotFoundError:
            pass
        for manager in PackageManager:
            manager_path = paths.current / f"packages-{manager.value}.json"
            records = [p.to_dict() for p in packages if p.manager is manager]
            _atomic_json(manager_path, records)
            package_metadata_files.append(manager_path)
    _atomic_json(paths.configs_file, [c.to_dict() for c in configs] if configs_enabled else [])
    _atomic_json(paths.system_file, collect_system_inventory(env))

    metadata_files = [
        str(paths.manifest_file), str(paths.configs_file),
        str(paths.system_file), str(paths.excludes_file), str(paths.sources_file),
    ]
    metadata_files.extend(str(path) for path in package_metadata_files)
    if filesystem_enabled:
        data_sources = effective_selected_sources
    elif configs_enabled:
        data_sources = [c.path for c in chosen_configs]
    else:
        data_sources = []
    source_set = list(dict.fromkeys(data_sources + metadata_files))
    source_set = [
        value for value in source_set
        if value in {str(paths.manifest_file), str(paths.sources_file)} or Path(value).exists()
    ]

    # Keep the manifest intentionally small. Potentially huge package/config
    # inventories are versioned in their own metadata files and loaded through
    # the bounded/chunked privileged transport only when needed.
    manifest = {
        "schema": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "backup_root": str(paths.root),
        "domain": domain,
        "components": [domain],
        "selected_sources": requested_selected_sources,
        "source_exclusions": list(source_exclusions) if filesystem_enabled else [],
        "selected_package_count": len(chosen_packages),
        "package_managers": [manager.value for manager in PackageManager if any(p.manager is manager for p in packages)] if packages_enabled else [],
        "selected_config_count": len(chosen_configs),
        "effective_source_count": len(source_set),
        "exclude_rules": [r.to_dict() for r in rules] if filesystem_enabled else [],
        "metadata_suffix": "/" + paths.manifest_file.relative_to(paths.root).as_posix(),
    }
    _atomic_json(paths.manifest_file, manifest)
    _atomic_text(paths.sources_file, "\n".join(source_set) + "\n")
    return manifest


def build_privileged_state(
    paths: PrivilegedPaths,
    env: dict[str, str],
    selected_sources: list[str],
    source_exclusions: list[str],
    rules: list[ExcludeRule],
    packages: list[PackageRecord],
    configs: list[ConfigRecord],
    components: list[str] | None = None,
    effective_filesystem_sources: list[str] | None = None,
) -> dict:
    """Build the same legacy-compatible metadata layout without GUI paths."""
    return build_state(
        paths,
        env,
        selected_sources,
        source_exclusions,
        rules,
        packages,
        configs,
        components,
        effective_filesystem_sources,
    )
