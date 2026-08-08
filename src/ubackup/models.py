from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import StrEnum
from pathlib import Path
from typing import Any


class SelectionPolicy(StrEnum):
    DEFAULT = "default"
    INCLUDE = "include"
    INCLUDE_RECURSIVE = "include_recursive"
    EXCLUDE = "exclude"


class BackupComponent(StrEnum):
    FILESYSTEM = "filesystem"
    CONFIGS = "configs"
    PACKAGES = "packages"


class ExclusionOrigin(StrEnum):
    NONE = "none"
    SYSTEM = "system"
    PRECONFIGURED = "preconfigured"
    MANUAL = "manual"
    BACKUP_ROOT = "backup_root"


class BackupState(StrEnum):
    # EXCLUDED is retained for backward compatibility with old serialized/UI code.
    EXCLUDED = "excluded"
    SYSTEM_EXCLUDED = "system_excluded"
    PRECONFIGURED_EXCLUDED = "preconfigured_excluded"
    MANUALLY_EXCLUDED = "manually_excluded"
    BACKED_UP = "backed_up"
    BACKED_UP_NOW = "backed_up_now"
    PENDING = "pending"
    NOT_SELECTED = "not_selected"
    REVIEW_REQUIRED = "review_required"


class DiscoveryState(StrEnum):
    KNOWN = "known"
    NEW_UNSELECTED = "new_unselected"


class PackageManager(StrEnum):
    APT = "apt"
    SNAP = "snap"
    FLATPAK = "flatpak"


class PackageInstallState(StrEnum):
    INSTALLED = "installed"
    UNINSTALLED = "uninstalled"


class PackagePolicy(StrEnum):
    INCLUDED = "included"
    EXCLUDED = "excluded"


class ConfigKind(StrEnum):
    MODIFIED_CONFFILE = "modified-conffile"
    UNMANAGED = "unmanaged"


class ConfigPolicy(StrEnum):
    INCLUDED = "included"
    EXCLUDED = "excluded"


class TaskState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DependencyState(StrEnum):
    INSTALLED = "installed"
    MISSING = "missing"
    OPTIONAL_MISSING = "optional_missing"


class RestoreState(StrEnum):
    IDLE = "idle"
    LOADING = "loading"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class DependencyStatus:
    name: str
    command: str
    required: bool
    installed: bool
    version: str = ""
    install_hint: str = ""

    @property
    def state(self) -> DependencyState:
        if self.installed:
            return DependencyState.INSTALLED
        return DependencyState.MISSING if self.required else DependencyState.OPTIONAL_MISSING


@dataclass(slots=True)
class PackageRecord:
    name: str
    version: str
    architecture: str
    installed: bool
    manual: bool
    selected: bool = True
    origin: str = ""
    manager: PackageManager | str = PackageManager.APT
    scope: str = "system"
    channel: str = ""
    reference: str = ""
    origin_url: str = ""
    classic: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.manager, PackageManager):
            self.manager = PackageManager(str(self.manager))

    @property
    def install_state(self) -> PackageInstallState:
        return PackageInstallState.INSTALLED if self.installed else PackageInstallState.UNINSTALLED

    @property
    def policy(self) -> PackagePolicy:
        return PackagePolicy.INCLUDED if self.selected else PackagePolicy.EXCLUDED

    @property
    def policy_key(self) -> str:
        return f"{self.manager.value}|{self.scope}|{self.name}"

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["manager"] = self.manager.value
        return value


@dataclass(slots=True)
class ConfigRecord:
    path: str
    kind: ConfigKind | str
    package: str = ""
    selected: bool = True
    size: int = 0
    mtime_ns: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ConfigKind):
            self.kind = ConfigKind(str(self.kind))

    @property
    def policy(self) -> ConfigPolicy:
        return ConfigPolicy.INCLUDED if self.selected else ConfigPolicy.EXCLUDED

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["kind"] = str(self.kind)
        return value


@dataclass(slots=True)
class SnapshotRecord:
    id: str
    time: str
    hostname: str
    paths: list[str]
    tags: list[str]
    parent: str = ""
    total_bytes_processed: int = 0
    data_added: int = 0
    data_added_packed: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_gui_dict(self) -> dict[str, Any]:
        """Return the bounded snapshot summary needed by the desktop UI.

        Restic's ``paths`` field contains every source passed to ``backup``.
        Curated configuration snapshots can therefore contain thousands of
        absolute paths and make a *single* startup/RPC record exceed the
        protocol frame limit.  The GUI never uses that list: restore source
        policy comes from the versioned UBackup manifest instead.  Keep full
        paths inside the privileged Restic model for maintenance/metadata
        operations, but do not move them across the UI transport boundary.
        """
        value = asdict(self)
        value["paths"] = []
        return value


@dataclass(slots=True)
class DryRunSummary:
    snapshot_id: str = ""
    total_bytes_processed: int = 0
    data_added: int = 0
    data_added_packed: int = 0
    files_new: int = 0
    files_changed: int = 0
    files_unmodified: int = 0
    partial: bool = False

    @property
    def estimated_repository_delta(self) -> int:
        return self.data_added_packed or self.data_added


@dataclass(slots=True)
class FsNode:
    path: Path
    size: int | None
    is_dir: bool
    mtime_ns: int
    cached_at: float | None = None


@dataclass(slots=True)
class TaskRecord:
    task_id: str
    name: str
    state: TaskState
    started_at: float
    updated_at: float
    current_item: str = ""
    items_processed: int = 0
    bytes_processed: int = 0
    bytes_total: int = 0
    percent: float | None = None
    error: str = ""
