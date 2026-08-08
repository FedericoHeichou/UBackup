from __future__ import annotations

"""Human-facing labels and theme colors for semantic domain enums.

Business logic uses enums from :mod:`ubackup.models`.  This module is the
presentation boundary: widgets ask for a label/color instead of comparing or
persisting rendered strings.
"""

from enum import Enum
from typing import Any

from ..models import (
    BackupState,
    ConfigKind,
    ConfigPolicy,
    DependencyState,
    PackageInstallState,
    PackageManager,
    PackagePolicy,
    RestoreState,
    SelectionPolicy,
    TaskState,
)


_LABELS: dict[type[Enum], dict[Enum, str]] = {
    BackupState: {
        BackupState.SYSTEM_EXCLUDED: "System excluded",
        BackupState.PRECONFIGURED_EXCLUDED: "Preconfigured excluded",
        BackupState.MANUALLY_EXCLUDED: "Manually excluded",
        BackupState.BACKED_UP: "Backed up",
        BackupState.BACKED_UP_NOW: "Backed up now",
        BackupState.PENDING: "Pending backup",
        BackupState.NOT_SELECTED: "Not selected",
        BackupState.REVIEW_REQUIRED: "Review required",
        BackupState.EXCLUDED: "Excluded",
    },
    PackageManager: {
        PackageManager.APT: "APT",
        PackageManager.SNAP: "Snap",
        PackageManager.FLATPAK: "Flatpak",
    },
    PackageInstallState: {
        PackageInstallState.INSTALLED: "Installed",
        PackageInstallState.UNINSTALLED: "Uninstalled",
    },
    PackagePolicy: {
        PackagePolicy.INCLUDED: "Included",
        PackagePolicy.EXCLUDED: "Excluded",
    },
    ConfigPolicy: {
        ConfigPolicy.INCLUDED: "Included",
        ConfigPolicy.EXCLUDED: "Excluded",
    },
    ConfigKind: {
        ConfigKind.MODIFIED_CONFFILE: "Modified configuration",
        ConfigKind.UNMANAGED: "Unmanaged",
    },
    DependencyState: {
        DependencyState.INSTALLED: "Installed",
        DependencyState.MISSING: "Missing",
        DependencyState.OPTIONAL_MISSING: "Optional / missing",
    },
    TaskState: {
        TaskState.QUEUED: "Queued",
        TaskState.RUNNING: "Running",
        TaskState.COMPLETED: "Completed",
        TaskState.FAILED: "Failed",
        TaskState.CANCELLED: "Cancelled",
    },
    RestoreState: {
        RestoreState.IDLE: "Idle",
        RestoreState.LOADING: "Loading",
        RestoreState.READY: "Ready",
        RestoreState.RUNNING: "Running",
        RestoreState.COMPLETED: "Completed",
        RestoreState.FAILED: "Failed",
    },
    SelectionPolicy: {
        SelectionPolicy.DEFAULT: "Default",
        SelectionPolicy.INCLUDE: "Included",
        SelectionPolicy.INCLUDE_RECURSIVE: "Included recursively",
        SelectionPolicy.EXCLUDE: "Manually excluded",
    },
}

# Colors deliberately carry semantic meaning and are shared by all widgets.
# Text/icons remain present; color is never the sole indicator.
_COLORS: dict[type[Enum], dict[Enum, str]] = {
    BackupState: {
        BackupState.SYSTEM_EXCLUDED: "#66717f",
        BackupState.PRECONFIGURED_EXCLUDED: "#7893ad",
        BackupState.MANUALLY_EXCLUDED: "#d16d78",
        BackupState.BACKED_UP: "#67b87a",
        BackupState.BACKED_UP_NOW: "#5fcf83",
        BackupState.PENDING: "#d99b4a",
        BackupState.NOT_SELECTED: "#8998aa",
        BackupState.REVIEW_REQUIRED: "#b17be8",
        BackupState.EXCLUDED: "#d16d78",
    },
    PackageManager: {
        PackageManager.APT: "#5f9ed1",
        PackageManager.SNAP: "#b17be8",
        PackageManager.FLATPAK: "#d99b4a",
    },
    PackageInstallState: {
        PackageInstallState.INSTALLED: "#67b87a",
        PackageInstallState.UNINSTALLED: "#d16d78",
    },
    PackagePolicy: {
        PackagePolicy.INCLUDED: "#67b87a",
        PackagePolicy.EXCLUDED: "#d16d78",
    },
    ConfigPolicy: {
        ConfigPolicy.INCLUDED: "#67b87a",
        ConfigPolicy.EXCLUDED: "#d16d78",
    },
    ConfigKind: {
        ConfigKind.MODIFIED_CONFFILE: "#d99b4a",
        ConfigKind.UNMANAGED: "#5f9ed1",
    },
    DependencyState: {
        DependencyState.INSTALLED: "#67b87a",
        DependencyState.MISSING: "#d16d78",
        DependencyState.OPTIONAL_MISSING: "#8998aa",
    },
    TaskState: {
        TaskState.QUEUED: "#8998aa",
        TaskState.RUNNING: "#5f9ed1",
        TaskState.COMPLETED: "#67b87a",
        TaskState.FAILED: "#d16d78",
        TaskState.CANCELLED: "#d99b4a",
    },
    RestoreState: {
        RestoreState.IDLE: "#8998aa",
        RestoreState.LOADING: "#5f9ed1",
        RestoreState.READY: "#67b87a",
        RestoreState.RUNNING: "#5f9ed1",
        RestoreState.COMPLETED: "#67b87a",
        RestoreState.FAILED: "#d16d78",
    },
    SelectionPolicy: {
        SelectionPolicy.DEFAULT: "#8998aa",
        SelectionPolicy.INCLUDE: "#67b87a",
        SelectionPolicy.INCLUDE_RECURSIVE: "#67b87a",
        SelectionPolicy.EXCLUDE: "#d16d78",
    },
}


def semantic_label(value: Any) -> str:
    if isinstance(value, Enum):
        return _LABELS.get(type(value), {}).get(value, str(value.value).replace("_", " ").title())
    return str(value)


def semantic_color(value: Any, default: str = "#8998aa") -> str:
    if isinstance(value, Enum):
        return _COLORS.get(type(value), {}).get(value, default)
    return default
