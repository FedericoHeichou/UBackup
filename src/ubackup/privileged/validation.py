from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .runtime import Phase2Error
from ubackup.models import BackupComponent


MAX_LIST_ITEMS = 2048
# Locally discovered package/config inventories can legitimately exceed the
# generic request-list bound on long-lived desktop systems. They remain
# separately bounded and are also constrained by the aggregate RPC byte cap.
MAX_INVENTORY_ITEMS = 65536
MAX_PATH_LENGTH = 4096
MAX_SNAPSHOT_LENGTH = 128
_SNAPSHOT_RE = re.compile(r"^[0-9a-f]{8,64}$")
_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9+.-]*)?$")
RESTIC_GLOB_METACHARS = frozenset("*?[]{}")


def exact_fields(payload: Mapping[str, Any], fields: set[str]) -> None:
    actual = set(payload)
    missing = fields - actual
    unknown = actual - fields
    if missing:
        raise Phase2Error("missing_field", f"missing payload field: {sorted(missing)[0]}")
    if unknown:
        raise Phase2Error("unknown_field", f"unknown payload field: {sorted(unknown)[0]}")


def bounded_list(value: Any, name: str, *, maximum: int = MAX_LIST_ITEMS) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise Phase2Error("invalid_schema", f"{name} must be a bounded list")
    return value


def absolute_path(value: Any, name: str = "path") -> str:
    if not isinstance(value, str) or not value:
        raise Phase2Error("invalid_path", f"{name} is invalid")
    try:
        too_long = len(value.encode("utf-8", "strict")) > MAX_PATH_LENGTH
    except UnicodeEncodeError as exc:
        raise Phase2Error("invalid_path", f"{name} is not valid UTF-8") from exc
    if too_long:
        raise Phase2Error("invalid_path", f"{name} is invalid")
    if (
        "\x00" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)
        or any(char in RESTIC_GLOB_METACHARS for char in value)
        or not Path(value).is_absolute()
    ):
        raise Phase2Error("invalid_path", f"{name} must be absolute")
    if "//" in value or "/../" in f"{value}/" or value.endswith("/.."):
        raise Phase2Error("invalid_path", f"{name} is not normalized")
    return value




def backup_component(value: Any, *, allow_packages: bool = True) -> str:
    if not isinstance(value, str):
        raise Phase2Error("invalid_component", "backup component is invalid")
    allowed = {item.value for item in BackupComponent}
    if not allow_packages:
        allowed.discard(BackupComponent.PACKAGES.value)
    if value not in allowed:
        raise Phase2Error("invalid_component", "backup component is invalid")
    return value

def snapshot_id(value: Any) -> str:
    if not isinstance(value, str) or len(value) > MAX_SNAPSHOT_LENGTH or not _SNAPSHOT_RE.fullmatch(value):
        raise Phase2Error("invalid_snapshot", "snapshot id is invalid")
    return value


def include_path(value: Any, *, backup_root: Path, inplace: bool = False) -> str:
    path = absolute_path(value, "include")
    pure = PurePosixPath(path)
    if any(part in {".", ".."} for part in pure.parts) or any(ch in path for ch in "*?[]{}"):
        raise Phase2Error("invalid_include", "include must be a literal absolute path")
    pseudo = ("/proc", "/sys", "/dev", "/run")
    if path == "/" or any(path == p or path.startswith(p + "/") for p in pseudo):
        raise Phase2Error("invalid_include", "pseudo-filesystem and root includes are prohibited")
    if inplace and path == "/etc":
        raise Phase2Error("invalid_include", "in-place restore of /etc is prohibited")
    root = str(backup_root)
    if path == root or path.startswith(root.rstrip("/") + "/"):
        raise Phase2Error("invalid_include", "backup-root includes are prohibited")
    return path


def package_name(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 256 or not _PACKAGE_RE.fullmatch(value):
        raise Phase2Error("invalid_package", "package name is invalid")
    return value


def line_value(value: Any, name: str, *, maximum: int = MAX_PATH_LENGTH) -> str:
    if not isinstance(value, str) or not value:
        raise Phase2Error("invalid_input", f"{name} is invalid")
    try:
        if len(value.encode("utf-8", "strict")) > maximum:
            raise Phase2Error("invalid_input", f"{name} is invalid")
    except UnicodeEncodeError as exc:
        raise Phase2Error("invalid_input", f"{name} is invalid") from exc
    if any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise Phase2Error("invalid_input", f"{name} contains forbidden control characters")
    return value


def validate_package_names(value: Any) -> list[str]:
    return [package_name(item) for item in bounded_list(value, "packages")]


def validate_credentials(value: Any) -> dict[str, str | None]:
    if not isinstance(value, Mapping):
        raise Phase2Error("invalid_credentials", "credentials must be an object")
    exact_fields(value, {"password", "password_file"})
    password = value["password"]
    password_file = value["password_file"]
    if password is not None:
        if (
            not isinstance(password, str)
            or not password
            or len(password) > 4096
            or any(ord(char) < 0x20 or char in "\r\n\x7f" for char in password)
        ):
            raise Phase2Error("invalid_credentials", "password material is invalid")
    if password_file is not None:
        password_file = absolute_path(password_file, "password_file")
    if (password is None) == (password_file is None):
        raise Phase2Error("invalid_credentials", "exactly one password source is required")
    return {"password": password, "password_file": password_file}
