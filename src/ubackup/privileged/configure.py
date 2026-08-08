from __future__ import annotations

"""The fixed ``configure`` privileged operation.

This module is deliberately small.  It validates the root and caller identity
before touching the filesystem, and it only creates the caller's GUI leaf.
It never accepts a destination, command, environment, or ownership value from
the request.
"""

import os
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

if __name__ == "__main__" and __package__ in {None, ""}:
    # The installed helper is executed by absolute filename with Python's
    # isolated mode.  Add only the fixed installed package parent, never an
    # environment-provided PYTHONPATH.
    sys.path.insert(0, "/usr/lib/ubackup")

from ubackup.paths import GuiPaths

from ubackup.privileged.protocol import (
    CONFIGURE_OPERATION,
    MAX_REQUEST_BYTES,
    ConfigureRequest,
    ProtocolError,
    decode_request,
    error_response,
    is_valid_user_uid,
    read_frame_fd,
    success_response,
)


class ConfigureError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class FilesystemOps(Protocol):
    def lstat(self, path: str | os.PathLike[str]) -> os.stat_result: ...

    def mkdir(self, path: str | os.PathLike[str], mode: int = 0o777): ...

    def chmod(self, path: str | os.PathLike[str], mode: int, *, follow_symlinks: bool = True): ...

    def chown(
        self,
        path: str | os.PathLike[str],
        uid: int,
        gid: int,
        *,
        follow_symlinks: bool = True,
    ): ...

class OsFilesystemOps:
    """Default system primitives, kept injectable for non-root tests."""

    def lstat(self, path: str | os.PathLike[str]) -> os.stat_result:
        return os.lstat(path)

    def mkdir(self, path: str | os.PathLike[str], mode: int = 0o777) -> None:
        os.mkdir(path, mode)

    def chmod(
        self,
        path: str | os.PathLike[str],
        mode: int,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        os.chmod(path, mode, follow_symlinks=follow_symlinks)

    def chown(
        self,
        path: str | os.PathLike[str],
        uid: int,
        gid: int,
        *,
        follow_symlinks: bool = True,
    ) -> None:
        os.chown(path, uid, gid, follow_symlinks=follow_symlinks)

    def read_bytes(self, path: str | os.PathLike[str], limit: int) -> bytes:
        with open(path, "rb") as handle:
            return handle.read(limit + 1)


ROOT_PARENT_MODE = 0o711
BACKUP_ROOT_MODE = 0o711
USER_DIRECTORY_MODE = 0o700
APPROVAL_MARKER_MODE = 0o600
APPROVAL_MARKER_RELATIVE = Path(".ubackup") / "approved"
APPROVAL_MARKER_CONTENT = b"ubackup-root-v1\n"
APPROVAL_MARKER = APPROVAL_MARKER_RELATIVE
CONFIGURE_DEADLINE_SECONDS = 120.0
DEFAULT_BACKUP_ROOT = Path("/backup")
BLOCKED_BACKUP_ROOTS = tuple(
    Path(value)
    for value in ("/", "/etc", "/usr", "/var", "/home", "/root", "/proc", "/sys", "/dev", "/run")
)
MAX_UID = (1 << 32) - 1  # Reserved ceiling retained for compatibility.


def validated_pkexec_uid(environment: Mapping[str, str] | None = None) -> int:
    """Read and strictly validate the UID that pkexec assigned to the caller."""
    env = os.environ if environment is None else environment
    raw = env.get("PKEXEC_UID")
    if not isinstance(raw, str) or not raw:
        raise ConfigureError("invalid_caller_uid", "PKEXEC_UID is required")
    # Do not accept whitespace, signs, decimal notation, or alternate forms.
    if not raw.isascii() or not raw.isdecimal() or (len(raw) > 1 and raw[0] == "0"):
        raise ConfigureError("invalid_caller_uid", "PKEXEC_UID must be a decimal UID")
    uid = int(raw, 10)
    if not is_valid_user_uid(uid):
        raise ConfigureError("invalid_caller_uid", "PKEXEC_UID is outside the valid range")
    return uid


def _path(value: str | os.PathLike[str]) -> Path:
    raw = os.fspath(value)
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ConfigureError("invalid_backup_root", "backup_root is invalid")
    if not Path(raw).is_absolute():
        raise ConfigureError("invalid_backup_root", "backup_root must be absolute")
    return Path(os.path.abspath(os.path.expanduser(raw)))


def _lstat(ops: FilesystemOps, path: Path):
    try:
        return ops.lstat(path)
    except TypeError:
        # Small test doubles often expose the one-argument form only; the
        # production implementation always uses os.lstat above.
        return ops.lstat(str(path))


def _checkpoint(checkpoint: Callable[[], None] | None) -> None:
    if checkpoint is not None:
        checkpoint()


def _chmod(ops: FilesystemOps, path: Path, mode: int, *, checkpoint: Callable[[], None] | None = None) -> None:
    _checkpoint(checkpoint)
    try:
        ops.chmod(path, mode, follow_symlinks=False)
    except TypeError:
        try:
            ops.chmod(path, mode)
        except OSError as exc:
            raise ConfigureError("provisioning_failed", f"could not secure {path}") from exc
    except OSError as exc:
        raise ConfigureError("provisioning_failed", f"could not secure {path}") from exc


def _chown(ops: FilesystemOps, path: Path, uid: int, *, checkpoint: Callable[[], None] | None = None) -> None:
    _checkpoint(checkpoint)
    try:
        # Keep the system group unchanged.  The owner UID is the security
        # boundary and mode 0700 prevents group access to the user leaf.
        ops.chown(path, uid, -1, follow_symlinks=False)
    except TypeError:
        try:
            ops.chown(path, uid, -1)
        except OSError as exc:
            raise ConfigureError("provisioning_failed", f"could not assign user ownership to {path}") from exc
    except OSError as exc:
        raise ConfigureError("provisioning_failed", f"could not assign user ownership to {path}") from exc


def _ancestor_paths(path: Path) -> tuple[Path, ...]:
    chain: list[Path] = []
    current = path
    while True:
        chain.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return tuple(reversed(chain))


def _stat_identity(info) -> tuple[int, int]:
    try:
        return int(info.st_dev), int(info.st_ino)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ConfigureError("invalid_backup_root", "filesystem identity is unavailable") from exc


def _inspect_ancestry(
    fs: FilesystemOps,
    path: Path,
    *,
    require_world_traversal: bool = False,
) -> tuple[tuple[Path, tuple[int, int]], ...]:
    inspected: list[tuple[Path, tuple[int, int]]] = []
    for component in _ancestor_paths(path):
        try:
            info = _lstat(fs, component)
        except FileNotFoundError as exc:
            raise ConfigureError("invalid_backup_root", "backup_root ancestry does not exist") from exc
        except OSError as exc:
            raise ConfigureError("invalid_backup_root", "backup_root ancestry cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ConfigureError("invalid_backup_root", "backup_root must not contain symlink components")
        if not stat.S_ISDIR(info.st_mode):
            raise ConfigureError("invalid_backup_root", "backup_root ancestry must be directories")
        if info.st_uid != 0:
            raise ConfigureError("invalid_backup_root", "backup_root ancestry must be root-owned")
        if info.st_mode & 0o022:
            raise ConfigureError("invalid_backup_root", "backup_root ancestry must not be writable")
        if require_world_traversal and component != path and not (info.st_mode & 0o001):
            raise ConfigureError(
                "invalid_backup_root",
                "non-default backup root ancestry must be world-traversable",
            )
        inspected.append((component, _stat_identity(info)))
    return tuple(inspected)


def _validate_approval_marker(fs: FilesystemOps, root: Path) -> tuple[int, int]:
    marker = root / APPROVAL_MARKER_RELATIVE
    marker_parent = marker.parent
    try:
        parent_info = _lstat(fs, marker_parent)
    except FileNotFoundError as exc:
        raise ConfigureError("approval_required", "non-default backup root is not approved") from exc
    except OSError as exc:
        raise ConfigureError("approval_invalid", "approval marker cannot be inspected") from exc
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise ConfigureError("approval_invalid", "approval marker parent is unsafe")
    if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
        raise ConfigureError("approval_invalid", "approval marker parent is not secure")

    try:
        info = _lstat(fs, marker)
    except FileNotFoundError as exc:
        raise ConfigureError("approval_required", "non-default backup root is not approved") from exc
    except OSError as exc:
        raise ConfigureError("approval_invalid", "approval marker cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ConfigureError("approval_invalid", "approval marker must be a regular file")
    if info.st_uid != 0 or (info.st_mode & 0o7777) != APPROVAL_MARKER_MODE:
        raise ConfigureError("approval_invalid", "approval marker ownership or mode is unsafe")
    try:
        reader = getattr(fs, "read_bytes", None)
        if reader is not None:
            content = reader(marker, len(APPROVAL_MARKER_CONTENT))
        else:
            raise AttributeError
    except AttributeError:
        try:
            with marker.open("rb") as handle:
                content = handle.read(len(APPROVAL_MARKER_CONTENT) + 1)
        except OSError as exc:
            raise ConfigureError("approval_invalid", "approval marker cannot be read") from exc
    except OSError as exc:
        raise ConfigureError("approval_invalid", "approval marker cannot be read") from exc
    if len(content) != len(APPROVAL_MARKER_CONTENT) or content != APPROVAL_MARKER_CONTENT:
        raise ConfigureError("approval_invalid", "approval marker content is invalid")
    return _stat_identity(info)


@dataclass(frozen=True, slots=True)
class RootAdmission:
    root: Path
    root_identity: tuple[int, int]
    ancestry: tuple[tuple[Path, tuple[int, int]], ...]
    marker_identity: tuple[int, int] | None
    requires_world_traversal: bool = False

    def revalidate(self, ops: FilesystemOps | None = None) -> None:
        fs = ops or OsFilesystemOps()
        current = _inspect_ancestry(
            fs,
            self.root,
            require_world_traversal=self.requires_world_traversal,
        )
        if current != self.ancestry or current[-1][1] != self.root_identity:
            raise ConfigureError("backup_root_changed", "backup_root changed during validation")
        if self.marker_identity is not None:
            if _validate_approval_marker(fs, self.root) != self.marker_identity:
                raise ConfigureError("approval_changed", "approval marker changed during validation")


def admit_backup_root(
    backup_root: str | os.PathLike[str], *, ops: FilesystemOps | None = None
) -> RootAdmission:
    """Admit a root without mutating it; mutation requires a later recheck."""
    fs = ops or OsFilesystemOps()
    path = _path(backup_root)
    if any(
        path == blocked or (blocked != Path("/") and path.is_relative_to(blocked))
        for blocked in BLOCKED_BACKUP_ROOTS
    ):
        raise ConfigureError("invalid_backup_root", "this system path cannot be a backup root")
    requires_world_traversal = path != DEFAULT_BACKUP_ROOT
    ancestry = _inspect_ancestry(
        fs,
        path,
        require_world_traversal=requires_world_traversal,
    )
    marker_identity = None
    if requires_world_traversal:
        marker_identity = _validate_approval_marker(fs, path)
    return RootAdmission(path, ancestry[-1][1], ancestry, marker_identity, requires_world_traversal)


def prepare_backup_root(
    backup_root: str | os.PathLike[str],
    *,
    ops: FilesystemOps | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> RootAdmission:
    """Admit a backup root, creating only the fixed default ``/backup`` if absent.

    Custom roots are never created implicitly: they must already satisfy the
    explicit approval-marker contract.  Automatic creation is intentionally
    restricted to ``DEFAULT_BACKUP_ROOT`` so the privileged helper cannot be
    abused as a general root-owned directory creator.
    """
    fs = ops or OsFilesystemOps()
    path = _path(backup_root)
    try:
        return admit_backup_root(path, ops=fs)
    except ConfigureError as exc:
        if path != DEFAULT_BACKUP_ROOT or exc.code != "invalid_backup_root":
            raise
        # Admission can fail for several unsafe reasons.  Only a genuinely
        # absent fixed /backup is eligible for automatic creation.
        try:
            _lstat(fs, path)
        except FileNotFoundError:
            pass
        except OSError as inspect_exc:
            raise ConfigureError("invalid_backup_root", "backup_root cannot be inspected") from inspect_exc
        else:
            raise exc

    # The default is a single fixed child of an already-trusted parent.
    # Revalidate that parent immediately before mkdir, then run ordinary
    # admission over the resulting object.
    _inspect_ancestry(fs, path.parent)
    _checkpoint(checkpoint)
    try:
        fs.mkdir(path, BACKUP_ROOT_MODE)
    except FileExistsError:
        # A concurrent creator won the race; normal admission below decides
        # whether the resulting object is safe.
        pass
    except OSError as exc:
        raise ConfigureError("provisioning_failed", "could not create default backup_root") from exc
    else:
        _chmod(fs, path, BACKUP_ROOT_MODE, checkpoint=checkpoint)
    return admit_backup_root(path, ops=fs)


def validate_backup_root(
    backup_root: str | os.PathLike[str], *, ops: FilesystemOps | None = None
) -> Path:
    """Compatibility wrapper returning an admitted, non-mutated root path."""
    return admit_backup_root(backup_root, ops=ops).root


def _existing_directory(
    fs: FilesystemOps,
    path: Path,
    *,
    owner_uid: int,
    mode: int,
    label: str,
    reject_writable: bool = False,
    checkpoint: Callable[[], None] | None = None,
) -> None:
    try:
        info = _lstat(fs, path)
    except FileNotFoundError as exc:
        raise ConfigureError("provisioning_failed", f"{label} disappeared during provisioning") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ConfigureError("unsafe_existing_path", f"{label} is not a directory")
    if info.st_uid != owner_uid:
        raise ConfigureError("unsafe_existing_path", f"{label} has the wrong owner")
    if reject_writable and info.st_mode & 0o022:
        raise ConfigureError("unsafe_existing_path", f"{label} is writable by group or others")
    if (info.st_mode & 0o7777) != mode:
        _chmod(fs, path, mode, checkpoint=checkpoint)


def _ensure_directory(
    fs: FilesystemOps,
    path: Path,
    *,
    owner_uid: int,
    mode: int,
    label: str,
    chown_new: bool,
    reject_writable: bool = False,
    checkpoint: Callable[[], None] | None = None,
) -> None:
    try:
        info = _lstat(fs, path)
    except FileNotFoundError:
        try:
            _checkpoint(checkpoint)
            fs.mkdir(path, mode)
            if chown_new:
                _chown(fs, path, owner_uid, checkpoint=checkpoint)
            _chmod(fs, path, mode, checkpoint=checkpoint)
        except OSError as exc:
            raise ConfigureError("provisioning_failed", f"could not create {label}") from exc
        _existing_directory(
            fs,
            path,
            owner_uid=owner_uid,
            mode=mode,
            label=label,
            reject_writable=reject_writable,
            checkpoint=checkpoint,
        )
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ConfigureError("unsafe_existing_path", f"{label} is not a directory")
    if info.st_uid != owner_uid:
        raise ConfigureError("unsafe_existing_path", f"{label} has the wrong owner")
    if reject_writable and info.st_mode & 0o022:
        raise ConfigureError("unsafe_existing_path", f"{label} is writable by group or others")
    if (info.st_mode & 0o7777) != mode:
        _chmod(fs, path, mode, checkpoint=checkpoint)


def _preflight_directory(
    fs: FilesystemOps,
    path: Path,
    *,
    owner_uid: int,
    label: str,
    reject_writable: bool = False,
) -> None:
    """Validate existing provisioning targets before the first mutation."""
    try:
        info = _lstat(fs, path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ConfigureError("provisioning_failed", f"could not inspect {label}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ConfigureError("unsafe_existing_path", f"{label} is not a directory")
    if info.st_uid != owner_uid:
        raise ConfigureError("unsafe_existing_path", f"{label} has the wrong owner")
    if reject_writable and info.st_mode & 0o022:
        raise ConfigureError("unsafe_existing_path", f"{label} is writable by group or others")


def _preflight_provision(fs: FilesystemOps, paths: GuiPaths) -> None:
    _preflight_directory(
        fs,
        paths.internal,
        owner_uid=0,
        label=".ubackup",
        reject_writable=True,
    )
    _preflight_directory(
        fs,
        paths.users,
        owner_uid=0,
        label=".ubackup/users",
        reject_writable=True,
    )
    for directory in paths.directories():
        _preflight_directory(
            fs,
            directory,
            owner_uid=paths.uid,
            label=str(directory),
        )


def provision_user_runtime(
    backup_root: str | os.PathLike[str],
    uid: int,
    *,
    ops: FilesystemOps | None = None,
    admission: RootAdmission | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> GuiPaths:
    """Create only the requested user's private GUI runtime tree.

    ``.ubackup`` and ``.ubackup/users`` are root-owned execute-only parents.
    They are allowed to be adjusted from an older 0700 layout so a user can
    reach its own leaf, but no existing repository/state directory is touched.
    """
    if not is_valid_user_uid(uid):
        raise ConfigureError("invalid_caller_uid", "invalid caller UID")
    fs = ops or OsFilesystemOps()
    if admission is None:
        admission = prepare_backup_root(backup_root, ops=fs, checkpoint=checkpoint)
    elif admission.root != _path(backup_root):
        raise ConfigureError("backup_root_changed", "admitted backup_root does not match request")
    paths = GuiPaths.for_user(admission.root, uid)
    _preflight_provision(fs, paths)

    # This is the first mutation.  The identity/ancestry check is deliberately
    # adjacent to it so a replacement of the approved root is rejected first.
    admission.revalidate(fs)
    _chmod(fs, admission.root, BACKUP_ROOT_MODE, checkpoint=checkpoint)

    # These are the only root-owned parents whose mode may be normalized.  A
    # user cannot list their contents, but execute permission reaches the leaf.
    _ensure_directory(
        fs,
        paths.internal,
        owner_uid=0,
        mode=ROOT_PARENT_MODE,
        label=".ubackup",
        chown_new=False,
        reject_writable=True,
        checkpoint=checkpoint,
    )
    _ensure_directory(
        fs,
        paths.users,
        owner_uid=0,
        mode=ROOT_PARENT_MODE,
        label=".ubackup/users",
        chown_new=False,
        reject_writable=True,
        checkpoint=checkpoint,
    )

    # All remaining directories belong to this UID.  No recursive operation is
    # used, so existing repository or privileged state cannot be re-owned.
    for directory in paths.directories():
        _checkpoint(checkpoint)
        _ensure_directory(
            fs,
            directory,
            owner_uid=uid,
            mode=USER_DIRECTORY_MODE,
            label=str(directory.relative_to(admission.root)),
            chown_new=True,
            checkpoint=checkpoint,
        )
    return paths


# Explicit aliases keep the operation name readable at call sites and make
# the provisioning seam convenient to exercise without invoking pkexec.
provision_user_paths = provision_user_runtime
provision_gui_paths = provision_user_runtime


def configure_request(
    request: ConfigureRequest,
    *,
    environment: Mapping[str, str] | None = None,
    ops: FilesystemOps | None = None,
    effective_uid: int | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> GuiPaths:
    if request.operation != CONFIGURE_OPERATION:
        raise ConfigureError("operation_mismatch", "operation does not match configure helper")
    if effective_uid is None:
        effective_uid = os.geteuid()
    if isinstance(effective_uid, bool) or effective_uid != 0:
        raise ConfigureError("not_root", "configure helper must run as root")
    uid = validated_pkexec_uid(environment)
    _checkpoint(checkpoint)
    return provision_user_runtime(request.backup_root, uid, ops=ops, checkpoint=checkpoint)


def handle_request(
    raw: bytes | bytearray | memoryview | str,
    *,
    environment: Mapping[str, str] | None = None,
    ops: FilesystemOps | None = None,
    effective_uid: int | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> bytes:
    try:
        request = decode_request(raw, expected_operation=CONFIGURE_OPERATION)
    except ProtocolError as exc:
        return error_response(CONFIGURE_OPERATION, exc.code, exc.message)
    try:
        paths = configure_request(
            request,
            environment=environment,
            ops=ops,
            effective_uid=effective_uid,
            checkpoint=checkpoint,
        )
    except ConfigureError as exc:
        return error_response(CONFIGURE_OPERATION, exc.code, exc.message)
    except OSError:
        # Never let a filesystem failure escape the one-shot helper as a
        # traceback.  error_response bounds the serialized message.
        return error_response(CONFIGURE_OPERATION, "filesystem_error", "filesystem operation failed")
    return success_response(CONFIGURE_OPERATION, paths.uid, str(paths.user_root))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        response = error_response(
            CONFIGURE_OPERATION,
            "unexpected_arguments",
            "configure helper does not accept command-line arguments",
        )
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 64
    try:
        # Keep stdin open after the initial request.  The broker's framed
        # cancel/EOF control is observed while provisioning is in progress.
        from ubackup.privileged.runtime import (
            Phase2Error,
            _ControlMonitor,
            ensure_not_cancelled,
            install_cancellation_handler,
            reset_cancellation,
        )

        install_cancellation_handler()
        reset_cancellation()
        fd = sys.stdin.buffer.fileno()
        raw = read_frame_fd(fd, limit=MAX_REQUEST_BYTES)
        if raw is None:
            raise ProtocolError("malformed_frame", "initial request frame is missing")
        monitor = _ControlMonitor(fd, deadline=time.monotonic() + CONFIGURE_DEADLINE_SECONDS)
        monitor.start()
        try:
            response = handle_request(raw, checkpoint=ensure_not_cancelled)
        finally:
            monitor.close()
    except Exception as exc:
        if isinstance(exc, (ProtocolError, ConfigureError)) or hasattr(exc, "code"):
            response = error_response(
                CONFIGURE_OPERATION,
                getattr(exc, "code", "protocol_error"),
                getattr(exc, "message", "configure operation failed"),
            )
        elif isinstance(exc, OSError):
            response = error_response(CONFIGURE_OPERATION, "filesystem_error", "filesystem operation failed")
        else:
            response = error_response(CONFIGURE_OPERATION, "internal_error", "configure operation failed")
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
