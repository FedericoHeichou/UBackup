from __future__ import annotations

"""Authenticated root helper retained for one UBackup GUI session.

Startup provisioning and inventory happen once after Polkit authorization. The
process then serves only the fixed typed privileged operation allow-list over
the inherited private pipe; it is never a general command executor.
"""

import os
import select
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping

if __name__ == "__main__" and __package__ in {None, ""}:
    sys.path.insert(0, "/usr/lib/ubackup")

from ubackup.cache import CacheDB
from ubackup.paths import PrivilegedPaths
from ubackup.system_scan import cached_config_inventory, cached_package_inventory
from ubackup.privileged.configure import ConfigureError, prepare_backup_root, provision_user_runtime, validated_pkexec_uid
from ubackup.privileged.credentials import credentialed_engine
from ubackup.privileged.inspect import (
    KIND_FS_CHILDREN, KIND_SNAPSHOTS, KIND_STATS, KIND_DIRECTORY, KIND_METADATA,
    _children, validate_inspect_payload, handle_inspect,
)
from ubackup.privileged.filesystem_navigation import admitted_children
from ubackup.privileged.protocol import (
    PROTOCOL_VERSION, INSPECT_OPERATION, BACKUP_OPERATION, RESTORE_STAGING_OPERATION,
    RESTORE_INPLACE_OPERATION, PACKAGES_INSTALL_OPERATION, MAINTENANCE_OPERATION, Phase2Request,
    MAX_REQUEST_BYTES, MAX_STARTUP_COMMAND_BYTES, MAX_STARTUP_FRAME_BYTES, MAX_NAVIGATION_REQUEST_BYTES,
    MAX_SESSION_REQUEST_BYTES, MAX_SESSION_REQUEST_ASSEMBLED_BYTES, ProtocolError,
    decode_startup_command, decode_startup_request, read_frame_fd_deadline,
    decode_control_frame,
    startup_error_frame, startup_progress_frame, startup_ready_response, startup_done_frame,
    navigation_ready_frame, navigation_result_frame, navigation_error_frame,
    decode_navigation_request, decode_session_request, decode_session_request_chunk, session_success_frames, session_error_frame, session_progress_frame,
    read_frame_fd, write_frame_fd_deadline,
)
from ubackup.privileged.runtime import (
    _ControlMonitor, Phase2Error, cancellation_requested, ensure_not_cancelled, install_cancellation_handler,
    reset_cancellation,
)
from ubackup.privileged.validation import validate_credentials
from ubackup.privileged.backup import validate_backup_payload_for_root, handle_backup
from ubackup.privileged.restore import (
    validate_staging_payload, validate_inplace_payload, validate_packages_payload,
    handle_restore_staging, handle_restore_inplace, handle_packages_install,
)
from ubackup.privileged.maintenance import validate_maintenance_payload, handle_maintenance
from ubackup.privileged.runtime import ChildProcessError

STARTUP_AUTH_READY_SECONDS = 120.0
STARTUP_START_WAIT_SECONDS = 900.0
STARTUP_PLAN_SECONDS = 900.0
NAVIGATION_REQUEST_SECONDS = 30.0
NAVIGATION_IDLE_SECONDS = 120.0
NAVIGATION_HARD_LIFETIME_SECONDS = 1800.0
PAGE_SIZE = 500


def _send(fd: int, frame: bytes, deadline: float) -> None:
    write_frame_fd_deadline(fd, frame, deadline=deadline, cancelled=cancellation_requested)


def _send_terminal(fd: int, frame: bytes) -> None:
    # Terminal cancellation/error frames must still be writable after the
    # cancellation flag is raised; the short cleanup budget is independent.
    write_frame_fd_deadline(fd, frame, deadline=time.monotonic() + 1.0, cancelled=None)


def _emit(fd: int, section: str, records: list[Any], request_id: str, deadline: float, *, offset: int = 0) -> None:
    """Emit bounded pages, including an explicit empty/final page."""
    if not records:
        _send(fd, startup_progress_frame(section, [], offset, None, True, request_id), deadline)
        return
    index = 0
    while index < len(records):
        page: list[Any] = []
        while index + len(page) < len(records) and len(page) < PAGE_SIZE:
            candidate = page + [records[index + len(page)]]
            try:
                startup_progress_frame(section, candidate, offset + index,
                                       offset + index + len(candidate), False, request_id)
            except ProtocolError:
                if not page:
                    raise ProtocolError("response_too_large", "startup record exceeds frame limit")
                break
            page = candidate
        next_offset = offset + index + len(page)
        final = next_offset >= offset + len(records)
        _send(fd, startup_progress_frame(section, page, offset + index, None if final else next_offset,
                                          final, request_id), deadline)
        ensure_not_cancelled()
        index += len(page)


def _emit_root(fd: int, request_id: str, deadline: float, paths: PrivilegedPaths) -> None:
    # Startup cannot know the GUI's current exclusion profile, so it emits only
    # directory metadata. The GUI immediately performs a hidden profile-aware
    # cache refresh once the authenticated session is ready.
    offset = 0
    from ubackup.restic_engine import MAX_DIRECTORY_NODES
    while True:
        if offset >= MAX_DIRECTORY_NODES:
            _send(fd, startup_progress_frame(KIND_FS_CHILDREN, [], offset, None, True, request_id, True), deadline)
            return
        limit = min(PAGE_SIZE, MAX_DIRECTORY_NODES - offset)
        records = _children(Path("/"), limit, offset, probe=True)
        truncated = len(records) > PAGE_SIZE
        records = records[:PAGE_SIZE]
        capped = offset + len(records) >= MAX_DIRECTORY_NODES and truncated
        final = not truncated or capped
        _send(fd, startup_progress_frame(KIND_FS_CHILDREN, records, offset,
                                          None if final else offset + len(records), final, request_id, capped), deadline)
        ensure_not_cancelled()
        if final:
            return
        offset += len(records)


def _repository_initialized(paths: PrivilegedPaths, *, expected_uid: int = 0) -> bool:
    """Return whether any domain repository already exists and is trusted.

    UBackup uses one password for three independent Restic repositories.  A
    clean installation therefore needs password confirmation only while none
    of the domain repositories exist.  If one or more already exist, every
    existing config must still satisfy the root-owned/trusted invariant.
    Missing domain repositories are initialized lazily with the same password.
    """
    legacy_repository = paths.root / "repository"
    if legacy_repository.exists() or legacy_repository.is_symlink():
        raise ConfigureError(
            "legacy_repository_layout",
            "Old single-repository layout detected. Reset the backup root before using the three-repository architecture.",
        )
    found = False
    for component in ("filesystem", "configs", "packages"):
        config = paths.for_component(component).repository / "config"
        try:
            info = os.lstat(config)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ConfigureError("invalid_repository", "Restic repository config cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022:
            raise ConfigureError("invalid_repository", "Restic repository config is not a trusted root-owned file")
        found = True
    return found


def run_plan(fd: int, admission, uid: int, credentials: Mapping[str, Any], request_id: str, deadline: float) -> None:
    # The admission is retained across provisioning and rechecked immediately
    # before deriving paths or changing the helper environment.
    admission.revalidate()
    paths = PrivilegedPaths.for_root(admission.root)
    env = paths.prepare_environment(dict(os.environ))
    paths.cleanup_stale_request_artifacts(active_request_id=request_id)

    inventory_cache = CacheDB(paths.cache / "system-inventory.sqlite3")
    try:
        _emit_root(fd, request_id, deadline, paths)
        packages = cached_package_inventory(inventory_cache, env, uid)
        _emit(fd, "package-inventory", packages, request_id, deadline)

        configs = cached_config_inventory(
            inventory_cache, env, checkpoint=ensure_not_cancelled
        )
        _emit(fd, "config-inventory", configs, request_id, deadline)
        _send(fd, startup_done_frame(request_id), deadline)
    finally:
        inventory_cache.close()


def _inject_session_credentials(operation: str, payload: Mapping[str, Any], credentials: Mapping[str, Any]) -> dict[str, Any]:
    """Bind Restic credentials to the authenticated session, never to later GUI requests."""
    value = dict(payload)
    if "credentials" in value:
        raise Phase2Error("invalid_credentials", "session requests must not replace startup credentials")
    if operation == INSPECT_OPERATION:
        if value.get("kind") in {KIND_SNAPSHOTS, KIND_STATS, KIND_DIRECTORY, KIND_METADATA}:
            value["credentials"] = dict(credentials)
    elif operation in {BACKUP_OPERATION, RESTORE_STAGING_OPERATION, RESTORE_INPLACE_OPERATION, PACKAGES_INSTALL_OPERATION, MAINTENANCE_OPERATION}:
        value["credentials"] = dict(credentials)
    return value


def _dispatch_session_request(
    admission, uid: int, environment: Mapping[str, str], credentials: Mapping[str, Any],
    request: Mapping[str, Any], progress_cb=None,
):
    operation = request["operation"]
    payload = _inject_session_credentials(operation, request["payload"], credentials)
    if operation == INSPECT_OPERATION:
        validated = validate_inspect_payload(payload)
        handler = handle_inspect
    elif operation == BACKUP_OPERATION:
        validated = validate_backup_payload_for_root(payload, admission.root)
        handler = handle_backup
    elif operation == RESTORE_STAGING_OPERATION:
        validated = validate_staging_payload(payload)
        handler = handle_restore_staging
    elif operation == RESTORE_INPLACE_OPERATION:
        validated = validate_inplace_payload(payload)
        handler = handle_restore_inplace
    elif operation == PACKAGES_INSTALL_OPERATION:
        validated = validate_packages_payload(payload)
        handler = handle_packages_install
    elif operation == MAINTENANCE_OPERATION:
        validated = validate_maintenance_payload(payload)
        handler = handle_maintenance
    else:
        raise Phase2Error("unknown_operation", "session operation is not allowed")
    typed = Phase2Request(PROTOCOL_VERSION, request["request_id"], operation, str(admission.root), validated)
    admission.revalidate()
    ensure_not_cancelled()
    result = handler(typed, uid, environment, None, progress_cb)
    ensure_not_cancelled()
    if not isinstance(result, (dict, list)):
        raise Phase2Error("invalid_result", "privileged operation returned an invalid result")
    return result


SESSION_OPERATION_SECONDS = 3700.0
SESSION_CHUNK_SEQUENCE_SECONDS = 10.0


def _decode_session_request_from_first(fd: int, raw: bytes, session_id: str) -> dict[str, Any]:
    """Decode a regular request or reassemble a strictly ordered chunk sequence.

    Once a chunked request starts, the GUI has a short bounded interval to
    deliver every remaining frame. This prevents a partially written large
    request from pinning the privileged helper indefinitely.
    """
    try:
        return decode_session_request(raw, session_id=session_id)
    except ProtocolError as direct_error:
        try:
            first = decode_session_request_chunk(raw, session_id=session_id)
        except ProtocolError:
            raise direct_error
    if first["index"] != 0:
        raise ProtocolError("invalid_chunk_sequence", "session request chunks must start at index zero")
    request_id = first["request_id"]
    operation = first["operation"]
    count = first["count"]
    chunks = [first["data"]]
    total = len(first["data"])
    deadline = time.monotonic() + SESSION_CHUNK_SEQUENCE_SECONDS
    for expected_index in range(1, count):
        next_raw = read_frame_fd_deadline(
            fd, limit=MAX_SESSION_REQUEST_BYTES, deadline=deadline, allow_eof=False
        )
        assert next_raw is not None
        chunk = decode_session_request_chunk(next_raw, session_id=session_id)
        if (
            chunk["request_id"] != request_id
            or chunk["operation"] != operation
            or chunk["count"] != count
            or chunk["index"] != expected_index
        ):
            raise ProtocolError("invalid_chunk_sequence", "session request chunk sequence does not match")
        total += len(chunk["data"])
        if total > MAX_SESSION_REQUEST_ASSEMBLED_BYTES:
            raise ProtocolError("message_too_large", "assembled session request exceeds the protocol limit")
        chunks.append(chunk["data"])
    return decode_session_request(
        b"".join(chunks), session_id=session_id, limit=MAX_SESSION_REQUEST_ASSEMBLED_BYTES
    )


def run_session(fd: int, out_fd: int, admission, uid: int, credentials: Mapping[str, Any], session_id: str) -> None:
    """Serve the private pipe for the lifetime of the GUI after one Polkit authorization.

    The pipe is inherited only by this pkexec child and its GUI parent.  Requests
    can select only fixed typed operations; arbitrary executables/argv are never
    accepted.
    """
    paths = PrivilegedPaths.for_root(admission.root)
    environment = paths.prepare_environment(dict(os.environ))
    while True:
        raw = read_frame_fd(fd, limit=MAX_SESSION_REQUEST_BYTES, allow_eof=True)
        if raw is None:
            return
        reset_cancellation()
        # Retain the original narrowly-scoped navigation protocol for backward
        # compatibility.  It cannot select an executable or operation.
        try:
            nav = decode_navigation_request(raw, session_id=session_id)
        except ProtocolError:
            nav = None
        if nav is not None:
            try:
                records = admitted_children(admission, nav["path"], nav["limit"], nav["offset"])[0:nav["limit"]]
                frame = navigation_result_frame(session_id, nav["request_id"], records, None, True)
            except (Phase2Error, ConfigureError) as exc:
                frame = navigation_error_frame(session_id, nav["request_id"], getattr(exc, "code", "navigation_error"), getattr(exc, "message", "navigation failed"))
            write_frame_fd_deadline(out_fd, frame, deadline=time.monotonic() + 30.0, cancelled=None)
            continue
        request_id = None
        operation = INSPECT_OPERATION
        monitor: _ControlMonitor | None = None
        try:
            request = _decode_session_request_from_first(fd, raw, session_id)
            request_id = request["request_id"]
            operation = request["operation"]
            # While the root operation is running no second RPC is permitted.
            # The only valid concurrent input is the existing cancel/EOF
            # control channel, so closing the GUI or timing out can still stop
            # privileged child work instead of leaving a detached root task.
            monitor = _ControlMonitor(fd, deadline=time.monotonic() + SESSION_OPERATION_SECONDS)
            monitor.start()

            def progress_cb(value: Mapping[str, Any]) -> None:
                ensure_not_cancelled()
                frame = session_progress_frame(session_id, request_id, operation, value)
                write_frame_fd_deadline(
                    out_fd, frame, deadline=time.monotonic() + 10.0,
                    cancelled=cancellation_requested,
                )

            result = _dispatch_session_request(
                admission, uid, environment, credentials, request, progress_cb
            )
            monitor.close(); monitor = None
            frames = session_success_frames(session_id, request_id, operation, result)
        except (ProtocolError, Phase2Error, ChildProcessError, ConfigureError) as exc:
            if monitor is not None:
                monitor.close(); monitor = None
            if request_id is None:
                # A malformed frame has no trustworthy request identity. End
                # the private session instead of attempting to recover.
                return
            frames = [session_error_frame(
                session_id, request_id, operation, getattr(exc, "code", "operation_failed"),
                getattr(exc, "message", "privileged operation failed"),
            )]
        except Exception:
            if monitor is not None:
                monitor.close(); monitor = None
            if request_id is None:
                return
            frames = [session_error_frame(session_id, request_id, operation, "internal_error", "privileged operation failed")]
        finally:
            if monitor is not None:
                monitor.close()
        for frame in frames:
            write_frame_fd_deadline(out_fd, frame, deadline=time.monotonic() + 30.0, cancelled=None)


def _wait_initial(fd: int, deadline: float) -> bytes:
    return read_frame_fd_deadline(fd, limit=MAX_REQUEST_BYTES, deadline=deadline, allow_eof=False)  # type: ignore[return-value]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        # Launcher argument rejection is deliberately outside the protocol.
        sys.stderr.write("ubackup-startup: arguments are not accepted\n")
        return 64
    install_cancellation_handler(); reset_cancellation()
    deadline = time.monotonic() + STARTUP_AUTH_READY_SECONDS
    out_fd = sys.stdout.buffer.fileno()
    in_fd = sys.stdin.buffer.fileno()
    request_id: str | None = None
    monitor: _ControlMonitor | None = None
    try:
        request = decode_startup_request(_wait_initial(in_fd, deadline))
        request_id = request.request_id
        # From the moment the authenticated request is accepted, cancellation
        # and EOF must be observable while root performs admission/provisioning.
        monitor = _ControlMonitor(in_fd, deadline=deadline)
        monitor.start()
        if os.geteuid() != 0:
            raise ConfigureError("not_root", "startup helper must run as root")
        uid = validated_pkexec_uid()
        # Pause before reading the one start frame so the monitor cannot
        # consume that typed command.
        admission = prepare_backup_root(request.backup_root, checkpoint=ensure_not_cancelled)
        paths = provision_user_runtime(request.backup_root, uid, admission=admission, checkpoint=ensure_not_cancelled)
        monitor.close()
        monitor = None
        _send(
            out_fd,
            startup_ready_response(
                uid,
                str(paths.user_root),
                request_id,
                repository_initialized=_repository_initialized(PrivilegedPaths.for_root(admission.root)),
            ),
            deadline,
        )

        # Exactly one start frame is accepted.  While waiting, EOF/cancel and
        # the global deadline are the only non-start outcomes.
        deadline = time.monotonic() + STARTUP_START_WAIT_SECONDS
        command_raw = read_frame_fd_deadline(in_fd, limit=MAX_STARTUP_COMMAND_BYTES,
                                              deadline=deadline, allow_eof=True)
        if command_raw is None:
            raise ProtocolError("cancelled", "startup client closed the session")
        try:
            command = decode_startup_command(command_raw)
        except ProtocolError:
            if decode_control_frame(command_raw) == "cancel":
                raise ProtocolError("cancelled", "startup client cancelled before start")
            raise
        if command.get("request_id") != request_id:
            raise ProtocolError("request_id_mismatch", "startup command request id does not match")
        credentials = command.get("credentials")
        if not isinstance(credentials, Mapping):
            raise ProtocolError("invalid_credentials", "startup credentials are required")
        # Validate before root filesystem/package/configuration scans.
        credentials = validate_credentials(credentials)

        deadline = time.monotonic() + STARTUP_PLAN_SECONDS
        monitor = _ControlMonitor(in_fd, deadline=deadline)
        monitor.start()
        run_plan(out_fd, admission, uid, credentials, request_id, deadline)
        monitor.close(); monitor = None
        _send(out_fd, navigation_ready_frame(request_id), time.monotonic() + 5.0)
        # Credentials are now bound to this private authenticated helper session.
        # Subsequent GUI operations reuse this process and therefore do not invoke
        # pkexec or Polkit again.
        run_session(in_fd, out_fd, admission, uid, credentials, request_id)
        return 0
    except Exception as exc:
        if request_id is not None:
            try:
                _send_terminal(out_fd, startup_error_frame(request_id, getattr(exc, "code", "startup_failed"),
                                                            getattr(exc, "message", "startup operation failed")))
            except Exception:
                pass
        return 0
    finally:
        if monitor is not None:
            monitor.close()


if __name__ == "__main__":
    raise SystemExit(main())
