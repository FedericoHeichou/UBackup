from __future__ import annotations

"""Small common I/O boundary for fixed Phase 2 helper entrypoints.

This is not a command dispatcher.  Each executable supplies its own constant
operation, payload validator, and handler; the caller cannot select any of
those values through stdin or argv.
"""

import ctypes
import os
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from .configure import ConfigureError, FilesystemOps, validated_pkexec_uid
from .protocol import (
    ERROR_REQUEST_ID,
    FRAME_HEADER_BYTES,
    MAX_CONTROL_FRAME_BYTES,
    MAX_PHASE2_REQUEST_BYTES,
    PHASE2_OPERATIONS,
    Phase2Request,
    ProtocolError,
    decode_control_frame,
    decode_phase2_request,
    phase2_error_response,
    phase2_success_response,
    read_frame_fd,
)


class Phase2Error(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class ChildProcessError(RuntimeError):
    """A bounded child deadline/cancellation that must never become success."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


_child_group_lock = threading.RLock()
_active_child_group: int | None = None
_cancellation_requested = False
_cancellation_code = "cancelled"
CHILD_GRACE_SECONDS = 2.0
CONTROL_POLL_SECONDS = 0.1

# These deadlines are enforced by the helper itself.  The broker has a
# separate local timeout, but it is not the authority that stops root work.
ACTION_DEADLINES = {
    "inspect": 1800.0,
    "backup": 3600.0,
    "restore-staging": 1800.0,
    "restore-inplace": 1800.0,
    "packages-install": 1800.0,
}
INSPECTION_DEADLINES = {
    "config-inventory": 900.0,
    "package-inventory": 300.0,
    "snapshots": 300.0,
    "snapshot-stats": 300.0,
    "snapshot-directory": 900.0,
    "metadata": 900.0,
    "filesystem-children": 300.0,
    "filesystem-size": 1800.0,
    "filesystem-cache": 300.0,
    "staging-children": 300.0,
}


def _terminate_registered_child(process: Any, pgid: int) -> None:
    """Stop and reap a child whose group was registered after cancellation.

    The cancellation handler can run between ``Popen`` and registration.  A
    registration therefore has to close that small window itself rather than
    relying on the signal handler having seen the group.
    """
    try:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        if process is not None:
            try:
                process.wait(timeout=CHILD_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            else:
                # The leader may have exited while a descendant still owns a
                # pipe.  Do not leave that descendant behind.
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        else:
            # A caller that only has a pgid can still reap direct children
            # with waitpid.  Production launchers pass the Popen object so
            # that the bounded wait below can be used.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while True:
                try:
                    os.waitpid(-pgid, 0)
                except ChildProcessError:
                    break
                except InterruptedError:
                    continue
    finally:
        unregister_child_group(pgid)


def register_child_group(pgid: int, process: Any | None = None) -> None:
    global _active_child_group
    if pgid <= 0 or pgid == os.getpgrp():
        raise ChildProcessError("internal_error", "child process group is not isolated")
    with _child_group_lock:
        if _active_child_group is not None:
            raise ChildProcessError("internal_error", "another child process is active")
        _active_child_group = pgid
        already_cancelled = _cancellation_requested
    if already_cancelled:
        _terminate_registered_child(process, pgid)
        raise ChildProcessError("cancelled", "child process cancelled before registration")


def unregister_child_group(pgid: int) -> None:
    global _active_child_group
    with _child_group_lock:
        if _active_child_group == pgid:
            _active_child_group = None


def _cancellation_handler(_signum: int, _frame: Any) -> None:
    request_cancellation("cancelled")


def install_cancellation_handler() -> None:
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _cancellation_handler)
        signal.signal(signal.SIGINT, _cancellation_handler)


def reset_cancellation() -> None:
    global _cancellation_requested, _cancellation_code, _active_child_group
    with _child_group_lock:
        _cancellation_requested = False
        _cancellation_code = "cancelled"
        _active_child_group = None


def request_cancellation(code: str = "cancelled") -> None:
    """Cancel the action and TERM the one known child process group."""
    global _cancellation_requested, _cancellation_code
    if code not in {"cancelled", "timeout", "protocol_error"}:
        code = "cancelled"
    with _child_group_lock:
        _cancellation_requested = True
        # A malformed/additional control frame must not be hidden by a later
        # EOF or ordinary cancel event.
        if _cancellation_code == "cancelled" or code == "protocol_error":
            _cancellation_code = code
        pgid = _active_child_group
    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def cancellation_requested() -> bool:
    return _cancellation_requested


def ensure_not_cancelled() -> None:
    if _cancellation_requested:
        raise Phase2Error(_cancellation_code, "privileged operation was cancelled")



def command_as_uid(command: list[str], uid: int) -> list[str]:
    """Return a fixed-argv setpriv wrapper for one unprivileged child command.

    The privileged helper may need to inspect or restore per-user package
    stores. Do not perform uid/gid changes in Python ``preexec_fn``: the helper
    owns monitor threads, and libc/account-database work after fork is unsafe in
    a multithreaded process. ``setpriv`` performs the transition after exec.
    """
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise ValueError("uid must be a non-negative integer")
    if uid == os.geteuid():
        return list(command)
    if os.geteuid() != 0:
        raise PermissionError("cannot change child uid without root privileges")
    import pwd
    account = pwd.getpwuid(uid)
    setpriv = "/usr/bin/setpriv"
    try:
        info = os.lstat(setpriv)
    except OSError as exc:
        raise RuntimeError("trusted /usr/bin/setpriv is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0 or info.st_mode & 0o022
    ):
        raise RuntimeError("trusted /usr/bin/setpriv is unavailable")
    return [
        setpriv, f"--reuid={uid}", f"--regid={account.pw_gid}",
        "--init-groups", "--", *command,
    ]

def child_process_preexec() -> Callable[[], None] | None:
    """Couple a helper child to its Linux parent.

    ``start_new_session`` and helper-owned group termination are the primary
    whole-tree cancellation mechanism.  ``PR_SET_PDEATHSIG`` is only
    defensive coupling for the case where the helper itself disappears; it is
    not a substitute for terminating the known process group.
    """
    if sys.platform != "linux":
        return None
    parent_pid = os.getpid()

    def setup() -> None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            prctl = libc.prctl
            prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            prctl.restype = ctypes.c_int
            # Linux PR_SET_PDEATHSIG = 1.
            if prctl(1, int(signal.SIGKILL), 0, 0, 0) != 0:
                os._exit(127)
            if os.getppid() != parent_pid:
                os.kill(os.getpid(), signal.SIGKILL)
        except BaseException:
            # A child that could not install the lifetime coupling must not
            # continue into the privileged operation.
            os._exit(127)

    return setup


def _terminate_process_group(process: Any, pgid: int) -> None:
    """TERM, bounded-wait, KILL, and reap one registered child group."""
    try:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=CHILD_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        else:
            # The leader can exit while a normal descendant still owns a pipe.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        unregister_child_group(pgid)


def run_cancellable_subprocess(
    command: list[str],
    env: Mapping[str, str],
    *,
    timeout: float,
    checkpoint: Callable[[], None] | None = None,
    output_limit: int = 8 * 1024 * 1024,
) -> subprocess.CompletedProcess[str]:
    """Run scanner/tool work with the same child-group contract as Restic."""
    if checkpoint is not None:
        checkpoint()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env=dict(env),
        start_new_session=True,
        preexec_fn=child_process_preexec(),
    )
    pgid = os.getpgid(process.pid)
    try:
        register_child_group(pgid, process)
    except BaseException:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise

    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    overflow = {"stdout": False, "stderr": False}

    def drain(stream: Any, buffer: bytearray, name: str) -> None:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            remaining = max(0, output_limit - len(buffer))
            if remaining:
                buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow[name] = True

    stdout_thread = threading.Thread(
        target=drain, args=(process.stdout, stdout_buffer, "stdout"), daemon=True
    )
    stderr_thread = threading.Thread(
        target=drain, args=(process.stderr, stderr_buffer, "stderr"), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + timeout
    try:
        while True:
            if checkpoint is not None:
                checkpoint()
            if cancellation_requested():
                code = _cancellation_code
                _terminate_process_group(process, pgid)
                raise ChildProcessError(code, f"child process {code}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process, pgid)
                raise ChildProcessError("timeout", "child process timeout")
            try:
                process.wait(timeout=min(CONTROL_POLL_SECONDS, remaining))
            except subprocess.TimeoutExpired:
                continue
            if cancellation_requested():
                code = _cancellation_code
                _terminate_process_group(process, pgid)
                raise ChildProcessError(code, f"child process {code}")
            break
    except BaseException:
        if process.poll() is None:
            _terminate_process_group(process, pgid)
        else:
            unregister_child_group(pgid)
        raise
    finally:
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        unregister_child_group(pgid)
    if overflow["stdout"] or overflow["stderr"]:
        raise Phase2Error("output_too_large", "scanner command output exceeds its internal limit")
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        bytes(stdout_buffer).decode("utf-8", "replace"),
        bytes(stderr_buffer).decode("utf-8", "replace"),
    )


class _ControlMonitor:
    """Poll the retained helper stdin for exactly one control protocol."""

    def __init__(self, fd: int, *, deadline: float):
        self.fd = fd
        self.deadline = deadline
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="ubackup-control", daemon=True)
        self._old_blocking: bool | None = None

    def start(self) -> None:
        # The monitor needs non-blocking reads, but callers may reuse the same
        # authenticated pipe afterwards (the persistent startup helper does).
        # Always restore the descriptor mode in close().
        self._old_blocking = os.get_blocking(self.fd)
        os.set_blocking(self.fd, False)
        self.thread.start()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=CONTROL_POLL_SECONDS * 3)
        if self._old_blocking is not None:
            try:
                os.set_blocking(self.fd, self._old_blocking)
            except OSError:
                pass
            self._old_blocking = None

    def _run(self) -> None:
        poller = selectors.DefaultSelector()
        buffer = bytearray()
        seen_control = False
        try:
            poller.register(self.fd, selectors.EVENT_READ)
            while not self.stop.is_set():
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    request_cancellation("timeout")
                    return
                events = poller.select(timeout=min(CONTROL_POLL_SECONDS, remaining))
                if not events:
                    continue
                eof = False
                try:
                    while True:
                        try:
                            chunk = os.read(self.fd, 65536)
                        except BlockingIOError:
                            break
                        except InterruptedError:
                            continue
                        except OSError:
                            request_cancellation("protocol_error")
                            return
                        if not chunk:
                            eof = True
                            break
                        buffer.extend(chunk)
                        if len(buffer) > FRAME_HEADER_BYTES + MAX_CONTROL_FRAME_BYTES:
                            request_cancellation("protocol_error")
                            return
                finally:
                    # HUP is reported together with readable bytes on pipes;
                    # parse those bytes before treating EOF as cancellation.
                    pass

                while buffer:
                    if len(buffer) < FRAME_HEADER_BYTES:
                        if eof:
                            request_cancellation("protocol_error")
                            return
                        break
                    length = int.from_bytes(buffer[:FRAME_HEADER_BYTES], "big")
                    if length <= 0 or length > MAX_CONTROL_FRAME_BYTES:
                        request_cancellation("protocol_error")
                        return
                    total = FRAME_HEADER_BYTES + length
                    if len(buffer) < total:
                        if eof:
                            request_cancellation("protocol_error")
                            return
                        break
                    payload = bytes(buffer[FRAME_HEADER_BYTES:total])
                    del buffer[:total]
                    if seen_control:
                        request_cancellation("protocol_error")
                        return
                    seen_control = True
                    try:
                        decode_control_frame(payload)
                    except ProtocolError:
                        request_cancellation("protocol_error")
                        return
                    request_cancellation("cancelled")
                if eof:
                    request_cancellation("cancelled")
                    return
        finally:
            try:
                poller.unregister(self.fd)
            except Exception:
                pass


PayloadValidator = Callable[[Mapping[str, Any]], dict[str, Any]]
Handler = Callable[[Phase2Request, int, Mapping[str, str], FilesystemOps | None], dict[str, Any] | list[Any]]


def phase2_identity(
    environment: Mapping[str, str] | None = None,
    effective_uid: int | None = None,
) -> int:
    euid = os.geteuid() if effective_uid is None else effective_uid
    if isinstance(euid, bool) or euid != 0:
        raise Phase2Error("not_root", "privileged helper must run as root")
    try:
        return validated_pkexec_uid(environment)
    except ConfigureError as exc:
        raise Phase2Error(exc.code, exc.message) from exc


def _bounded_request(raw: bytes) -> bytes:
    if len(raw) > MAX_PHASE2_REQUEST_BYTES + FRAME_HEADER_BYTES:
        raise ProtocolError("message_too_large", "phase 2 request exceeds protocol limit")
    return raw


def handle_fixed_request(
    raw: bytes,
    *,
    operation: str,
    payload_validator: PayloadValidator,
    handler: Handler,
    environment: Mapping[str, str] | None = None,
    effective_uid: int | None = None,
    ops: FilesystemOps | None = None,
) -> bytes:
    if operation not in PHASE2_OPERATIONS:
        return phase2_error_response(ERROR_REQUEST_ID, operation, "unknown_operation", "unknown helper operation")
    request_id = ERROR_REQUEST_ID
    try:
        request = decode_phase2_request(_bounded_request(raw), expected_operation=operation)
        request_id = request.request_id
        payload = payload_validator(request.payload)
        request = Phase2Request(
            request.version,
            request.request_id,
            request.operation,
            request.backup_root,
            payload,
        )
        uid = phase2_identity(environment, effective_uid)
        ensure_not_cancelled()
        result = handler(request, uid, environment or os.environ, ops)
        ensure_not_cancelled()
        response = phase2_success_response(request.request_id, operation, uid, result)
        ensure_not_cancelled()
        return response
    except ProtocolError as exc:
        return phase2_error_response(request_id, operation, exc.code, exc.message)
    except Phase2Error as exc:
        return phase2_error_response(request_id, operation, exc.code, exc.message)
    except ChildProcessError as exc:
        return phase2_error_response(request_id, operation, exc.code, exc.message)
    except ConfigureError as exc:
        return phase2_error_response(request_id, operation, exc.code, exc.message)
    except OSError:
        return phase2_error_response(request_id, operation, "filesystem_error", "filesystem operation failed")
    except Exception:
        # Never expose exception text: it may contain a path or credential.
        return phase2_error_response(request_id, operation, "internal_error", "privileged operation failed")


def run_fixed_helper(
    argv: list[str],
    *,
    operation: str,
    payload_validator: PayloadValidator,
    handler: Handler,
    action_deadline: float | None = None,
) -> int:
    if argv:
        response = phase2_error_response(
            ERROR_REQUEST_ID,
            operation,
            "unexpected_arguments",
            "helper does not accept command-line arguments",
        )
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 64
    try:
        install_cancellation_handler()
        reset_cancellation()
        fd = sys.stdin.buffer.fileno()
        raw = read_frame_fd(fd, limit=MAX_PHASE2_REQUEST_BYTES)
        if raw is None:
            raise ProtocolError("malformed_frame", "initial request frame is missing")
        initial_request = decode_phase2_request(raw, expected_operation=operation)
        seconds = action_deadline
        if seconds is None:
            seconds = ACTION_DEADLINES.get(operation, 1800.0)
            if operation == "inspect":
                seconds = INSPECTION_DEADLINES.get(
                    str(initial_request.payload.get("kind")), seconds
                )
        monitor = _ControlMonitor(fd, deadline=time.monotonic() + max(0.001, seconds))
        monitor.start()
        try:
            response = handle_fixed_request(
                raw,
                operation=operation,
                payload_validator=payload_validator,
                handler=handler,
                environment=os.environ,
            )
        finally:
            monitor.close()
    except (OSError, ProtocolError) as exc:
        code = exc.code if isinstance(exc, ProtocolError) else "io_error"
        response = phase2_error_response(
            ERROR_REQUEST_ID,
            operation,
            code,
            exc.message if isinstance(exc, ProtocolError) else "helper input/output failed",
        )
    sys.stdout.buffer.write(response)
    sys.stdout.buffer.flush()
    return 0
