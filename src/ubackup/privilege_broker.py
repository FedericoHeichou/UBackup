from __future__ import annotations

"""Privilege boundary for the unprivileged GUI.

A single startup helper is authorized through pkexec and retained on a private
pipe for the lifetime of the GUI.  The session accepts only typed, allow-listed
operations; standalone fixed helpers remain available for tests/maintenance but
the GUI never re-invokes pkexec after startup.
"""

import os
import selectors
import select
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from .paths import GuiPaths
from .privileged.runtime import CHILD_GRACE_SECONDS
from .privileged.protocol import (
    CONFIGURE_OPERATION,
    STARTUP_OPERATION,
    BACKUP_OPERATION,
    INSPECT_OPERATION,
    MAX_RESPONSE_BYTES,
    MAX_PHASE2_RESPONSE_BYTES,
    PACKAGES_INSTALL_OPERATION,
    RESTORE_INPLACE_OPERATION,
    RESTORE_STAGING_OPERATION,
    HelperResponse,
    ProtocolError,
    Phase2Response,
    encode_cancel_frame,
    encode_phase2_request_frame,
    decode_phase2_response,
    decode_response,
    StartupFrameParser,
    encode_startup_request_frame_with_id,
    startup_start_frame,
    encode_navigation_request_frame,
    MAX_SESSION_RESPONSE_BYTES, MAX_SESSION_RESPONSE_ASSEMBLED_BYTES, encode_session_request_frames, decode_session_response, decode_session_message,
    read_frame_fd_deadline,
    encode_request_frame,
)


PKEXEC_EXECUTABLE = "/usr/bin/pkexec"
ALLOWED_HELPERS = MappingProxyType(
    {
        CONFIGURE_OPERATION: "/usr/libexec/ubackup-configure",
        STARTUP_OPERATION: "/usr/libexec/ubackup-startup",
        INSPECT_OPERATION: "/usr/libexec/ubackup-inspect",
        BACKUP_OPERATION: "/usr/libexec/ubackup-backup",
        RESTORE_STAGING_OPERATION: "/usr/libexec/ubackup-restore-staging",
        RESTORE_INPLACE_OPERATION: "/usr/libexec/ubackup-restore-inplace",
        PACKAGES_INSTALL_OPERATION: "/usr/libexec/ubackup-packages-install",
    }
)
ALLOWED_OPERATIONS = ALLOWED_HELPERS
BROKER_TIMEOUT_SECONDS = 60.0
MAX_SUBPROCESS_DIAGNOSTIC_BYTES = 8192
# This is an explicit cleanup budget, not an unexplained signal grace.  The
# helper needs time to stop/reap its child, join pipe readers, remove its
# request-private plan/credential, and serialize the structured outcome.
BROKER_CHILD_TERMINATION_BUDGET_SECONDS = CHILD_GRACE_SECONDS
# Restic/APT drain stdout and stderr with two sequential bounded joins.
BROKER_IO_JOIN_BUDGET_SECONDS = 2.0 + 2.0
BROKER_REQUEST_CLEANUP_BUDGET_SECONDS = 1.0
BROKER_RESPONSE_SERIALIZATION_BUDGET_SECONDS = 0.5
BROKER_TERMINATION_GRACE_SECONDS = sum(
    (
        BROKER_CHILD_TERMINATION_BUDGET_SECONDS,
        BROKER_IO_JOIN_BUDGET_SECONDS,
        BROKER_REQUEST_CLEANUP_BUDGET_SECONDS,
        BROKER_RESPONSE_SERIALIZATION_BUDGET_SECONDS,
    )
)
# Explicit budget used after a local timeout while the helper cancels and
# cleans request-private artifacts.  No broker signal is used in this window.
BROKER_CLEANUP_BUDGET_SECONDS = BROKER_TERMINATION_GRACE_SECONDS
# Helper deadlines and broker allowances are intentionally separate.  The
# broker's ready window includes pkexec authorization, while later windows
# include delivery/validation overhead plus the helper phase and cleanup.
STARTUP_HELPER_READY_SECONDS = 120.0
STARTUP_HELPER_START_WAIT_SECONDS = 900.0
STARTUP_HELPER_PLAN_SECONDS = 900.0
BROKER_POLKIT_AUTHORIZATION_SECONDS = 120.0
BROKER_START_DELIVERY_SECONDS = 30.0
BROKER_READY_WINDOW_SECONDS = (
    BROKER_POLKIT_AUTHORIZATION_SECONDS + STARTUP_HELPER_READY_SECONDS + BROKER_CLEANUP_BUDGET_SECONDS
)
BROKER_START_WINDOW_SECONDS = (
    BROKER_START_DELIVERY_SECONDS + STARTUP_HELPER_START_WAIT_SECONDS + BROKER_CLEANUP_BUDGET_SECONDS
)
BROKER_PLAN_WINDOW_SECONDS = (
    BROKER_START_DELIVERY_SECONDS + STARTUP_HELPER_PLAN_SECONDS + BROKER_CLEANUP_BUDGET_SECONDS
)
ACTION_TIMEOUTS = MappingProxyType(
    {
        INSPECT_OPERATION: 1800.0,
        BACKUP_OPERATION: 3600.0,
        RESTORE_STAGING_OPERATION: 1800.0,
        RESTORE_INPLACE_OPERATION: 1800.0,
        PACKAGES_INSTALL_OPERATION: 1800.0,
        CONFIGURE_OPERATION: 120.0,
        STARTUP_OPERATION: 900.0,
    }
)
INSPECTION_TIMEOUTS = MappingProxyType(
    {
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
)


class BrokerError(RuntimeError):
    """Base class for structured broker failures."""

    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None):
        self.code = code
        self.message = message
        self.details = dict(details or {})
        super().__init__(f"{code}: {message}")


class BrokerProtocolError(BrokerError):
    pass


class BrokerSubprocessError(BrokerError):
    pass


class BrokerDisconnectedError(BrokerSubprocessError):
    """The helper did not return a structured response within cleanup budget."""

    pass


class BrokerOperationError(BrokerError):
    pass


# Descriptive aliases for callers that want to distinguish the failure
# families without depending on the shorter internal class names.
PrivilegeBrokerError = BrokerError
ProtocolFailure = BrokerProtocolError
SubprocessFailure = BrokerSubprocessError
HelperDisconnected = BrokerDisconnectedError


@dataclass(frozen=True, slots=True)
class ConfigureResult:
    uid: int
    user_root: str


class StartupSession:
    """One verified startup pipe; it exposes no arbitrary privileged request."""

    def __init__(self, process: subprocess.Popen[bytes], request_id: str, *, deadline: float,
                 start_window: float = BROKER_START_WINDOW_SECONDS,
                 plan_window: float = BROKER_PLAN_WINDOW_SECONDS):
        self._process = process
        self.request_id = request_id
        self._deadline = deadline
        self._start_window = start_window
        self._plan_window = plan_window
        self._parser = StartupFrameParser(request_id)
        self._pending: list[dict[str, Any]] = []
        self._started = False
        self._closed = False
        self._lock = threading.RLock()
        self._reader_thread: int | None = None
        self._finalized = threading.Event()
        self._finalize_lock = threading.Lock()
        self._navigation_lock = threading.Lock()
        self._request_lock = threading.Lock()
        self._navigation_ready = False
        self._saw_done = False
        # Filled by ``begin_startup`` from the root helper's ready frame.
        # Defaults to False for old helpers/test doubles so the GUI takes the
        # conservative new-repository password-confirmation path.
        self.repository_initialized = False
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        stream = self._process.stderr
        if stream is None:
            return
        while True:
            try:
                if not stream.read(4096):
                    return
            except (OSError, ValueError):
                return

    def _write(self, frame: bytes, *, deadline: float | None = None) -> None:
        if self._closed or self._process.stdin is None:
            raise BrokerDisconnectedError("session_closed", "startup session is closed")
        fd = self._process.stdin.fileno()
        view = memoryview(frame)
        os.set_blocking(fd, False)
        while view:
            remaining = (deadline or self._deadline) - time.monotonic()
            if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                raise BrokerSubprocessError("timeout", "startup session write timed out")
            try:
                count = os.write(fd, view)
            except (BrokenPipeError, OSError) as exc:
                raise BrokerDisconnectedError("helper_disconnected", "startup helper closed stdin") from exc
            view = view[count:]

    def start(self, *, password: str | None = None, password_file: str | None = None) -> None:
        with self._lock:
            if self._started:
                raise BrokerProtocolError("startup_already_started", "startup session can only be started once")
            try:
                from .privileged.validation import validate_credentials
                credentials = validate_credentials({"password": password, "password_file": password_file})
                frame = startup_start_frame(credentials, self.request_id)
            except Exception as exc:
                if isinstance(exc, BrokerError):
                    raise
                raise BrokerProtocolError(getattr(exc, "code", "invalid_credentials"),
                                          getattr(exc, "message", "invalid startup credentials")) from exc
            self._deadline = time.monotonic() + self._plan_window
            self._write(frame)
            self._started = True

    def _read_one(self) -> dict[str, Any] | None:
        with self._lock:
            current = threading.get_ident()
            if self._reader_thread is None:
                self._reader_thread = current
            elif self._reader_thread != current:
                raise BrokerProtocolError("concurrent_reader", "startup events has one reader")
        frame = self._pending.pop(0) if self._pending else None
        if frame is None and self._closed:
            return None
        stdout = self._process.stdout
        fd: int = -1
        if frame is None:
            if stdout is None:
                raise BrokerDisconnectedError("helper_disconnected", "startup helper has no stdout")
            fd = stdout.fileno()
            os.set_blocking(fd, False)
        while frame is None and not self._pending:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                self._reader_finalize()
                raise BrokerSubprocessError("timeout", "startup helper exceeded its deadline")
            if not select.select([fd], [], [], remaining)[0]:
                continue
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                try:
                    self._parser.finish()
                except ProtocolError:
                    self._reader_finalize()
                    raise
                # Compatibility with the original one-shot startup helper:
                # a complete `done` frame followed by clean EOF is terminal.
                # Check this before process.poll(): EOF can become observable a
                # few microseconds before the kernel reports the child exit,
                # which otherwise turns a successful helper into a spurious
                # helper_disconnected error.
                if self._saw_done:
                    self._reader_finalize()
                    return None
                if self._process.poll() is None:
                    self._reader_finalize()
                    raise BrokerDisconnectedError("helper_disconnected", "startup helper closed stdout")
                self._reader_finalize()
                raise BrokerDisconnectedError("helper_exit", "startup helper ended before terminal frame")
            try:
                self._pending.extend(self._parser.feed(chunk))
            except ProtocolError:
                self._reader_finalize()
                raise
        if frame is None:
            frame = self._pending.pop(0)
        if frame["type"] == "done":
            self._saw_done = True
            return self._read_one()
        if frame["type"] == "navigation-ready":
            self._navigation_ready = True
            self._reader_thread = None
            return frame
        if frame["type"] == "error":
            self._reap_terminal()
            if frame["code"] in {"cancelled", "timeout"}:
                return None
            raise BrokerOperationError(frame["code"], frame["message"])
        return frame

    def _reader_finalize(self) -> None:
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
        except OSError:
            pass
        self._finalize_process(BROKER_CLEANUP_BUDGET_SECONDS)

    def _reap_terminal(self) -> None:
        self._finalize_process(BROKER_CLEANUP_BUDGET_SECONDS)

    def _finalize_process(self, budget: float) -> None:
        if self._finalized.is_set():
            return
        with self._finalize_lock:
            if self._finalized.is_set():
                return
            deadline = time.monotonic() + budget
            while self._process.poll() is None and time.monotonic() < deadline:
                try:
                    self._process.wait(timeout=min(0.05, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
            if self._process.poll() is None:
                raise BrokerDisconnectedError("helper_disconnected", "startup helper was not reaped")
            self._closed = True
            for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            self._finalized.set()

    def events(self):
        if not self._started:
            raise BrokerProtocolError("startup_not_started", "call start before reading startup events")
        while True:
            frame = self._read_one()
            if frame is None:
                return
            yield frame
            if frame.get("type") == "navigation-ready":
                return

    def request(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        timeout: float = 3600.0,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Run one typed operation through the already-authorized private helper.

        Requests are serialized deliberately: the root helper executes one
        privileged operation at a time, matching the child-process/cancellation
        invariants used by the existing engines.
        """
        with self._request_lock:
            if not self._navigation_ready or self._closed:
                raise BrokerDisconnectedError("session_unavailable", "privileged startup session is not available")
            request_id = str(uuid.uuid4())
            try:
                frames = encode_session_request_frames(self.request_id, request_id, operation, payload)
            except ProtocolError as exc:
                raise BrokerProtocolError(exc.code, exc.message) from exc
            deadline = time.monotonic() + max(1.0, float(timeout))
            for frame in frames:
                self._write(frame, deadline=deadline)
            stdout = self._process.stdout
            if stdout is None:
                raise BrokerDisconnectedError("helper_disconnected", "privileged helper has no stdout")
            while True:
                try:
                    raw = read_frame_fd_deadline(
                        stdout.fileno(), limit=MAX_SESSION_RESPONSE_BYTES, deadline=deadline, allow_eof=True
                    )
                except ProtocolError as exc:
                    # Never reuse a request/response stream after a framing timeout
                    # or protocol failure: a late response would desynchronize the
                    # next RPC. Closing stdin is also observed by the helper's
                    # per-operation control monitor and cancels privileged work.
                    try:
                        self.close()
                    except BrokerError:
                        pass
                    raise BrokerProtocolError(exc.code, exc.message) from exc
                if raw is None:
                    self._closed = True
                    raise BrokerDisconnectedError("helper_disconnected", "privileged helper closed the session")
                try:
                    message = decode_session_message(
                        raw, session_id=self.request_id, request_id=request_id, operation=operation
                    )
                except ProtocolError as exc:
                    raise BrokerProtocolError(exc.code, exc.message) from exc
                if message.get("type") == "progress":
                    if progress_cb is not None:
                        progress_cb(message["progress"])
                    continue
                if message.get("type") == "response-chunk":
                    count = message["count"]
                    if message["index"] != 0:
                        raise BrokerProtocolError("invalid_chunk_sequence", "session response chunks must start at index zero")
                    chunks = [message["data"]]
                    total = len(message["data"])
                    for expected_index in range(1, count):
                        try:
                            chunk_raw = read_frame_fd_deadline(
                                stdout.fileno(), limit=MAX_SESSION_RESPONSE_BYTES, deadline=deadline, allow_eof=False
                            )
                            chunk_message = decode_session_message(
                                chunk_raw, session_id=self.request_id, request_id=request_id, operation=operation
                            )
                        except ProtocolError as exc:
                            try:
                                self.close()
                            except BrokerError:
                                pass
                            raise BrokerProtocolError(exc.code, exc.message) from exc
                        if chunk_message.get("type") != "response-chunk" or chunk_message["count"] != count or chunk_message["index"] != expected_index:
                            raise BrokerProtocolError("invalid_chunk_sequence", "session response chunk sequence does not match")
                        total += len(chunk_message["data"])
                        if total > MAX_SESSION_RESPONSE_ASSEMBLED_BYTES:
                            raise BrokerProtocolError("message_too_large", "assembled session response exceeds the protocol limit")
                        chunks.append(chunk_message["data"])
                    try:
                        message = decode_session_message(
                            b"".join(chunks), session_id=self.request_id, request_id=request_id,
                            operation=operation, limit=MAX_SESSION_RESPONSE_ASSEMBLED_BYTES,
                        )
                    except ProtocolError as exc:
                        raise BrokerProtocolError(exc.code, exc.message) from exc
                if not message["ok"]:
                    raise BrokerOperationError(
                        message.get("code", "helper_error"), message.get("message", "privileged operation failed")
                    )
                return message["result"]

    def filesystem_children(self, path: str, *, limit: int = 500, offset: int = 0) -> dict[str, Any]:
        """Compatibility navigation exchange retained for older callers/tests.

        The production GUI uses the typed INSPECT RPC through PrivilegedClient;
        this narrow legacy exchange remains safe and is also accepted by the
        persistent helper.
        """
        # Legacy navigation shares the same bidirectional pipe as typed RPC.
        # Serialize both forms so an old caller cannot interleave a navigation
        # frame with a production session request and desynchronize framing.
        with self._request_lock, self._navigation_lock:
            if not self._navigation_ready:
                raise BrokerProtocolError("navigation_not_ready", "startup navigation is not ready")
            request_id = str(uuid.uuid4())
            try:
                frame = encode_navigation_request_frame(self.request_id, request_id, path, limit, offset)
            except ProtocolError as exc:
                raise BrokerProtocolError(exc.code, exc.message) from exc
            self._write(frame)
            response = self._read_one()
            if response is None:
                raise BrokerProtocolError("invalid_response", "navigation result is missing")
            if response.get("request_id") != request_id or response.get("session_id") != self.request_id:
                raise BrokerProtocolError("request_id_mismatch", "navigation response does not match request")
            if response.get("type") == "navigation-error":
                raise BrokerOperationError(response.get("code", "navigation_error"), response.get("message", "navigation request failed"))
            if response.get("type") != "navigation-result":
                raise BrokerProtocolError("invalid_response", "navigation result is missing")
            return response

    def cancel(self) -> None:
        with self._lock:
            if self._closed or self._process.poll() is not None:
                return
            try:
                self._write(encode_cancel_frame(), deadline=time.monotonic() + 0.5)
            except BrokerError:
                pass

    def close(self) -> None:
        if self._closed or self._finalized.is_set():
            return
        with self._lock:
            if self._closed or self._finalized.is_set():
                return
            self.cancel()
            foreign_reader = self._reader_thread is not None and self._reader_thread != threading.get_ident()
            try:
                if self._process.stdin is not None:
                    self._process.stdin.close()  # EOF fallback after cancel.
            except OSError:
                pass
            cleanup_deadline = time.monotonic() + BROKER_CLEANUP_BUDGET_SECONDS
            if foreign_reader:
                # The events owner must consume the cancellation terminal
                # frame and perform finalization; close only waits.
                while self._process.poll() is None and time.monotonic() < cleanup_deadline:
                    try:
                        self._process.wait(timeout=min(0.05, cleanup_deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        pass
                remaining = max(0.0, cleanup_deadline - time.monotonic())
                if not self._finalized.wait(remaining):
                    raise BrokerDisconnectedError("helper_disconnected", "event reader did not finalize startup")
                return
            # No events owner exists, so cleanup itself drains stdout before
            # the idempotent finalizer closes every descriptor.
            stdout = self._process.stdout
            if stdout is not None:
                os.set_blocking(stdout.fileno(), False)
            while self._process.poll() is None and time.monotonic() < cleanup_deadline:
                if stdout is not None:
                    try:
                        while os.read(stdout.fileno(), 65536):
                            pass
                    except (BlockingIOError, OSError):
                        pass
                try:
                    self._process.wait(timeout=min(0.05, cleanup_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
            self._finalize_process(max(0.001, cleanup_deadline - time.monotonic()))

    def __enter__(self) -> "StartupSession":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class Phase2Result:
    request_id: str
    operation: str
    uid: int
    result: dict[str, Any] | list[Any]


def _minimal_environment() -> dict[str, str]:
    """Build a small, fixed environment for pkexec.

    No caller-provided mapping is accepted.  Only a fixed locale subset is
    inherited; command paths and credentials are never inherited.
    """
    source = os.environ
    env = {"PATH": "/usr/bin:/bin"}
    for key in ("LANG", "LC_ALL"):
        value = source.get(key)
        if isinstance(value, str) and value:
            env[key] = value
    return env


def _bounded_text(value: bytes | str, limit: int = MAX_SUBPROCESS_DIAGNOSTIC_BYTES) -> str:
    truncated = False
    if isinstance(value, bytes):
        truncated = len(value) > limit
        value = value[:limit].decode("utf-8", "replace")
    else:
        truncated = len(value) > limit
    text = str(value)[:limit]
    if truncated:
        marker = "[diagnostic truncated]"
        text = text[: max(0, limit - len(marker) - 1)] + "\n" + marker
    return text


def _bounded_process(
    command: Sequence[str],
    request: bytes,
    *,
    timeout: float,
    stdout_limit: int,
    preserve_completed_on_grace: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """Run a helper while retaining stdin for helper-owned cancellation.

    A local timeout sends only the framed cancel control command.  The broker
    never signals the elevated process: the helper observes that command (or
    its own deadline), stops its known child group, cleans its request, and
    returns a structured response.  The retained prefixes continue draining
    until the helper exits so noisy output cannot deadlock the pipe.
    """
    process = subprocess.Popen(
        list(command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_minimal_environment(),
        start_new_session=True,
    )
    # The operation budget starts at process creation, not after a potentially
    # blocking request write.  stdin is handled with a nonblocking fd below.
    operation_deadline = time.monotonic() + timeout
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    overflow = {"stdout": False, "stderr": False}

    def drain(stream, buffer: bytearray, limit: int, name: str) -> None:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            remaining = max(0, limit - len(buffer))
            if remaining:
                buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow[name] = True

    stdout_thread = threading.Thread(
        target=drain, args=(process.stdout, stdout_buffer, stdout_limit, "stdout"), daemon=True
    )
    stderr_thread = threading.Thread(
        target=drain,
        args=(process.stderr, stderr_buffer, MAX_SUBPROCESS_DIAGNOSTIC_BYTES, "stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    cleanup_deadline: float | None = None
    timed_out = False
    cancel_sent = False
    disconnected = False
    disconnect_error: BrokerDisconnectedError | None = None
    initial_write_failed = False
    cancel_write_failed = False

    def write_until(fd: int, data: bytes, deadline: float) -> bool:
        view = memoryview(data)
        poller = selectors.DefaultSelector()
        try:
            os.set_blocking(fd, False)
            poller.register(fd, selectors.EVENT_WRITE)
            while view:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                events = poller.select(remaining)
                if not events:
                    return False
                try:
                    written = os.write(fd, view)
                except InterruptedError:
                    continue
                except (BrokenPipeError, OSError):
                    return False
                if written <= 0:
                    return False
                view = view[written:]
            return True
        finally:
            try:
                poller.unregister(fd)
            except Exception:
                pass
            poller.close()

    try:
        assert process.stdin is not None
        initial_write_failed = not write_until(process.stdin.fileno(), request, operation_deadline)
        if initial_write_failed:
            disconnected = True
            cleanup_deadline = time.monotonic() + BROKER_CLEANUP_BUDGET_SECONDS
            try:
                process.stdin.close()
            except OSError:
                pass
            disconnect_error = BrokerDisconnectedError(
                "request_timeout",
                "privileged helper did not accept the request before its deadline",
                details={"timeout": timeout},
            )
            while process.poll() is None and time.monotonic() < cleanup_deadline:
                try:
                    process.wait(timeout=min(0.1, cleanup_deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    continue
            returncode = process.poll()
        else:
            remaining = operation_deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(command), timeout)
            returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        cleanup_deadline = time.monotonic() + BROKER_CLEANUP_BUDGET_SECONDS
        try:
            assert process.stdin is not None
            cancel_sent = write_until(process.stdin.fileno(), encode_cancel_frame(), cleanup_deadline)
        except (BrokenPipeError, OSError):
            cancel_sent = False
        if not cancel_sent:
            cancel_write_failed = True
            disconnected = True
        while process.poll() is None and time.monotonic() < cleanup_deadline:
            try:
                process.wait(timeout=min(0.1, cleanup_deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                continue
        returncode = process.poll()
        if returncode is None:
            # Closing stdin is only a disconnect fallback.  It causes a
            # compliant helper to observe EOF, but it is not a substitute for
            # a signal and never turns a missing response into success.
            disconnected = True
            try:
                assert process.stdin is not None
                process.stdin.close()
            except OSError:
                pass
            disconnect_error = BrokerDisconnectedError(
                "helper_disconnected",
                "privileged helper did not return a cancellation response",
                details={"timeout": timeout, "cancel_sent": cancel_sent},
            )
    finally:
        join_deadline = cleanup_deadline or (time.monotonic() + BROKER_IO_JOIN_BUDGET_SECONDS)
        for thread in (stdout_thread, stderr_thread):
            thread.join(timeout=max(0.0, join_deadline - time.monotonic()))
    if timed_out:
        # Keep these attributes on the completed object so the broker can
        # decode a valid cancelled/timeout response before considering the
        # local deadline a failure.
        completed = subprocess.CompletedProcess(
            list(command), returncode if returncode is not None else -1, stdout=b"", stderr=b""
        )
    else:
        completed = subprocess.CompletedProcess(
            list(command), returncode if returncode is not None else -1
        )
    if overflow["stdout"]:
        raise BrokerProtocolError("response_too_large", "helper stdout exceeds protocol limit")
    stderr = bytes(stderr_buffer)
    if overflow["stderr"]:
        marker = b"\n[stderr truncated]"
        stderr = stderr[: max(0, MAX_SUBPROCESS_DIAGNOSTIC_BYTES - len(marker))] + marker
    completed.stdout = bytes(stdout_buffer)
    completed.stderr = stderr
    setattr(completed, "timed_out", timed_out)
    setattr(completed, "disconnected", disconnected)
    if disconnect_error is not None and not completed.stdout:
        raise disconnect_error
    if initial_write_failed:
        raise disconnect_error or BrokerDisconnectedError(
            "request_timeout", "privileged helper request was not delivered"
        )
    if cancel_write_failed:
        raise BrokerDisconnectedError(
            "cancel_timeout",
            "privileged helper cancellation could not be delivered before cleanup deadline",
            details={"timeout": timeout},
        )
    return completed


def _execute(
    command: Sequence[str],
    request: bytes,
    *,
    timeout: float,
    stdout_limit: int,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] | None,
    preserve_completed_on_grace: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    if runner is not None:
        return runner(
            list(command),
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_minimal_environment(),
            timeout=timeout,
            check=False,
        )
    return _bounded_process(
        command,
        request,
        timeout=timeout,
        stdout_limit=stdout_limit,
        preserve_completed_on_grace=preserve_completed_on_grace,
    )


class PrivilegeBroker:
    """Invoke only installed, allowlisted pkexec operations."""

    # MappingProxyType prevents a consumer from adding an arbitrary helper.
    allowed_helpers = ALLOWED_HELPERS
    helpers = ALLOWED_HELPERS

    def __init__(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
        timeout: float | None = None,
        uid_getter: Callable[[], int] | None = None,
        startup_process_factory: Callable[..., subprocess.Popen[bytes]] | None = None,
        startup_windows: Mapping[str, float] | None = None,
    ):
        self._runner = runner
        self._timeout = timeout
        self._uid_getter = uid_getter
        self._startup_process_factory = startup_process_factory
        self._startup_windows = dict(startup_windows) if startup_windows is not None else None

    def _startup_window(self, name: str, default: float) -> float:
        value = default if self._startup_windows is None else self._startup_windows.get(name, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise BrokerProtocolError("invalid_timeout", "startup timeout is invalid")
        return float(value)

    def _operation_timeout(self, operation: str, payload: Mapping[str, Any] | None = None) -> float:
        configured = ACTION_TIMEOUTS.get(operation, BROKER_TIMEOUT_SECONDS)
        if operation == INSPECT_OPERATION and payload is not None:
            configured = INSPECTION_TIMEOUTS.get(str(payload.get("kind")), configured)
        return configured if self._timeout is None else min(configured, self._timeout)

    def _caller_uid(self) -> int:
        uid = (self._uid_getter or os.getuid)()
        if isinstance(uid, bool) or not isinstance(uid, int):
            raise BrokerError("invalid_caller_uid", "local caller UID is invalid")
        if uid == 0:
            raise BrokerError("root_caller", "the privilege broker cannot be used by root")
        if uid < 1 or uid >= (1 << 32) - 1:
            raise BrokerError("invalid_caller_uid", "local caller UID is reserved")
        return uid

    def _invoke(self, operation: str, request: bytes) -> HelperResponse:
        # The operation is selected by this method, not by user input.  Keep
        # the command as a two-element argument list and do not use --keep-env.
        try:
            helper = ALLOWED_HELPERS[operation]
        except KeyError as exc:
            raise BrokerError("unknown_operation", "operation is not allowlisted") from exc
        command: Sequence[str] = (PKEXEC_EXECUTABLE, helper)
        runner = self._runner
        try:
            completed = _execute(
                command,
                request,
                timeout=self._operation_timeout(operation),
                stdout_limit=MAX_RESPONSE_BYTES,
                runner=runner,
            )
        except subprocess.TimeoutExpired as exc:
            raise BrokerSubprocessError(
                "timeout",
                "privileged helper timed out",
                details={"timeout": self._operation_timeout(operation)},
            ) from exc
        except FileNotFoundError as exc:
            raise BrokerSubprocessError(
                "pkexec_not_found", "pkexec executable is not available"
            ) from exc
        except OSError as exc:
            raise BrokerSubprocessError(
                "process_start_failed", "could not start pkexec", details={"errno": exc.errno}
            ) from exc

        stdout = getattr(completed, "stdout", b"") or b""
        stderr = getattr(completed, "stderr", b"") or b""
        if not isinstance(stdout, (bytes, str)):
            raise BrokerProtocolError("invalid_stdout", "pkexec returned non-text stdout")
        try:
            stdout_size = len(stdout.encode("utf-8") if isinstance(stdout, str) else stdout)
        except UnicodeEncodeError as exc:
            raise BrokerProtocolError("invalid_stdout", "pkexec returned invalid text") from exc
        if stdout_size > MAX_RESPONSE_BYTES:
            raise BrokerProtocolError("response_too_large", "helper response exceeds protocol limit")

        if bool(getattr(completed, "timed_out", False)):
            try:
                response = decode_response(stdout, expected_operation=operation)
            except ProtocolError as exc:
                raise BrokerDisconnectedError(
                    "helper_disconnected",
                    "privileged helper did not return a structured cancellation response",
                    details={"protocol_code": exc.code, "stderr": _bounded_text(stderr)},
                ) from exc
            if not response.ok:
                raise BrokerOperationError(
                    response.error_code or "helper_error",
                    response.error_message or "privileged operation failed",
                )
            raise BrokerSubprocessError(
                "timeout",
                "privileged helper exceeded the local timeout",
                details={"timeout": self._operation_timeout(operation)},
            )

        if completed.returncode != 0:
            raise BrokerSubprocessError(
                "helper_exit",
                "privileged helper exited unsuccessfully",
                details={
                    "returncode": completed.returncode,
                    "stderr": _bounded_text(stderr),
                },
            )

        try:
            response = decode_response(stdout, expected_operation=operation)
        except ProtocolError as exc:
            raise BrokerProtocolError(
                "invalid_response",
                exc.message,
                details={"protocol_code": exc.code, "stderr": _bounded_text(stderr)},
            ) from exc

        if not response.ok:
            raise BrokerOperationError(
                response.error_code or "helper_error",
                response.error_message or "privileged operation failed",
            )
        return response

    def _invoke_phase2(
        self,
        operation: str,
        backup_root: str | os.PathLike[str],
        payload: Mapping[str, Any],
    ) -> Phase2Result:
        caller_uid = self._caller_uid()
        raw_root = os.fspath(backup_root)
        if isinstance(raw_root, bytes):
            raw_root = os.fsdecode(raw_root)
        request_id = str(uuid.uuid4())
        try:
            request = encode_phase2_request_frame(request_id, operation, raw_root, payload)
        except ProtocolError as exc:
            raise BrokerProtocolError(exc.code, exc.message) from exc
        helper = ALLOWED_HELPERS.get(operation)
        if helper is None or operation == CONFIGURE_OPERATION:
            raise BrokerError("unknown_operation", "operation is not a Phase 2 allowlisted action")
        command = [PKEXEC_EXECUTABLE, helper]
        runner = self._runner
        try:
            completed = _execute(
                command,
                request,
                timeout=self._operation_timeout(operation, payload),
                stdout_limit=MAX_PHASE2_RESPONSE_BYTES,
                runner=runner,
                preserve_completed_on_grace=True,
            )
        except subprocess.TimeoutExpired as exc:
            raise BrokerSubprocessError(
                "timeout",
                "privileged helper timed out",
                details={"timeout": self._operation_timeout(operation, payload)},
            ) from exc
        except FileNotFoundError as exc:
            raise BrokerSubprocessError("pkexec_not_found", "pkexec executable is not available") from exc
        except OSError as exc:
            raise BrokerSubprocessError("process_start_failed", "could not start pkexec") from exc
        stdout = getattr(completed, "stdout", b"") or b""
        stderr = getattr(completed, "stderr", b"") or b""
        if isinstance(stdout, str):
            stdout_size = len(stdout.encode("utf-8"))
        elif isinstance(stdout, bytes):
            stdout_size = len(stdout)
        else:
            raise BrokerProtocolError("invalid_stdout", "pkexec returned invalid stdout")
        if stdout_size > MAX_PHASE2_RESPONSE_BYTES:
            raise BrokerProtocolError("response_too_large", "helper response exceeds protocol limit")
        timed_out = bool(getattr(completed, "timed_out", False))
        if timed_out:
            try:
                response: Phase2Response = decode_phase2_response(
                    stdout,
                    expected_operation=operation,
                    expected_request_id=request_id,
                )
            except ProtocolError as exc:
                raise BrokerDisconnectedError(
                    "helper_disconnected",
                    "privileged helper did not return a structured cancellation response",
                    details={"protocol_code": exc.code, "stderr": _bounded_text(stderr)},
                ) from exc
            if not response.ok:
                raise BrokerOperationError(
                    response.error_code or "helper_error",
                    response.error_message or "privileged operation failed",
                )
            # A successful response after the broker deadline is never
            # accepted: local timeout remains a failure.
            raise BrokerSubprocessError(
                "timeout",
                "privileged helper exceeded the local timeout",
                details={"timeout": self._operation_timeout(operation, payload)},
            )
        if completed.returncode != 0:
            raise BrokerSubprocessError(
                "helper_exit",
                "privileged helper exited unsuccessfully",
                details={"returncode": completed.returncode, "stderr": _bounded_text(stderr)},
            )
        try:
            response: Phase2Response = decode_phase2_response(
                stdout,
                expected_operation=operation,
                expected_request_id=request_id,
            )
        except ProtocolError as exc:
            raise BrokerProtocolError(
                "invalid_response",
                exc.message,
                details={"protocol_code": exc.code, "stderr": _bounded_text(stderr)},
            ) from exc
        if not response.ok:
            raise BrokerOperationError(
                response.error_code or "helper_error",
                response.error_message or "privileged operation failed",
            )
        if response.uid != caller_uid or response.result is None:
            raise BrokerProtocolError("identity_mismatch", "helper response UID does not match caller")
        return Phase2Result(request_id, operation, caller_uid, response.result)

    def configure(self, backup_root: str | os.PathLike[str]) -> ConfigureResult:
        """Provision the current pkexec caller's GUI runtime leaf."""
        try:
            caller_uid = self._caller_uid()
            raw_root = os.fspath(backup_root)
            if isinstance(raw_root, bytes):
                raw_root = os.fsdecode(raw_root)
            request = encode_request_frame(CONFIGURE_OPERATION, raw_root)
            expected_paths = GuiPaths.for_user(raw_root, caller_uid)
        except ProtocolError as exc:
            raise BrokerProtocolError(exc.code, exc.message) from exc
        except (TypeError, UnicodeError) as exc:
            raise BrokerProtocolError("invalid_schema", "backup_root must be a path string") from exc
        except ValueError as exc:
            raise BrokerProtocolError("invalid_schema", str(exc)) from exc
        response = self._invoke(CONFIGURE_OPERATION, request)
        expected_root = str(expected_paths.user_root)
        if response.uid != caller_uid or response.user_root != expected_root:
            raise BrokerProtocolError(
                "identity_mismatch",
                "helper response does not identify the local caller's GUI leaf",
                details={"expected_uid": caller_uid, "expected_user_root": expected_root},
            )
        return ConfigureResult(caller_uid, expected_root)

    def begin_startup(
        self,
        backup_root: str | os.PathLike[str],
    ) -> tuple[ConfigureResult, StartupSession]:
        """Authorize/provision only; scanning begins only after ``start``."""
        try:
            caller_uid = self._caller_uid()
            raw = os.fspath(backup_root)
            raw_root = os.fsdecode(raw) if isinstance(raw, bytes) else raw
            request_id = str(uuid.uuid4())
            initial = encode_startup_request_frame_with_id(raw_root, request_id)
            expected_root = str(GuiPaths.for_user(raw_root, caller_uid).user_root)
        except ProtocolError as exc:
            raise BrokerProtocolError(exc.code, exc.message) from exc
        except (TypeError, ValueError, UnicodeError) as exc:
            raise BrokerProtocolError("invalid_schema", "backup_root must be a valid path string") from exc
        ready_window = self._startup_window("ready", BROKER_READY_WINDOW_SECONDS)
        start_window = self._startup_window("start", BROKER_START_WINDOW_SECONDS)
        plan_window = self._startup_window("plan", BROKER_PLAN_WINDOW_SECONDS)
        session: StartupSession | None = None
        try:
            command = [PKEXEC_EXECUTABLE, ALLOWED_HELPERS[STARTUP_OPERATION]]
            factory = self._startup_process_factory or subprocess.Popen
            process = factory(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=_minimal_environment(), start_new_session=True,
            )
            # The ready window begins after process creation.  Process-spawn
            # overhead is not helper protocol time and must not consume a
            # deliberately small ready deadline used by callers/tests.
            deadline = time.monotonic() + ready_window
            session = StartupSession(process, request_id, deadline=deadline,
                                     start_window=start_window, plan_window=plan_window)
            session._write(initial)
            ready = session._read_one()
            if ready is None or ready.get("type") != "ready":
                raise BrokerProtocolError("invalid_response", "startup ready frame is missing")
            if ready.get("request_id") != request_id:
                raise BrokerProtocolError("request_id_mismatch", "startup ready request id does not match broker request")
            if ready.get("uid") != caller_uid or ready.get("user_root") != expected_root:
                raise BrokerProtocolError("identity_mismatch", "startup helper identity does not match caller")
            session.repository_initialized = bool(ready.get("repository_initialized", False))
            # The ready read belongs to begin_startup, not to the eventual
            # consumer.  Explicitly hand stdout ownership to the worker that
            # first calls events().
            session._reader_thread = None
            session._deadline = time.monotonic() + start_window
            return ConfigureResult(caller_uid, expected_root), session
        except BrokerOperationError:
            if session is not None:
                session.close()
            raise
        except BrokerError:
            if session is not None:
                session.close()
            raise
        except (FileNotFoundError, OSError) as exc:
            if session is not None:
                session.close()
            raise BrokerSubprocessError("process_start_failed", "could not start startup helper") from exc
        except ProtocolError as exc:
            if session is not None:
                session.close()
            raise BrokerProtocolError("invalid_response", exc.message) from exc

    def inspect(
        self,
        backup_root: str | os.PathLike[str],
        *,
        kind: str,
        component: str | None = None,
        snapshot_id: str | None = None,
        directory: str | None = None,
        filename: str | None = None,
        path: str | None = None,
        paths: list[str] | None = None,
        staging_id: str | None = None,
        limit: int = 500,
        offset: int = 0,
        force: bool = False,
        exclude_patterns: list[str] | None = None,
        password: str | None = None,
        password_file: str | None = None,
    ) -> Phase2Result:
        if kind == "repository-size":
            payload = {"kind": kind}
        elif kind in {"config-inventory", "package-inventory"}:
            payload = {"kind": kind, "limit": limit, "offset": offset, "force": force}
        elif kind == "snapshots":
            payload = {"kind": kind, "component": component, "limit": limit, "offset": offset, "credentials": {"password": password, "password_file": password_file}}
        elif kind == "snapshot-stats":
            payload = {"kind": kind, "component": component, "snapshot_id": snapshot_id, "credentials": {"password": password, "password_file": password_file}}
        elif kind == "snapshot-directory":
            payload = {"kind": kind, "component": component, "snapshot_id": snapshot_id, "directory": directory, "limit": limit, "offset": offset, "credentials": {"password": password, "password_file": password_file}}
        elif kind == "metadata":
            payload = {"kind": kind, "component": component, "snapshot_id": snapshot_id, "filename": filename, "limit": limit, "offset": offset, "credentials": {"password": password, "password_file": password_file}}
        elif kind in {"filesystem-children", "filesystem-size"}:
            payload = {"kind": kind, "path": path, "exclude_patterns": list(exclude_patterns or [])}
            if kind == "filesystem-children":
                payload.update({"limit": limit, "offset": offset})
            else:
                payload["force"] = bool(force)
        elif kind == "filesystem-cache":
            payload = {"kind": kind, "paths": list(paths or []), "exclude_patterns": list(exclude_patterns or [])}
        elif kind == "staging-children":
            payload = {"kind": kind, "staging_id": staging_id, "path": path or "", "limit": limit, "offset": offset}
        else:
            raise BrokerProtocolError("unknown_inspect_kind", "inspect kind is not allowed")
        return self._invoke_phase2(INSPECT_OPERATION, backup_root, payload)

    def backup(
        self,
        backup_root: str | os.PathLike[str],
        *,
        sources: list[str],
        source_exclusions: list[str],
        exclude_rules: list[dict[str, Any]],
        packages: list[dict[str, Any]],
        configs: list[dict[str, Any]],
        components: list[str] | None = None,
        dry_run: bool,
        password: str | None = None,
        password_file: str | None = None,
    ) -> Phase2Result:
        return self._invoke_phase2(
            BACKUP_OPERATION,
            backup_root,
            {
                "sources": sources,
                "source_exclusions": source_exclusions,
                "exclude_rules": exclude_rules,
                "packages": packages,
                "configs": configs,
                "components": list(components or []),
                "dry_run": dry_run,
                "credentials": {"password": password, "password_file": password_file},
            },
        )

    def restore_staging(self, backup_root, *, component: str, snapshot_id: str, includes: list[str], password: str | None = None, password_file: str | None = None) -> Phase2Result:
        return self._invoke_phase2(
            RESTORE_STAGING_OPERATION,
            backup_root,
            {"component": component, "snapshot_id": snapshot_id, "includes": includes, "credentials": {"password": password, "password_file": password_file}},
        )

    def restore_inplace(self, backup_root, *, component: str, snapshot_id: str, includes: list[str], password: str | None = None, password_file: str | None = None) -> Phase2Result:
        return self._invoke_phase2(
            RESTORE_INPLACE_OPERATION,
            backup_root,
            {"component": component, "snapshot_id": snapshot_id, "includes": includes, "credentials": {"password": password, "password_file": password_file}},
        )

    def packages_install(self, backup_root, *, snapshot_id: str, packages: list[str], simulate: bool, password: str | None = None, password_file: str | None = None) -> Phase2Result:
        return self._invoke_phase2(
            PACKAGES_INSTALL_OPERATION,
            backup_root,
            {"snapshot_id": snapshot_id, "packages": packages, "simulate": simulate, "credentials": {"password": password, "password_file": password_file}},
        )
