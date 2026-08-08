from __future__ import annotations

import base64
import binascii
import json
import os
import struct
import uuid
import select
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_MESSAGE_BYTES = MAX_REQUEST_BYTES
REQUEST_MAX_BYTES = MAX_REQUEST_BYTES
RESPONSE_MAX_BYTES = MAX_RESPONSE_BYTES
MAX_BACKUP_ROOT_LENGTH = 4096
MAX_ERROR_MESSAGE_LENGTH = 2048
CONFIGURE_OPERATION = "configure"
STARTUP_OPERATION = "startup"
INSPECT_OPERATION = "inspect"
BACKUP_OPERATION = "backup"
RESTORE_STAGING_OPERATION = "restore-staging"
RESTORE_INPLACE_OPERATION = "restore-inplace"
PACKAGES_INSTALL_OPERATION = "packages-install"
MAINTENANCE_OPERATION = "maintenance"
PHASE2_OPERATIONS = frozenset(
    {
        INSPECT_OPERATION,
        BACKUP_OPERATION,
        RESTORE_STAGING_OPERATION,
        RESTORE_INPLACE_OPERATION,
        PACKAGES_INSTALL_OPERATION,
        MAINTENANCE_OPERATION,
    }
)
MAX_PHASE2_REQUEST_BYTES = 128 * 1024
MAX_PHASE2_RESPONSE_BYTES = 256 * 1024
MAX_PHASE2_REQUEST_ID_LENGTH = 64
FRAME_HEADER_BYTES = 4
MAX_CONTROL_FRAME_BYTES = 1024
MAX_STARTUP_FRAME_BYTES = 64 * 1024
MAX_STARTUP_COMMAND_BYTES = 16 * 1024
MAX_NAVIGATION_REQUEST_BYTES = 16 * 1024
MAX_SESSION_REQUEST_BYTES = MAX_PHASE2_REQUEST_BYTES
# A single session frame remains deliberately small, but backup plans can
# legitimately contain thousands of package/config policy entries. Large typed
# requests are therefore split into bounded transport chunks and reassembled by
# the already-authorized helper before normal schema validation. The aggregate
# cap is a hard protocol limit, not an invitation to accept arbitrary input.
MAX_SESSION_REQUEST_ASSEMBLED_BYTES = 64 * 1024 * 1024
MAX_SESSION_REQUEST_CHUNK_BYTES = 64 * 1024
MAX_SESSION_REQUEST_CHUNKS = (MAX_SESSION_REQUEST_ASSEMBLED_BYTES + MAX_SESSION_REQUEST_CHUNK_BYTES - 1) // MAX_SESSION_REQUEST_CHUNK_BYTES
MAX_SESSION_RESPONSE_BYTES = MAX_PHASE2_RESPONSE_BYTES
MAX_SESSION_RESPONSE_ASSEMBLED_BYTES = 64 * 1024 * 1024
MAX_SESSION_RESPONSE_CHUNK_BYTES = 128 * 1024
MAX_SESSION_RESPONSE_CHUNKS = (MAX_SESSION_RESPONSE_ASSEMBLED_BYTES + MAX_SESSION_RESPONSE_CHUNK_BYTES - 1) // MAX_SESSION_RESPONSE_CHUNK_BYTES
MAX_SESSION_PROGRESS_BYTES = 64 * 1024
NAVIGATION_OPERATION = "filesystem-children"
ERROR_REQUEST_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
UID_MIN = 1
RESERVED_UID_MAX = (1 << 32) - 1
MAX_VALID_UID = RESERVED_UID_MAX - 1
RESTIC_GLOB_METACHARS = frozenset("*?[]{}")


def is_valid_user_uid(value: Any) -> bool:
    """Whether a UID is usable for an unprivileged GUI leaf."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and UID_MIN <= value <= MAX_VALID_UID
    )


class ProtocolError(ValueError):
    """A request or response is not valid for the fixed helper protocol."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def is_valid_request_id(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 36 or len(value) > MAX_PHASE2_REQUEST_ID_LENGTH:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return str(parsed) == value and parsed.int != 0


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _decode_json(raw: bytes | bytearray | memoryview | str, *, limit: int) -> Any:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ProtocolError("malformed_json", "message is not valid UTF-8 JSON") from exc
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        encoded = bytes(raw)
    else:
        raise ProtocolError("invalid_message", "message must be UTF-8 JSON bytes or text")
    if len(encoded) > limit:
        raise ProtocolError("message_too_large", f"message exceeds {limit} bytes")
    try:
        text = encoded.decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError, ValueError, RecursionError) as exc:
        raise ProtocolError("malformed_json", "message is not valid strict JSON") from exc


def encode_json_frame(
    raw: bytes | bytearray | memoryview | str,
    *,
    limit: int,
) -> bytes:
    """Encode one bounded JSON payload as a uint32 big-endian frame.

    The frame is deliberately independent from JSON whitespace and never uses
    EOF as a message delimiter.  ``limit`` applies to the JSON payload, not
    the four-byte framing prefix.
    """
    if isinstance(raw, str):
        try:
            payload = raw.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ProtocolError("malformed_json", "message is not valid UTF-8 JSON") from exc
    elif isinstance(raw, (bytes, bytearray, memoryview)):
        payload = bytes(raw)
    else:
        raise ProtocolError("invalid_message", "message must be UTF-8 JSON bytes or text")
    if not (0 < len(payload) <= limit):
        raise ProtocolError("message_too_large", f"message exceeds {limit} bytes")
    if len(payload) > 0xFFFFFFFF:
        raise ProtocolError("message_too_large", "message exceeds frame length range")
    _decode_json(payload, limit=limit)
    return struct.pack(">I", len(payload)) + payload


def _unwrap_json_frame(raw: bytes, *, limit: int) -> bytes:
    """Accept a single frame for compatibility with direct protocol callers."""
    if len(raw) < FRAME_HEADER_BYTES:
        raise ProtocolError("malformed_frame", "message frame is truncated")
    length = struct.unpack(">I", raw[:FRAME_HEADER_BYTES])[0]
    if length == 0 or length > limit:
        raise ProtocolError("message_too_large", f"message exceeds {limit} bytes")
    expected = FRAME_HEADER_BYTES + length
    if len(raw) != expected:
        raise ProtocolError("malformed_frame", "message frame has trailing or missing bytes")
    return raw[FRAME_HEADER_BYTES:]


def read_frame_fd(fd: int, *, limit: int, allow_eof: bool = False) -> bytes | None:
    """Read exactly one length-prefixed frame from a file descriptor.

    This uses ``os.read`` rather than a buffered file object so bytes belonging
    to the later control channel cannot be consumed while reading the initial
    request.  EOF is only accepted before a frame starts when ``allow_eof`` is
    true; a truncated header or payload is always a protocol error.
    """
    def read_exact(size: int, *, initial: bool = False) -> bytes | None:
        chunks = bytearray()
        while len(chunks) < size:
            try:
                chunk = os.read(fd, size - len(chunks))
            except InterruptedError:
                continue
            except OSError as exc:
                raise ProtocolError("io_error", "could not read protocol frame") from exc
            if not chunk:
                if initial and not chunks and allow_eof:
                    return None
                raise ProtocolError("malformed_frame", "protocol frame is truncated")
            chunks.extend(chunk)
        return bytes(chunks)

    header = read_exact(FRAME_HEADER_BYTES, initial=True)
    if header is None:
        return None
    length = struct.unpack(">I", header)[0]
    if length == 0 or length > limit:
        raise ProtocolError("message_too_large", f"message exceeds {limit} bytes")
    payload = read_exact(length)
    assert payload is not None
    return payload


def read_frame_fd_deadline(fd: int, *, limit: int, deadline: float, allow_eof: bool = False) -> bytes | None:
    """Read one frame without allowing a peer to hold a privileged helper."""
    old_blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    try:
        data = bytearray()
        target = FRAME_HEADER_BYTES
        while len(data) < target:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ProtocolError("timeout", "protocol frame deadline expired")
            try:
                chunk = os.read(fd, target - len(data))
            except BlockingIOError:
                continue
            if not chunk:
                if not data and allow_eof:
                    return None
                raise ProtocolError("malformed_frame", "protocol frame is truncated")
            data.extend(chunk)
        length = struct.unpack(">I", data)[0]
        if length <= 0 or length > limit:
            raise ProtocolError("message_too_large", f"message exceeds {limit} bytes")
        while len(data) < FRAME_HEADER_BYTES + length:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ProtocolError("timeout", "protocol frame deadline expired")
            try:
                chunk = os.read(fd, FRAME_HEADER_BYTES + length - len(data))
            except BlockingIOError:
                continue
            if not chunk:
                raise ProtocolError("malformed_frame", "protocol frame is truncated")
            data.extend(chunk)
        return bytes(data[FRAME_HEADER_BYTES:])
    finally:
        os.set_blocking(fd, old_blocking)


def write_frame_fd_deadline(fd: int, frame: bytes, *, deadline: float, cancelled: Callable[[], bool] | None = None) -> None:
    """Bounded nonblocking write used by the root startup stream."""
    max_payload = max(MAX_STARTUP_FRAME_BYTES, MAX_SESSION_RESPONSE_BYTES, MAX_SESSION_PROGRESS_BYTES)
    if len(frame) < FRAME_HEADER_BYTES or len(frame) > FRAME_HEADER_BYTES + max_payload:
        raise ProtocolError("message_too_large", "protocol frame is out of bounds")
    old_blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    view = memoryview(frame)
    try:
        while view:
            if cancelled is not None and cancelled():
                raise ProtocolError("cancelled", "startup output was cancelled")
            remaining = deadline - time.monotonic()
            # Poll briefly so a cancellation/timeout flag is observed even
            # while the peer has stopped draining a full pipe.
            if remaining <= 0:
                raise ProtocolError("timeout", "startup output deadline expired")
            if not select.select([], [fd], [], min(0.1, remaining))[1]:
                continue
            try:
                written = os.write(fd, view)
            except BlockingIOError:
                continue
            if written <= 0:
                raise ProtocolError("io_error", "startup output pipe closed")
            view = view[written:]
    finally:
        os.set_blocking(fd, old_blocking)


def write_frame_fd(fd: int, raw: bytes | bytearray | memoryview | str, *, limit: int) -> None:
    frame = encode_json_frame(raw, limit=limit)
    view = memoryview(frame)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        except OSError as exc:
            raise ProtocolError("io_error", "could not write protocol frame") from exc
        if written <= 0:
            raise ProtocolError("io_error", "could not write protocol frame")
        view = view[written:]


def decode_control_frame(raw: bytes | bytearray | memoryview | str) -> str:
    """Validate the only control command accepted after the initial frame."""
    value = _require_object(_decode_json(raw, limit=MAX_CONTROL_FRAME_BYTES))
    _require_exact_fields(value, {"type"})
    if value["type"] != "cancel":
        raise ProtocolError("invalid_control", "only the cancel control frame is allowed")
    return "cancel"


def encode_cancel_frame() -> bytes:
    return encode_json_frame(b'{"type":"cancel"}', limit=MAX_CONTROL_FRAME_BYTES)


def _require_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError("invalid_schema", "message must be a JSON object")
    return dict(value)


def _require_exact_fields(value: Mapping[str, Any], fields: set[str]) -> None:
    if any(not isinstance(key, str) for key in value):
        raise ProtocolError("invalid_schema", "object field names must be strings")
    actual = set(value)
    missing = fields - actual
    unknown = actual - fields
    if missing:
        raise ProtocolError("missing_field", f"missing field: {sorted(missing)[0]}")
    if unknown:
        raise ProtocolError("unknown_field", f"unknown field: {sorted(unknown)[0]}")


def _literal_backup_root(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError("invalid_schema", "backup_root must be a non-empty string")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ProtocolError("invalid_schema", "backup_root must be valid UTF-8") from exc
    if len(encoded) > MAX_BACKUP_ROOT_LENGTH or not Path(value).is_absolute():
        raise ProtocolError("invalid_schema", "backup_root must be an absolute bounded path")
    if (
        any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)
        or any(char in RESTIC_GLOB_METACHARS for char in value)
        or "//" in value
        or "/../" in f"{value}/"
        or value.endswith("/..")
    ):
        raise ProtocolError("invalid_schema", "backup_root must be a literal normalized path")
    return value


@dataclass(frozen=True, slots=True)
class ConfigureRequest:
    version: int
    operation: str
    backup_root: str


@dataclass(frozen=True, slots=True)
class StartupRequest:
    version: int
    operation: str
    backup_root: str
    request_id: str


@dataclass(frozen=True, slots=True)
class HelperResponse:
    version: int
    operation: str
    ok: bool
    uid: int | None = None
    user_root: str | None = None
    error_code: str | None = None
    error_message: str | None = None

    @property
    def error(self) -> dict[str, str] | None:
        if self.error_code is None:
            return None
        return {"code": self.error_code, "message": self.error_message or ""}


@dataclass(frozen=True, slots=True)
class Phase2Request:
    version: int
    request_id: str
    operation: str
    backup_root: str
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Phase2Response:
    version: int
    request_id: str
    operation: str
    ok: bool
    uid: int | None = None
    result: dict[str, Any] | list[Any] | None = None
    error_code: str | None = None
    error_message: str | None = None


def validate_request(
    value: Mapping[str, Any], *, expected_operation: str = CONFIGURE_OPERATION
) -> ConfigureRequest:
    obj = _require_object(value)
    _require_exact_fields(obj, {"version", "operation", "backup_root"})
    version = obj["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", "unsupported protocol version")
    operation = obj["operation"]
    if not isinstance(operation, str) or operation not in {CONFIGURE_OPERATION}:
        raise ProtocolError("unknown_operation", "unknown operation")
    if operation != expected_operation:
        raise ProtocolError("operation_mismatch", "operation does not match this helper")
    backup_root = _literal_backup_root(obj["backup_root"])
    return ConfigureRequest(version, operation, backup_root)


def decode_request(
    raw: bytes | bytearray | memoryview | str, *, expected_operation: str = CONFIGURE_OPERATION
) -> ConfigureRequest:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        encoded = bytes(raw)
        if len(encoded) >= FRAME_HEADER_BYTES and encoded[:1] != b"{" and encoded[:1] != b"[":
            encoded = _unwrap_json_frame(encoded, limit=MAX_REQUEST_BYTES)
        raw = encoded
    value = _decode_json(raw, limit=MAX_REQUEST_BYTES)
    return validate_request(value, expected_operation=expected_operation)


# Names used by callers that prefer the parse terminology.
parse_request = decode_request


def encode_request(operation: str, backup_root: str) -> bytes:
    request = validate_request(
        {"version": PROTOCOL_VERSION, "operation": operation, "backup_root": backup_root}
    )
    return json.dumps(
        {"version": request.version, "operation": request.operation, "backup_root": request.backup_root},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_request_frame(operation: str, backup_root: str) -> bytes:
    return encode_json_frame(encode_request(operation, backup_root), limit=MAX_REQUEST_BYTES)


def validate_startup_request(value: Mapping[str, Any]) -> StartupRequest:
    obj = _require_object(value)
    _require_exact_fields(obj, {"version", "operation", "backup_root", "request_id"})
    if obj["version"] != PROTOCOL_VERSION or isinstance(obj["version"], bool):
        raise ProtocolError("unsupported_version", "unsupported protocol version")
    if obj["operation"] != STARTUP_OPERATION:
        raise ProtocolError("operation_mismatch", "operation does not match startup helper")
    if not is_valid_request_id(obj["request_id"]):
        raise ProtocolError("invalid_request_id", "request_id must be a canonical UUID")
    return StartupRequest(PROTOCOL_VERSION, STARTUP_OPERATION, _literal_backup_root(obj["backup_root"]), obj["request_id"])


def decode_startup_request(raw: bytes | bytearray | memoryview | str) -> StartupRequest:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        encoded = bytes(raw)
        if len(encoded) >= FRAME_HEADER_BYTES and encoded[:1] not in (b"{", b"["):
            encoded = _unwrap_json_frame(encoded, limit=MAX_REQUEST_BYTES)
        raw = encoded
    return validate_startup_request(_decode_json(raw, limit=MAX_REQUEST_BYTES))


def encode_startup_request_frame(backup_root: str, request_id: str | None = None) -> bytes:
    # Convenience callers get a fresh identity; the broker always supplies its
    # canonical UUID explicitly.
    return encode_startup_request_frame_with_id(backup_root, request_id or str(uuid.uuid4()))


def encode_startup_request_frame_with_id(backup_root: str, request_id: str) -> bytes:
    if not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "request_id must be a canonical UUID")
    value = {"version": PROTOCOL_VERSION, "operation": STARTUP_OPERATION,
             "backup_root": backup_root, "request_id": request_id}
    _literal_backup_root(backup_root)
    return encode_json_frame(json.dumps(value, separators=(",", ":")), limit=MAX_REQUEST_BYTES)


def startup_ready_response(
    uid: int,
    user_root: str,
    request_id: str | None = None,
    *,
    repository_initialized: bool = False,
) -> bytes:
    request_id = request_id or str(uuid.uuid4())
    if not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid startup request id")
    if not is_valid_user_uid(uid) or not isinstance(user_root, str) or not Path(user_root).is_absolute():
        raise ProtocolError("invalid_schema", "invalid startup identity")
    if not isinstance(repository_initialized, bool):
        raise ProtocolError("invalid_schema", "repository_initialized must be boolean")
    return _encode_startup_frame({"type": "ready", "version": PROTOCOL_VERSION,
                                  "operation": STARTUP_OPERATION, "uid": uid, "user_root": user_root,
                                  "repository_initialized": repository_initialized,
                                  "request_id": request_id})


def startup_start_frame(credentials: Mapping[str, Any] | None = None, request_id: str | None = None) -> bytes:
    if request_id is None:
        request_id = str(uuid.uuid4())
    if not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid startup request id")
    value: dict[str, Any] = {"type": "start", "request_id": request_id}
    if credentials is not None:
        value["credentials"] = dict(credentials)
    frame = _encode_startup_frame(value)
    if len(frame) - FRAME_HEADER_BYTES > MAX_STARTUP_COMMAND_BYTES:
        raise ProtocolError("message_too_large", "startup command exceeds its limit")
    return frame


def decode_startup_command(raw: bytes | bytearray | memoryview | str) -> dict[str, Any]:
    value = _require_object(_decode_json(raw, limit=MAX_STARTUP_COMMAND_BYTES))
    fields = {"type", "request_id"} if "credentials" not in value else {"type", "request_id", "credentials"}
    _require_exact_fields(value, fields)
    if value["type"] != "start":
        raise ProtocolError("invalid_startup_command", "only one startup start command is allowed")
    if "credentials" in value:
        if not isinstance(value["credentials"], Mapping):
            raise ProtocolError("invalid_credentials", "credentials must be an object")
        value["credentials"] = dict(value["credentials"])
    return value


class StartupFrameParser:
    """Incremental bounded parser; it never retains more than one frame."""

    def __init__(self, expected_request_id: str | None = None) -> None:
        self._buffer = bytearray()
        self._done = False
        self._ready = False
        self._request_id: str | None = expected_request_id
        self._navigation_ready = False
        if expected_request_id is not None and not is_valid_request_id(expected_request_id):
            raise ProtocolError("invalid_request_id", "invalid expected startup request id")

    def feed(self, data: bytes) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        position = 0
        # Consume arbitrary/coalesced input in bounded pieces.  A caller may
        # hand us megabytes, but the retained state never exceeds header plus
        # the currently declared frame.
        while position < len(data) or self._buffer:
            if len(self._buffer) >= FRAME_HEADER_BYTES:
                length = struct.unpack(">I", self._buffer[:4])[0]
            else:
                length = None
            if length is not None and (length <= 0 or length > MAX_STARTUP_FRAME_BYTES):
                raise ProtocolError("message_too_large", "startup frame exceeds its limit")
            required = FRAME_HEADER_BYTES if length is None else FRAME_HEADER_BYTES + length
            if len(self._buffer) >= required:
                payload = bytes(self._buffer[FRAME_HEADER_BYTES:required])
                del self._buffer[:required]
                value = _require_object(_decode_json(payload, limit=MAX_STARTUP_FRAME_BYTES))
                self._validate(value)
                output.append(value)
                continue
            capacity = required - len(self._buffer)
            take = min(capacity, len(data) - position)
            if take:
                self._buffer.extend(data[position:position + take])
                position += take
                continue
            break
        return output

    def finish(self) -> None:
        if self._buffer:
            raise ProtocolError("malformed_frame", "startup stream ended mid-frame")

    def _validate(self, value: dict[str, Any]) -> None:
        kind = value.get("type")
        if kind == "ready":
            if self._ready or self._done:
                raise ProtocolError("invalid_order", "startup ready frame is out of order")
            # ``repository_initialized`` was added after the original
            # rootless protocol.  Accept old helpers without the field so a
            # mixed-version installation fails soft (it will ask for password
            # confirmation) rather than failing the startup handshake.
            required = {"type", "version", "operation", "uid", "user_root", "request_id"}
            actual = set(value)
            if not required.issubset(actual) or actual - (required | {"repository_initialized"}):
                raise ProtocolError("invalid_schema", "invalid startup ready frame fields")
            if value["version"] != PROTOCOL_VERSION or value["operation"] != STARTUP_OPERATION or not is_valid_user_uid(value["uid"]):
                raise ProtocolError("invalid_schema", "invalid startup ready frame")
            if "repository_initialized" in value and not isinstance(value["repository_initialized"], bool):
                raise ProtocolError("invalid_schema", "invalid repository initialization flag")
            if not is_valid_request_id(value["request_id"]):
                raise ProtocolError("invalid_request_id", "invalid startup ready request id")
            self._check_id(value)
            self._ready = True
        elif kind == "result":
            if not self._ready or self._done:
                raise ProtocolError("invalid_order", "startup result frame is out of order")
            _require_exact_fields(value, {"type", "request_id", "section", "records", "offset", "next_offset", "final", "truncated"})
            self._check_id(value)
            if not isinstance(value["section"], str) or not isinstance(value["records"], list) or not isinstance(value["offset"], int) or not isinstance(value["final"], bool) or not isinstance(value["truncated"], bool):
                raise ProtocolError("invalid_schema", "invalid startup result frame")
            if value["next_offset"] is not None and (not isinstance(value["next_offset"], int) or value["next_offset"] < 0):
                raise ProtocolError("invalid_schema", "invalid startup next offset")
        elif kind == "done":
            if not self._ready or self._done:
                raise ProtocolError("invalid_order", "startup done frame is out of order")
            _require_exact_fields(value, {"type", "request_id"})
            self._check_id(value); self._done = True
        elif kind == "error":
            if self._done:
                raise ProtocolError("invalid_order", "startup error frame is out of order")
            _require_exact_fields(value, {"type", "request_id", "code", "message"})
            self._check_id(value)
            if not isinstance(value["code"], str) or not isinstance(value["message"], str):
                raise ProtocolError("invalid_schema", "invalid startup error frame")
            self._done = True
        elif kind == "navigation-ready":
            if not self._done or self._navigation_ready:
                raise ProtocolError("invalid_order", "navigation-ready frame is out of order")
            _require_exact_fields(value, {"type", "session_id"})
            if value["session_id"] != self._request_id:
                raise ProtocolError("request_id_mismatch", "navigation session id does not match")
            self._navigation_ready = True
        elif kind == "navigation-result":
            if not self._navigation_ready:
                raise ProtocolError("invalid_order", "navigation result is not ready")
            _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "records", "next_offset", "final", "truncated"})
            if value["session_id"] != self._request_id or value["operation"] != NAVIGATION_OPERATION or not is_valid_request_id(value["request_id"]):
                raise ProtocolError("request_id_mismatch", "navigation result identity does not match")
            if not isinstance(value["records"], list) or not isinstance(value["final"], bool) or not isinstance(value["truncated"], bool):
                raise ProtocolError("invalid_schema", "invalid navigation result")
            if value["next_offset"] is not None and (not isinstance(value["next_offset"], int) or not 0 <= value["next_offset"] <= 10000):
                raise ProtocolError("invalid_schema", "invalid navigation next offset")
        elif kind == "navigation-error":
            if not self._navigation_ready:
                raise ProtocolError("invalid_order", "navigation error is not ready")
            _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "code", "message"})
            if value["session_id"] != self._request_id or value["operation"] != NAVIGATION_OPERATION or not is_valid_request_id(value["request_id"]):
                raise ProtocolError("request_id_mismatch", "navigation error identity does not match")
        else:
            raise ProtocolError("invalid_schema", "unknown startup stream frame")

    def _check_id(self, value: Mapping[str, Any]) -> None:
        frame_id = value.get("request_id")
        if self._request_id is None:
            if not is_valid_request_id(frame_id):
                raise ProtocolError("invalid_request_id", "invalid startup frame request id")
            self._request_id = frame_id
        elif frame_id != self._request_id:
            raise ProtocolError("request_id_mismatch", "startup frame request id does not match")


def _encode_startup_frame(value: Mapping[str, Any]) -> bytes:
    raw = json.dumps(dict(value), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encode_json_frame(raw, limit=MAX_STARTUP_FRAME_BYTES)


def startup_progress_frame(section: str, records: list[Any], offset: int, next_offset: int | None, final: bool, request_id: str, truncated: bool = False) -> bytes:
    if not is_valid_request_id(request_id) or offset < 0 or (next_offset is not None and next_offset < 0):
        raise ProtocolError("invalid_schema", "invalid startup result identity or offset")
    return _encode_startup_frame({"type": "result", "request_id": request_id, "section": section,
                                  "records": records, "offset": offset, "next_offset": next_offset,
                                  "final": final, "truncated": truncated})


def startup_done_frame(request_id: str | None = None) -> bytes:
    request_id = request_id or str(uuid.uuid4())
    return _encode_startup_frame({"type": "done", "request_id": request_id})


def startup_error_frame(request_id: str, code: str, message: str) -> bytes:
    return _encode_startup_frame({"type": "error", "request_id": request_id,
                                  "code": str(code)[:128], "message": str(message)[:MAX_ERROR_MESSAGE_LENGTH]})


def navigation_ready_frame(session_id: str) -> bytes:
    if not is_valid_request_id(session_id):
        raise ProtocolError("invalid_request_id", "invalid navigation session id")
    return _encode_startup_frame({"type": "navigation-ready", "session_id": session_id})


def encode_navigation_request_frame(session_id: str, request_id: str, path: str, limit: int, offset: int) -> bytes:
    if not is_valid_request_id(session_id) or not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid navigation request identity")
    _literal_backup_root(path)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ProtocolError("invalid_schema", "navigation limit is out of bounds")
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 10000 or offset + limit > 10000:
        raise ProtocolError("invalid_schema", "navigation offset is out of bounds")
    frame = _encode_startup_frame({"type": "navigation-request", "session_id": session_id,
                                   "request_id": request_id, "operation": NAVIGATION_OPERATION,
                                   "path": path, "limit": limit, "offset": offset})
    if len(frame) - FRAME_HEADER_BYTES > MAX_NAVIGATION_REQUEST_BYTES:
        raise ProtocolError("message_too_large", "navigation request exceeds its limit")
    return frame


def navigation_result_frame(session_id: str, request_id: str, records: list[Any], next_offset: int | None, final: bool, truncated: bool = False) -> bytes:
    if not is_valid_request_id(session_id) or not is_valid_request_id(request_id) or not isinstance(records, list) or not isinstance(final, bool) or not isinstance(truncated, bool):
        raise ProtocolError("invalid_schema", "invalid navigation result")
    if next_offset is not None and (not isinstance(next_offset, int) or not 0 <= next_offset <= 10000):
        raise ProtocolError("invalid_schema", "invalid navigation next offset")
    return _encode_startup_frame({"type": "navigation-result", "session_id": session_id,
                                  "request_id": request_id, "operation": NAVIGATION_OPERATION,
                                  "records": records, "next_offset": next_offset,
                                  "final": final, "truncated": truncated})


def navigation_error_frame(session_id: str, request_id: str, code: str, message: str) -> bytes:
    if not is_valid_request_id(session_id) or not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid navigation error identity")
    return _encode_startup_frame({"type": "navigation-error", "session_id": session_id,
                                  "request_id": request_id, "operation": NAVIGATION_OPERATION,
                                  "code": str(code)[:128], "message": str(message)[:MAX_ERROR_MESSAGE_LENGTH]})


def decode_navigation_request(raw: bytes | bytearray | memoryview | str, *, session_id: str) -> dict[str, Any]:
    value = _require_object(_decode_json(raw, limit=MAX_NAVIGATION_REQUEST_BYTES))
    _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "path", "limit", "offset"})
    if value["type"] != "navigation-request" or value["session_id"] != session_id or value["operation"] != NAVIGATION_OPERATION:
        raise ProtocolError("invalid_navigation", "navigation request is not permitted")
    if not is_valid_request_id(value["request_id"]):
        raise ProtocolError("invalid_request_id", "invalid navigation request id")
    path = _literal_backup_root(value["path"])
    if isinstance(value["limit"], bool) or not isinstance(value["limit"], int) or not 1 <= value["limit"] <= 500:
        raise ProtocolError("invalid_schema", "navigation limit is out of bounds")
    if isinstance(value["offset"], bool) or not isinstance(value["offset"], int) or not 0 <= value["offset"] <= 10000 or value["offset"] + value["limit"] > 10000:
        raise ProtocolError("invalid_schema", "navigation offset is out of bounds")
    return {"request_id": value["request_id"], "path": path, "limit": value["limit"], "offset": value["offset"]}



def _session_request_json(session_id: str, request_id: str, operation: str, payload: Mapping[str, Any]) -> bytes:
    if not is_valid_request_id(session_id) or not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid session request identity")
    if operation not in PHASE2_OPERATIONS:
        raise ProtocolError("unknown_operation", "session operation is not allowed")
    if not isinstance(payload, Mapping):
        raise ProtocolError("invalid_schema", "session payload must be an object")
    raw = json.dumps(
        {
            "type": "session-request",
            "session_id": session_id,
            "request_id": request_id,
            "operation": operation,
            "payload": dict(payload),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_SESSION_REQUEST_ASSEMBLED_BYTES:
        raise ProtocolError(
            "message_too_large",
            f"session request exceeds {MAX_SESSION_REQUEST_ASSEMBLED_BYTES} bytes",
        )
    return raw


def encode_session_request_frame(session_id: str, request_id: str, operation: str, payload: Mapping[str, Any]) -> bytes:
    """Encode a request that fits in one legacy session frame.

    New production callers should use :func:`encode_session_request_frames`,
    which transparently chunks larger typed requests. Keeping this function
    strict preserves compatibility with direct protocol callers/tests.
    """
    return encode_json_frame(
        _session_request_json(session_id, request_id, operation, payload),
        limit=MAX_SESSION_REQUEST_BYTES,
    )


def encode_session_request_frames(
    session_id: str, request_id: str, operation: str, payload: Mapping[str, Any]
) -> list[bytes]:
    """Encode one typed request as one or more independently bounded frames."""
    raw = _session_request_json(session_id, request_id, operation, payload)
    if len(raw) <= MAX_SESSION_REQUEST_BYTES:
        return [encode_json_frame(raw, limit=MAX_SESSION_REQUEST_BYTES)]
    chunks = [raw[i:i + MAX_SESSION_REQUEST_CHUNK_BYTES] for i in range(0, len(raw), MAX_SESSION_REQUEST_CHUNK_BYTES)]
    if not chunks or len(chunks) > MAX_SESSION_REQUEST_CHUNKS:
        raise ProtocolError("message_too_large", "session request requires too many chunks")
    frames: list[bytes] = []
    count = len(chunks)
    for index, chunk in enumerate(chunks):
        envelope = json.dumps(
            {
                "type": "session-request-chunk",
                "session_id": session_id,
                "request_id": request_id,
                "operation": operation,
                "index": index,
                "count": count,
                "data": base64.b64encode(chunk).decode("ascii"),
            },
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        frames.append(encode_json_frame(envelope, limit=MAX_SESSION_REQUEST_BYTES))
    return frames


def decode_session_request_chunk(
    raw: bytes | bytearray | memoryview | str, *, session_id: str
) -> dict[str, Any]:
    """Validate and decode one bounded transport chunk without interpreting its payload."""
    value = _require_object(_decode_json(raw, limit=MAX_SESSION_REQUEST_BYTES))
    _require_exact_fields(
        value, {"type", "session_id", "request_id", "operation", "index", "count", "data"}
    )
    if value["type"] != "session-request-chunk" or value["session_id"] != session_id:
        raise ProtocolError("invalid_session", "session request chunk does not belong to this session")
    if not is_valid_request_id(value["request_id"]):
        raise ProtocolError("invalid_request_id", "invalid session request chunk id")
    if value["operation"] not in PHASE2_OPERATIONS:
        raise ProtocolError("unknown_operation", "session operation is not allowed")
    index, count = value["index"], value["count"]
    if isinstance(index, bool) or not isinstance(index, int) or isinstance(count, bool) or not isinstance(count, int):
        raise ProtocolError("invalid_schema", "session request chunk index/count must be integers")
    if not 1 <= count <= MAX_SESSION_REQUEST_CHUNKS or not 0 <= index < count:
        raise ProtocolError("invalid_schema", "session request chunk index/count is out of bounds")
    data = value["data"]
    if not isinstance(data, str):
        raise ProtocolError("invalid_schema", "session request chunk data must be text")
    try:
        decoded = base64.b64decode(data.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("invalid_schema", "session request chunk data is not valid base64") from exc
    if not decoded or len(decoded) > MAX_SESSION_REQUEST_CHUNK_BYTES:
        raise ProtocolError("message_too_large", "session request chunk payload is out of bounds")
    return {
        "request_id": value["request_id"],
        "operation": value["operation"],
        "index": index,
        "count": count,
        "data": decoded,
    }


def decode_session_request(
    raw: bytes | bytearray | memoryview | str, *, session_id: str,
    limit: int = MAX_SESSION_REQUEST_BYTES,
) -> dict[str, Any]:
    value = _require_object(_decode_json(raw, limit=limit))
    _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "payload"})
    if value["type"] != "session-request" or value["session_id"] != session_id:
        raise ProtocolError("invalid_session", "session request does not belong to this session")
    if not is_valid_request_id(value["request_id"]):
        raise ProtocolError("invalid_request_id", "invalid session request id")
    if value["operation"] not in PHASE2_OPERATIONS:
        raise ProtocolError("unknown_operation", "session operation is not allowed")
    payload = _require_object(value["payload"])
    return {
        "request_id": value["request_id"],
        "operation": value["operation"],
        "payload": dict(payload),
    }


def _session_success_json(session_id: str, request_id: str, operation: str, result: Any) -> bytes:
    if not is_valid_request_id(session_id) or not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid session response identity")
    if operation not in PHASE2_OPERATIONS:
        raise ProtocolError("unknown_operation", "session operation is not allowed")
    if not isinstance(result, (dict, list)):
        raise ProtocolError("invalid_result", "session result must be an object or list")
    raw = json.dumps(
        {
            "type": "session-response",
            "session_id": session_id,
            "request_id": request_id,
            "operation": operation,
            "ok": True,
            "result": result,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(raw) > MAX_SESSION_RESPONSE_ASSEMBLED_BYTES:
        raise ProtocolError("message_too_large", f"session response exceeds {MAX_SESSION_RESPONSE_ASSEMBLED_BYTES} bytes")
    return raw


def session_success_frame(session_id: str, request_id: str, operation: str, result: Any) -> bytes:
    """Compatibility encoder for responses that fit one frame."""
    return encode_json_frame(
        _session_success_json(session_id, request_id, operation, result),
        limit=MAX_SESSION_RESPONSE_BYTES,
    )


def session_success_frames(session_id: str, request_id: str, operation: str, result: Any) -> list[bytes]:
    """Encode a terminal response into one or more bounded authenticated frames."""
    raw = _session_success_json(session_id, request_id, operation, result)
    if len(raw) <= MAX_SESSION_RESPONSE_BYTES:
        return [encode_json_frame(raw, limit=MAX_SESSION_RESPONSE_BYTES)]
    chunks = [raw[i:i + MAX_SESSION_RESPONSE_CHUNK_BYTES] for i in range(0, len(raw), MAX_SESSION_RESPONSE_CHUNK_BYTES)]
    if not chunks or len(chunks) > MAX_SESSION_RESPONSE_CHUNKS:
        raise ProtocolError("message_too_large", "session response requires too many chunks")
    frames: list[bytes] = []
    count = len(chunks)
    for index, chunk in enumerate(chunks):
        envelope = json.dumps(
            {
                "type": "session-response-chunk",
                "session_id": session_id,
                "request_id": request_id,
                "operation": operation,
                "index": index,
                "count": count,
                "data": base64.b64encode(chunk).decode("ascii"),
            },
            ensure_ascii=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        frames.append(encode_json_frame(envelope, limit=MAX_SESSION_RESPONSE_BYTES))
    return frames


def decode_session_response_chunk(
    raw: bytes | bytearray | memoryview | str, *, session_id: str, request_id: str, operation: str
) -> dict[str, Any]:
    value = _require_object(_decode_json(raw, limit=MAX_SESSION_RESPONSE_BYTES))
    _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "index", "count", "data"})
    if value["type"] != "session-response-chunk":
        raise ProtocolError("invalid_session", "invalid session response chunk type")
    if value["session_id"] != session_id or value["request_id"] != request_id:
        raise ProtocolError("request_id_mismatch", "session response chunk identity mismatch")
    if value["operation"] != operation:
        raise ProtocolError("operation_mismatch", "session response chunk operation mismatch")
    index, count = value["index"], value["count"]
    if isinstance(index, bool) or not isinstance(index, int) or isinstance(count, bool) or not isinstance(count, int):
        raise ProtocolError("invalid_schema", "session response chunk index/count must be integers")
    if not 1 <= count <= MAX_SESSION_RESPONSE_CHUNKS or not 0 <= index < count:
        raise ProtocolError("invalid_schema", "session response chunk index/count is out of bounds")
    data = value["data"]
    if not isinstance(data, str):
        raise ProtocolError("invalid_schema", "session response chunk data must be text")
    try:
        decoded = base64.b64decode(data.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ProtocolError("invalid_schema", "session response chunk data is not valid base64") from exc
    if not decoded or len(decoded) > MAX_SESSION_RESPONSE_CHUNK_BYTES:
        raise ProtocolError("message_too_large", "session response chunk payload is out of bounds")
    return {"index": index, "count": count, "data": decoded}


def session_progress_frame(
    session_id: str, request_id: str, operation: str, progress: Mapping[str, Any]
) -> bytes:
    """Encode one bounded progress event for an authorized session request."""
    if not is_valid_request_id(session_id) or not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid session progress identity")
    if operation not in PHASE2_OPERATIONS:
        raise ProtocolError("unknown_operation", "session operation is not allowed")
    if not isinstance(progress, Mapping):
        raise ProtocolError("invalid_schema", "session progress must be an object")
    # Progress is deliberately a small presentation protocol, not an arbitrary
    # object tunnel from privileged code.  In particular Restic can emit very
    # large current_files arrays, which must never be able to fill the IPC pipe
    # or exceed the bounded frame size.
    allowed = {
        "message_type", "percent_done", "current_files", "action", "item", "text",
        "current_item", "items_processed", "files_done", "bytes_done", "total_files",
        "total_bytes", "seconds_elapsed",
    }
    safe: dict[str, Any] = {}
    for key, value in progress.items():
        if key not in allowed:
            continue
        if isinstance(value, str):
            safe[key] = value[:4096]
        elif isinstance(value, bool) or isinstance(value, (int, float)):
            safe[key] = value
        elif key == "current_files" and isinstance(value, list):
            safe[key] = [str(item)[:4096] for item in value[:8]]
    raw = json.dumps(
        {
            "type": "session-progress",
            "session_id": session_id,
            "request_id": request_id,
            "operation": operation,
            "progress": safe,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return encode_json_frame(raw, limit=MAX_SESSION_PROGRESS_BYTES)


def session_error_frame(session_id: str, request_id: str, operation: str, code: str, message: str) -> bytes:
    if not is_valid_request_id(session_id) or not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "invalid session response identity")
    if operation not in PHASE2_OPERATIONS:
        raise ProtocolError("unknown_operation", "session operation is not allowed")
    raw = json.dumps(
        {
            "type": "session-response",
            "session_id": session_id,
            "request_id": request_id,
            "operation": operation,
            "ok": False,
            "error": {
                "code": str(code)[:128],
                "message": str(message)[:MAX_ERROR_MESSAGE_LENGTH],
            },
        },
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return encode_json_frame(raw, limit=MAX_SESSION_RESPONSE_BYTES)


def decode_session_message(
    raw: bytes | bytearray | memoryview | str,
    *,
    session_id: str,
    request_id: str,
    operation: str,
    limit: int = MAX_SESSION_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Decode progress, a chunk envelope, or a terminal response for one RPC."""
    value = _require_object(_decode_json(raw, limit=limit))
    if value.get("session_id") != session_id or value.get("request_id") != request_id:
        raise ProtocolError("request_id_mismatch", "session response identity mismatch")
    if value.get("operation") != operation:
        raise ProtocolError("operation_mismatch", "session response operation mismatch")
    message_type = value.get("type")
    if message_type == "session-response-chunk":
        chunk = decode_session_response_chunk(
            raw, session_id=session_id, request_id=request_id, operation=operation
        )
        return {"type": "response-chunk", **chunk}
    if message_type == "session-progress":
        _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "progress"})
        progress = _require_object(value["progress"])
        return {"type": "progress", "progress": dict(progress)}
    if message_type != "session-response":
        raise ProtocolError("invalid_session", "invalid session response type")
    ok = value.get("ok")
    if not isinstance(ok, bool):
        raise ProtocolError("invalid_schema", "session response status is invalid")
    if ok:
        _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "ok", "result"})
        if not isinstance(value["result"], (dict, list)):
            raise ProtocolError("invalid_result", "session response result is invalid")
        return {"type": "response", "ok": True, "result": value["result"]}
    _require_exact_fields(value, {"type", "session_id", "request_id", "operation", "ok", "error"})
    error = _require_object(value["error"])
    _require_exact_fields(error, {"code", "message"})
    if not isinstance(error["code"], str) or not isinstance(error["message"], str):
        raise ProtocolError("invalid_schema", "session response error is invalid")
    return {"type": "response", "ok": False, "code": error["code"], "message": error["message"]}


def decode_session_response(
    raw: bytes | bytearray | memoryview | str,
    *,
    session_id: str,
    request_id: str,
    operation: str,
) -> dict[str, Any]:
    """Compatibility decoder for callers that expect an immediate terminal response."""
    message = decode_session_message(
        raw, session_id=session_id, request_id=request_id, operation=operation
    )
    if message.get("type") != "response":
        raise ProtocolError("unexpected_progress", "session progress was received where a terminal response was expected")
    message.pop("type", None)
    return message

def decode_startup_stream(raw: bytes) -> list[dict[str, Any]]:
    parser = StartupFrameParser()
    frames = parser.feed(raw)
    parser.finish()
    if not frames or not parser._done:
        raise ProtocolError("invalid_schema", "startup stream must terminate")
    return frames


def success_response(operation: str, uid: int, user_root: str) -> bytes:
    if operation != CONFIGURE_OPERATION:
        raise ProtocolError("unknown_operation", "unknown operation")
    if not is_valid_user_uid(uid):
        raise ProtocolError("invalid_schema", "uid must be a non-reserved user UID")
    if (
        not isinstance(user_root, str)
        or not user_root
        or "\x00" in user_root
        or not Path(user_root).is_absolute()
    ):
        raise ProtocolError("invalid_schema", "user_root must be a valid path string")
    value = {
        "version": PROTOCOL_VERSION,
        "operation": operation,
        "ok": True,
        "uid": uid,
        "user_root": user_root,
    }
    return _encode_response(value)


def error_response(operation: str, code: str, message: str) -> bytes:
    if operation != CONFIGURE_OPERATION:
        operation = CONFIGURE_OPERATION
    if not isinstance(code, str) or not code or len(code) > 128:
        code = "protocol_error"
    if not isinstance(message, str) or not message:
        message = "helper request failed"
    message = message[:MAX_ERROR_MESSAGE_LENGTH]
    return _encode_response(
        {
            "version": PROTOCOL_VERSION,
            "operation": operation,
            "ok": False,
            "error": {"code": code, "message": message},
        }
    )


def _encode_response(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProtocolError("response_too_large", "response exceeds protocol limit")
    return raw


def encode_response(response: HelperResponse) -> bytes:
    """Serialize a validated response model for a helper implementation."""
    if (
        isinstance(response.version, bool)
        or not isinstance(response.version, int)
        or response.version != PROTOCOL_VERSION
    ):
        raise ProtocolError("unsupported_version", "unsupported response protocol version")
    if response.ok:
        if response.uid is None or response.user_root is None:
            raise ProtocolError("invalid_schema", "successful response is incomplete")
        return success_response(response.operation, response.uid, response.user_root)
    return error_response(
        response.operation,
        response.error_code or "helper_error",
        response.error_message or "helper request failed",
    )


def decode_response(
    raw: bytes | bytearray | memoryview | str, *, expected_operation: str = CONFIGURE_OPERATION
) -> HelperResponse:
    value = _require_object(_decode_json(raw, limit=MAX_RESPONSE_BYTES))
    version = value.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", "unsupported response protocol version")
    if value.get("operation") != expected_operation:
        raise ProtocolError("operation_mismatch", "response operation does not match request")
    ok = value.get("ok")
    if ok is True:
        _require_exact_fields(value, {"version", "operation", "ok", "uid", "user_root"})
        uid = value["uid"]
        user_root = value["user_root"]
        if not is_valid_user_uid(uid):
            raise ProtocolError("invalid_schema", "invalid response uid")
        if (
            not isinstance(user_root, str)
            or not user_root
            or "\x00" in user_root
            or not Path(user_root).is_absolute()
        ):
            raise ProtocolError("invalid_schema", "invalid response user_root")
        return HelperResponse(PROTOCOL_VERSION, expected_operation, True, uid, user_root)
    if ok is False:
        _require_exact_fields(value, {"version", "operation", "ok", "error"})
        error = value["error"]
        if not isinstance(error, dict):
            raise ProtocolError("invalid_schema", "response error must be an object")
        _require_exact_fields(error, {"code", "message"})
        code = error["code"]
        message = error["message"]
        if (
            not isinstance(code, str)
            or not code
            or len(code) > 128
            or not isinstance(message, str)
            or not message
            or len(message) > MAX_ERROR_MESSAGE_LENGTH
        ):
            raise ProtocolError("invalid_schema", "invalid response error")
        return HelperResponse(
            PROTOCOL_VERSION,
            expected_operation,
            False,
            error_code=code,
            error_message=message,
        )
    raise ProtocolError("invalid_schema", "response ok must be a boolean")


parse_response = decode_response


def validate_response(
    value: Mapping[str, Any] | bytes | bytearray | memoryview | str,
    *,
    expected_operation: str = CONFIGURE_OPERATION,
) -> HelperResponse:
    if isinstance(value, Mapping):
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    else:
        raw = value
    return decode_response(raw, expected_operation=expected_operation)


def validate_phase2_request(
    value: Mapping[str, Any], *, expected_operation: str
) -> Phase2Request:
    obj = _require_object(value)
    _require_exact_fields(obj, {"version", "request_id", "operation", "backup_root", "payload"})
    version = obj["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", "unsupported protocol version")
    request_id = obj["request_id"]
    if not is_valid_request_id(request_id):
        raise ProtocolError("invalid_request_id", "request_id must be a canonical UUID")
    operation = obj["operation"]
    if not isinstance(operation, str) or operation not in PHASE2_OPERATIONS:
        raise ProtocolError("unknown_operation", "unknown privileged operation")
    if operation != expected_operation:
        raise ProtocolError("operation_mismatch", "operation does not match this helper")
    backup_root = _literal_backup_root(obj["backup_root"])
    payload = obj["payload"]
    if not isinstance(payload, Mapping):
        raise ProtocolError("invalid_schema", "payload must be an object")
    return Phase2Request(version, request_id, operation, backup_root, dict(payload))


def decode_phase2_request(raw: bytes | bytearray | memoryview | str, *, expected_operation: str) -> Phase2Request:
    if isinstance(raw, (bytes, bytearray, memoryview)):
        encoded = bytes(raw)
        if len(encoded) >= FRAME_HEADER_BYTES and encoded[:1] != b"{" and encoded[:1] != b"[":
            encoded = _unwrap_json_frame(encoded, limit=MAX_PHASE2_REQUEST_BYTES)
        raw = encoded
    value = _decode_json(raw, limit=MAX_PHASE2_REQUEST_BYTES)
    return validate_phase2_request(value, expected_operation=expected_operation)


def encode_phase2_request_frame(
    request_id: str, operation: str, backup_root: str, payload: Mapping[str, Any]
) -> bytes:
    return encode_json_frame(
        encode_phase2_request(request_id, operation, backup_root, payload),
        limit=MAX_PHASE2_REQUEST_BYTES,
    )


def encode_phase2_request(
    request_id: str, operation: str, backup_root: str, payload: Mapping[str, Any]
) -> bytes:
    request = validate_phase2_request(
        {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "operation": operation,
            "backup_root": backup_root,
            "payload": dict(payload),
        },
        expected_operation=operation,
    )
    raw = json.dumps(
        {
            "version": request.version,
            "request_id": request.request_id,
            "operation": request.operation,
            "backup_root": request.backup_root,
            "payload": request.payload,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(raw) > MAX_PHASE2_REQUEST_BYTES:
        raise ProtocolError("message_too_large", "phase 2 request exceeds protocol limit")
    return raw


def _encode_phase2_response(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_PHASE2_RESPONSE_BYTES:
        raise ProtocolError("response_too_large", "phase 2 response exceeds protocol limit")
    return raw


def phase2_success_response(
    request_id: str,
    operation: str,
    uid: int,
    result: dict[str, Any] | list[Any],
) -> bytes:
    if operation not in PHASE2_OPERATIONS or not is_valid_request_id(request_id):
        raise ProtocolError("invalid_schema", "invalid phase 2 response identity")
    if not is_valid_user_uid(uid):
        raise ProtocolError("invalid_schema", "invalid phase 2 response UID")
    if not isinstance(result, (dict, list)):
        raise ProtocolError("invalid_schema", "phase 2 result must be an object or array")
    return _encode_phase2_response(
        {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "operation": operation,
            "ok": True,
            "uid": uid,
            "result": result,
        }
    )


def phase2_error_response(
    request_id: str,
    operation: str,
    code: str,
    message: str,
) -> bytes:
    if not is_valid_request_id(request_id):
        request_id = ERROR_REQUEST_ID
    if operation not in PHASE2_OPERATIONS:
        operation = INSPECT_OPERATION
    if not isinstance(code, str) or not code or len(code) > 128:
        code = "privileged_error"
    if not isinstance(message, str) or not message:
        message = "privileged operation failed"
    return _encode_phase2_response(
        {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "operation": operation,
            "ok": False,
            "error": {"code": code, "message": message[:MAX_ERROR_MESSAGE_LENGTH]},
        }
    )


def decode_phase2_response(
    raw: bytes | bytearray | memoryview | str,
    *,
    expected_operation: str,
    expected_request_id: str,
) -> Phase2Response:
    value = _require_object(_decode_json(raw, limit=MAX_PHASE2_RESPONSE_BYTES))
    _require_exact_fields(
        value,
        {"version", "request_id", "operation", "ok", "uid", "result"}
        if value.get("ok") is True
        else {"version", "request_id", "operation", "ok", "error"},
    )
    version = value["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise ProtocolError("unsupported_version", "unsupported phase 2 response version")
    request_id = value["request_id"]
    if not is_valid_request_id(request_id) or request_id != expected_request_id:
        raise ProtocolError("request_id_mismatch", "response request_id does not match request")
    if value["operation"] != expected_operation:
        raise ProtocolError("operation_mismatch", "response operation does not match request")
    ok = value["ok"]
    if ok is True:
        uid = value["uid"]
        result = value["result"]
        if not is_valid_user_uid(uid) or not isinstance(result, (dict, list)):
            raise ProtocolError("invalid_schema", "invalid phase 2 success response")
        return Phase2Response(version, request_id, expected_operation, True, uid, result=result)
    if ok is False:
        error = value["error"]
        if not isinstance(error, dict):
            raise ProtocolError("invalid_schema", "phase 2 response error must be an object")
        _require_exact_fields(error, {"code", "message"})
        code, message = error["code"], error["message"]
        if not isinstance(code, str) or not code or len(code) > 128:
            raise ProtocolError("invalid_schema", "invalid phase 2 error code")
        if not isinstance(message, str) or not message or len(message) > MAX_ERROR_MESSAGE_LENGTH:
            raise ProtocolError("invalid_schema", "invalid phase 2 error message")
        return Phase2Response(
            version,
            request_id,
            expected_operation,
            False,
            error_code=code,
            error_message=message,
        )
    raise ProtocolError("invalid_schema", "phase 2 response ok must be a boolean")
