import pytest
import uuid
import os
import time
import threading

from ubackup.privileged.protocol import (
    ProtocolError, decode_startup_command, decode_startup_request,
    decode_startup_stream, encode_json_frame, encode_startup_request_frame,
    startup_done_frame, startup_ready_response, startup_start_frame,
    startup_progress_frame, StartupFrameParser,
    write_frame_fd_deadline,
    MAX_STARTUP_FRAME_BYTES,
)


def test_startup_request_is_only_root_and_operation():
    request_id = str(uuid.uuid4())
    assert decode_startup_request(encode_startup_request_frame("/backup", request_id)).request_id == request_id
    with pytest.raises(ProtocolError):
        decode_startup_request(b'{"version":1,"operation":"startup","backup_root":"/backup","kind":"packages"}')


def test_start_command_is_fixed_and_stream_order_is_bounded():
    request_id = str(uuid.uuid4())
    assert decode_startup_command(startup_start_frame({"password_file": "/backup/pw"}, request_id)[4:])["type"] == "start"
    with pytest.raises(ProtocolError):
        decode_startup_command(encode_json_frame(b'{"type":"start","kind":"packages"}', limit=1024)[4:])
    stream = startup_ready_response(1000, "/backup/.ubackup/users/1000", request_id) + startup_done_frame(request_id)
    assert decode_startup_stream(stream)[-1]["type"] == "done"
    with pytest.raises(ProtocolError):
        decode_startup_stream(startup_done_frame(request_id) + startup_ready_response(1000, "/backup/u", request_id))


def test_startup_ready_reports_repository_initialization_without_exposing_repository_data():
    request_id = str(uuid.uuid4())
    frame = startup_ready_response(
        1000,
        "/backup/.ubackup/users/1000",
        request_id,
        repository_initialized=True,
    )
    parsed = StartupFrameParser(request_id).feed(frame)[0]
    assert parsed["repository_initialized"] is True


def test_expected_uuid_binds_ready_and_pre_ready_error():
    request_id = str(uuid.uuid4())
    other_id = str(uuid.uuid4())
    parser = StartupFrameParser(request_id)
    with pytest.raises(ProtocolError, match="request id"):
        parser.feed(startup_ready_response(1000, "/backup/u", other_id))
    parser = StartupFrameParser(request_id)
    from ubackup.privileged.protocol import startup_error_frame
    with pytest.raises(ProtocolError, match="request id"):
        parser.feed(startup_error_frame(other_id, "failed", "no"))


def test_parser_accepts_declared_maximum_frame_and_coalesced_frames():
    request_id = str(uuid.uuid4())
    parser = StartupFrameParser(request_id)
    parser.feed(startup_ready_response(1000, "/backup/u", request_id))
    frame = startup_progress_frame("root", ["x" * (MAX_STARTUP_FRAME_BYTES - 256)], 0, None, True, request_id)
    assert len(frame) <= MAX_STARTUP_FRAME_BYTES + 4
    done = startup_done_frame(request_id)
    parsed = parser.feed(frame + done)
    assert [item["type"] for item in parsed] == ["result", "done"]


def test_incremental_parser_handles_stream_larger_than_eight_megabytes():
    request_id = str(uuid.uuid4())
    parser = StartupFrameParser()
    assert parser.feed(startup_ready_response(1000, "/backup/u", request_id))[0]["type"] == "ready"
    total = 0
    for index in range(70_000):
        frame = startup_progress_frame("root", [], index, index + 1, False, request_id)
        total += len(frame)
        parser.feed(frame)
    assert total > 8 * 1024 * 1024
    parser.feed(startup_done_frame(request_id))
    parser.finish()


def test_full_pipe_writer_observes_cancellation_without_a_reader():
    read_fd, write_fd = os.pipe()
    try:
        os.set_blocking(write_fd, False)
        while True:
            try:
                os.write(write_fd, b"x" * 65536)
            except BlockingIOError:
                break
        checks = [0]

        def cancelled():
            checks[0] += 1
            return checks[0] >= 2

        started = time.monotonic()
        with pytest.raises(Exception):
            write_frame_fd_deadline(write_fd, b"\x00\x00\x00\x01x", deadline=time.monotonic() + 2,
                                     cancelled=cancelled)
        assert checks[0] >= 2 and time.monotonic() - started < 1.0
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_session_protocol_rejects_unknown_operation_and_binds_identity():
    from ubackup.privileged.protocol import (
        INSPECT_OPERATION, decode_session_request, decode_session_response,
        encode_session_request_frame, session_success_frame,
    )
    session_id = str(uuid.uuid4()); request_id = str(uuid.uuid4())
    frame = encode_session_request_frame(session_id, request_id, INSPECT_OPERATION, {"kind": "repository-size"})
    request = decode_session_request(frame[4:], session_id=session_id)
    assert request["operation"] == INSPECT_OPERATION
    response = session_success_frame(session_id, request_id, INSPECT_OPERATION, {"size": 1})
    assert decode_session_response(response[4:], session_id=session_id, request_id=request_id, operation=INSPECT_OPERATION)["result"] == {"size": 1}
    with pytest.raises(ProtocolError):
        encode_session_request_frame(session_id, request_id, "run-anything", {})


def test_session_progress_frame_is_typed_bounded_and_identity_bound():
    from ubackup.privileged.protocol import (
        INSPECT_OPERATION, decode_session_message, session_progress_frame,
    )

    session_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    frame = session_progress_frame(
        session_id,
        request_id,
        INSPECT_OPERATION,
        {
            "current_item": "/etc/ssh/sshd_config",
            "items_processed": 12,
            "bytes_done": 4096,
            "current_files": [f"/tmp/item-{index}" for index in range(1000)],
            "ignored": "must not cross the privileged protocol boundary",
        },
    )
    decoded = decode_session_message(
        frame[4:], session_id=session_id, request_id=request_id, operation=INSPECT_OPERATION
    )
    assert decoded["type"] == "progress"
    assert decoded["progress"]["current_item"] == "/etc/ssh/sshd_config"
    assert decoded["progress"]["items_processed"] == 12
    assert "ignored" not in decoded["progress"]
    assert len(decoded["progress"]["current_files"]) < 1000

    with pytest.raises(ProtocolError, match="identity mismatch"):
        decode_session_message(
            frame[4:], session_id=session_id, request_id=str(uuid.uuid4()), operation=INSPECT_OPERATION
        )


def test_large_session_request_is_chunked_and_reassembled_with_identity():
    from ubackup.privileged.protocol import (
        BACKUP_OPERATION, MAX_SESSION_REQUEST_BYTES,
        encode_session_request_frames,
    )
    from ubackup.privileged.startup import _decode_session_request_from_first

    session_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    # Deliberately incompressible-enough JSON volume to exceed the historical
    # 128 KiB single-frame cap used by package/config backup plans.
    payload = {"records": [{"name": f"package-{i}", "note": "x" * 180} for i in range(1500)]}
    frames = encode_session_request_frames(session_id, request_id, BACKUP_OPERATION, payload)
    assert len(frames) > 1
    assert all(len(frame) <= MAX_SESSION_REQUEST_BYTES + 4 for frame in frames)

    read_fd, write_fd = os.pipe()
    writer = threading.Thread(target=lambda: [os.write(write_fd, frame) for frame in frames[1:]])
    writer.start()
    try:
        decoded = _decode_session_request_from_first(read_fd, frames[0][4:], session_id)
    finally:
        writer.join(2)
        os.close(read_fd)
        os.close(write_fd)
    assert decoded["request_id"] == request_id
    assert decoded["operation"] == BACKUP_OPERATION
    assert decoded["payload"] == payload


def test_large_session_request_rejects_mixed_chunk_sequence():
    from ubackup.privileged.protocol import BACKUP_OPERATION, encode_session_request_frames
    from ubackup.privileged.startup import _decode_session_request_from_first

    session_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    other_request_id = str(uuid.uuid4())
    payload = {"blob": "x" * 300_000}
    frames = encode_session_request_frames(session_id, request_id, BACKUP_OPERATION, payload)
    other = encode_session_request_frames(session_id, other_request_id, BACKUP_OPERATION, payload)
    assert len(frames) > 2 and len(other) == len(frames)

    read_fd, write_fd = os.pipe()
    def write_mixed():
        os.write(write_fd, other[1])
    writer = threading.Thread(target=write_mixed)
    writer.start()
    try:
        with pytest.raises(ProtocolError, match="chunk sequence"):
            _decode_session_request_from_first(read_fd, frames[0][4:], session_id)
    finally:
        os.close(read_fd)
        os.close(write_fd)
        writer.join(2)


def test_large_session_response_is_chunked_and_reassembled_without_256k_limit():
    import json
    from ubackup.privileged.protocol import (
        INSPECT_OPERATION,
        MAX_SESSION_RESPONSE_BYTES,
        MAX_SESSION_RESPONSE_ASSEMBLED_BYTES,
        decode_session_message,
        session_success_frames,
    )

    session_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    result = {"value": [{"path": f"/etc/example/{index}", "note": "x" * 700} for index in range(1500)]}
    frames = session_success_frames(session_id, request_id, INSPECT_OPERATION, result)
    assert len(frames) > 1
    assert all(len(frame) <= MAX_SESSION_RESPONSE_BYTES + 4 for frame in frames)

    chunks = []
    count = None
    for index, frame in enumerate(frames):
        message = decode_session_message(
            frame[4:], session_id=session_id, request_id=request_id, operation=INSPECT_OPERATION
        )
        assert message["type"] == "response-chunk"
        assert message["index"] == index
        count = message["count"]
        chunks.append(message["data"])
    assert count == len(frames)
    assembled = b"".join(chunks)
    assert len(assembled) > 262_144
    assert len(assembled) < MAX_SESSION_RESPONSE_ASSEMBLED_BYTES
    terminal = decode_session_message(
        assembled,
        session_id=session_id,
        request_id=request_id,
        operation=INSPECT_OPERATION,
        limit=MAX_SESSION_RESPONSE_ASSEMBLED_BYTES,
    )
    assert terminal["ok"] is True
    assert terminal["result"] == result


def test_large_session_response_chunks_reject_cross_request_mixing():
    from ubackup.privileged.protocol import (
        INSPECT_OPERATION, ProtocolError, decode_session_message, session_success_frames,
    )
    session_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    other_id = str(uuid.uuid4())
    result = {"value": [{"path": f"/etc/{i}", "note": "x" * 700} for i in range(1000)]}
    frames = session_success_frames(session_id, request_id, INSPECT_OPERATION, result)
    other = session_success_frames(session_id, other_id, INSPECT_OPERATION, result)
    assert len(frames) > 1 and len(other) > 1
    with pytest.raises(ProtocolError, match="identity mismatch"):
        decode_session_message(
            other[1][4:], session_id=session_id, request_id=request_id, operation=INSPECT_OPERATION
        )


def test_session_request_chunking_supports_payloads_beyond_old_eight_megabyte_cap():
    from ubackup.privileged.protocol import (
        BACKUP_OPERATION,
        MAX_SESSION_REQUEST_ASSEMBLED_BYTES,
        encode_session_request_frames,
    )

    session_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    payload = {"blob": "x" * (9 * 1024 * 1024)}
    frames = encode_session_request_frames(session_id, request_id, BACKUP_OPERATION, payload)
    assert len(frames) > 1
    assert MAX_SESSION_REQUEST_ASSEMBLED_BYTES >= 64 * 1024 * 1024
