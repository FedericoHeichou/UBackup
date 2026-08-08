import subprocess
import sys
import threading
import time
import uuid

from ubackup.privilege_broker import StartupSession
from ubackup.privileged.protocol import encode_startup_request_frame_with_id


SCRIPT = r'''
import json, struct, sys
def read():
    header = sys.stdin.buffer.read(4)
    if not header:
        return None
    size = struct.unpack(">I", header)[0]
    return json.loads(sys.stdin.buffer.read(size))
def frame(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack(">I", len(raw)) + raw
request = read()
rid = request["request_id"]
sys.stdout.buffer.write(frame({"type":"ready", "version":1, "operation":"startup",
                               "uid":1000, "user_root":"/backup/u", "request_id":rid}))
sys.stdout.buffer.flush()
command = read()
if command is not None:
    sys.stdout.buffer.write(frame({"type":"done", "request_id":rid}))
    sys.stdout.buffer.flush()
'''


def make_process(rid):
    process = subprocess.Popen([sys.executable, "-c", SCRIPT], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert process.stdin is not None
    process.stdin.write(encode_startup_request_frame_with_id("/backup", rid))
    process.stdin.flush()
    return process


def test_ready_handoff_then_worker_events_reaps_process():
    rid = str(uuid.uuid4())
    process = make_process(rid)
    session = StartupSession(process, rid, deadline=time.monotonic() + 5)
    ready = session._read_one(); assert ready is not None and ready["type"] == "ready"
    session._reader_thread = None  # begin_startup explicitly performs this handoff.
    session.start(password="secret")
    errors = []

    def consume():
        try:
            assert list(session.events()) == []
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=consume)
    worker.start(); worker.join(3)
    assert not errors
    assert process.poll() == 0
    session.close()


def test_second_events_consumer_is_rejected():
    rid = str(uuid.uuid4())
    process = make_process(rid)
    session = StartupSession(process, rid, deadline=time.monotonic() + 5)
    ready = session._read_one(); assert ready is not None and ready["type"] == "ready"
    session.start(password="secret")
    session._reader_thread = threading.get_ident()
    errors = []

    def consume():
        try:
            list(session.events())
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=consume)
    worker.start(); worker.join(2)
    assert errors
    session.close()


def test_startup_session_reassembles_large_chunked_terminal_response_over_real_pipe(tmp_path):
    """Exercise StartupSession.request itself, not only protocol encoders."""
    import textwrap

    session_id = str(uuid.uuid4())
    source_root = str((__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))
    script = textwrap.dedent(
        f"""
        import json, struct, sys
        sys.path.insert(0, {source_root!r})
        from ubackup.privileged.protocol import session_success_frames

        header = sys.stdin.buffer.read(4)
        if len(header) != 4:
            raise SystemExit(2)
        size = struct.unpack(">I", header)[0]
        request = json.loads(sys.stdin.buffer.read(size))
        result = {{"value": [{{"path": f"/etc/item-{{i}}", "note": "x" * 900}} for i in range(1200)]}}
        for frame in session_success_frames(
            request["session_id"], request["request_id"], request["operation"], result
        ):
            sys.stdout.buffer.write(frame)
        sys.stdout.buffer.flush()
        """
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    session = StartupSession(process, session_id, deadline=time.monotonic() + 10)
    session._navigation_ready = True
    session._started = True
    try:
        result = session.request("inspect", {"kind": "repository-size"}, timeout=10)
        assert isinstance(result, dict)
        assert len(result["value"]) == 1200
        assert sum(len(item["note"]) for item in result["value"]) > 1_000_000
    finally:
        process.wait(timeout=5)
        session.close()
