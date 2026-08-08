import subprocess
import sys
import threading
import time
from typing import Any, cast

import pytest

from ubackup.privilege_broker import (
    BrokerOperationError,
    BrokerProtocolError,
    BrokerSubprocessError,
    BROKER_CLEANUP_BUDGET_SECONDS,
    BROKER_POLKIT_AUTHORIZATION_SECONDS,
    BROKER_READY_WINDOW_SECONDS,
    BROKER_PLAN_WINDOW_SECONDS,
    BROKER_START_DELIVERY_SECONDS,
    STARTUP_HELPER_READY_SECONDS,
    STARTUP_HELPER_PLAN_SECONDS,
    PrivilegeBroker,
)


CHILD = r'''
import base64, json, os, struct, sys, time
def read():
    h=sys.stdin.buffer.read(4)
    if not h:return None
    n=struct.unpack(">I",h)[0]
    return json.loads(sys.stdin.buffer.read(n))
def send(v):
    x=json.dumps(v,separators=(",",":")).encode()
    sys.stdout.buffer.write(struct.pack(">I",len(x))+x);sys.stdout.buffer.flush()
q=read(); rid=q["request_id"]; mode=os.environ["UBACKUP_TEST_MODE"]
if mode == "pre-error":
    send({"type":"error","request_id":rid,"code":"admission_failed","message":"rejected"}); raise SystemExit
ready={"type":"ready","version":1,"operation":"startup","uid":1000,
       "user_root":"/backup/.ubackup/users/1000","request_id":rid}
if mode == "ready-delay": time.sleep(.12)
if mode == "wrong-id": ready["request_id"]="00000000-0000-4000-8000-000000000001"
if mode == "wrong-uid": ready["uid"]=1001
if mode == "wrong-root": ready["user_root"]="/backup/other"
send(ready)
command=read()
if mode == "eof-before-start": raise SystemExit
if mode == "late-done": time.sleep(.25)
if mode == "plan-wait":
    # Remain alive until cancel/EOF; this exercises close while events reads.
    read(); send({"type":"error","request_id":rid,"code":"cancelled","message":"cancelled"})
    raise SystemExit
if mode == "plan-eof":
    raise SystemExit
if mode == "nav":
    send({"type":"done","request_id":rid})
    send({"type":"navigation-ready","session_id":rid})
    req=read()
    send({"type":"navigation-result","session_id":rid,"request_id":req["request_id"],"operation":"filesystem-children","records":[],"next_offset":None,"final":True,"truncated":False})
    raise SystemExit
if mode == "rpc-large":
    send({"type":"done","request_id":rid})
    send({"type":"navigation-ready","session_id":rid})
    req=read()
    if req["type"] == "session-request-chunk":
        chunks=[base64.b64decode(req["data"])]
        count=req["count"]
        for expected in range(1,count):
            part=read()
            assert part["type"] == "session-request-chunk" and part["index"] == expected
            assert part["request_id"] == req["request_id"] and part["session_id"] == rid
            chunks.append(base64.b64decode(part["data"]))
        req=json.loads(b"".join(chunks))
    send({"type":"session-response","session_id":rid,"request_id":req["request_id"],"operation":req["operation"],"ok":True,"result":{"received":len(req["payload"].get("blob",""))}})
    read()
    raise SystemExit
send({"type":"done","request_id":rid})
if mode == "success":
    send({"type":"navigation-ready","session_id":rid})
'''


def broker_for(mode, *, windows=None, holder=None):
    def factory(_command, **kwargs):
        env = dict(kwargs["env"])
        env["UBACKUP_TEST_MODE"] = mode
        kwargs["env"] = env
        process = cast(Any, subprocess.Popen([sys.executable, "-c", CHILD], **kwargs))
        if holder is not None:
            holder.append(process)
        return process
    return PrivilegeBroker(uid_getter=lambda: 1000, startup_process_factory=factory,
                           startup_windows=windows or {"ready": 2, "start": 2, "plan": 2})


def test_public_broker_ready_worker_events_and_reap():
    processes = []
    result, session = broker_for("success", holder=processes).begin_startup("/backup")
    assert result.uid == 1000
    session.start(password="secret")
    events = list(session.events())
    assert events and events[-1]["type"] == "navigation-ready"
    session.close()
    assert processes[0].poll() == 0
    assert processes[0].stdin.closed and processes[0].stdout.closed and processes[0].stderr.closed


@pytest.mark.parametrize("mode", ["wrong-id", "wrong-uid", "wrong-root"])
def test_public_broker_identity_mismatch_cleans_up(mode):
    with pytest.raises(BrokerProtocolError):
        broker_for(mode).begin_startup("/backup")


def test_public_broker_pre_ready_error_is_operation_error():
    with pytest.raises(BrokerOperationError):
        broker_for("pre-error").begin_startup("/backup")


def test_public_broker_eof_before_start_is_cleaned_up():
    _, session = broker_for("eof-before-start").begin_startup("/backup")
    session.close()


def test_public_broker_eof_during_plan_is_cleaned_up():
    _, session = broker_for("plan-wait").begin_startup("/backup")
    session.start(password="secret")
    session.close()


def test_public_broker_worker_close_does_not_steal_reader():
    processes = []
    _, session = broker_for("plan-wait", holder=processes).begin_startup("/backup")
    session.start(password="secret")
    errors = []
    worker = threading.Thread(target=lambda: _consume(session, errors))
    worker.start()
    time.sleep(.05)
    session.close()
    worker.join(3)
    assert not worker.is_alive()
    assert not errors
    assert processes[0].poll() == 0
    assert processes[0].stdin.closed and processes[0].stdout.closed and processes[0].stderr.closed


def _consume(session, errors):
    try:
        list(session.events())
    except Exception as exc:
        errors.append(exc)


def test_public_broker_late_done_is_timeout_failure():
    _, session = broker_for("late-done", windows={"ready": 2, "start": 2, "plan": .05}).begin_startup("/backup")
    session.start(password="secret")
    with pytest.raises((BrokerSubprocessError, BrokerProtocolError)):
        list(session.events())


def test_production_windows_include_helper_phases_and_cleanup_margin():
    assert BROKER_READY_WINDOW_SECONDS >= BROKER_POLKIT_AUTHORIZATION_SECONDS + STARTUP_HELPER_READY_SECONDS + BROKER_CLEANUP_BUDGET_SECONDS
    assert BROKER_PLAN_WINDOW_SECONDS >= BROKER_START_DELIVERY_SECONDS + STARTUP_HELPER_PLAN_SECONDS + BROKER_CLEANUP_BUDGET_SECONDS


def test_delayed_ready_is_allowed_only_inside_broker_ready_window():
    _, session = broker_for("ready-delay", windows={"ready": 3.0, "start": 2, "plan": 2}).begin_startup("/backup")
    session.close()
    with pytest.raises(BrokerSubprocessError):
        broker_for("ready-delay", windows={"ready": .01, "start": 2, "plan": 2}).begin_startup("/backup")


def test_public_broker_no_terminal_eof_still_finalizes_worker():
    processes = []
    _, session = broker_for("plan-eof", holder=processes).begin_startup("/backup")
    session.start(password="secret")
    errors = []
    worker = threading.Thread(target=lambda: _consume(session, errors))
    worker.start(); worker.join(3)
    assert not worker.is_alive()
    assert errors and errors[0].__class__.__name__ == "BrokerDisconnectedError"
    assert processes[0].poll() == 0
    assert processes[0].stdin.closed and processes[0].stdout.closed and processes[0].stderr.closed


def test_public_broker_navigation_ready_exposes_only_children_exchange():
    _, session = broker_for("nav").begin_startup("/backup")
    session.start(password="secret")
    events = list(session.events())
    assert events and events[-1]["type"] == "navigation-ready"
    page = session.filesystem_children("/tmp", limit=10, offset=0)
    assert page["type"] == "navigation-result" and page["records"] == []
    session.close()


def test_public_broker_large_typed_rpc_uses_chunked_transport():
    _, session = broker_for("rpc-large").begin_startup("/backup")
    session.start(password="secret")
    assert list(session.events())[-1]["type"] == "navigation-ready"
    result = session.request("inspect", {"blob": "x" * 300_000})
    assert result == {"received": 300_000}
    session.close()
