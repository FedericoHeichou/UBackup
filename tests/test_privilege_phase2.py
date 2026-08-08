import json
import os
import signal
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest

from ubackup.manifest import build_privileged_state
from ubackup.cache import CacheDB
from ubackup.models import ConfigRecord, PackageManager, PackageRecord
from ubackup.paths import PrivilegedPaths
from ubackup.privilege_broker import (
    ACTION_TIMEOUTS,
    BROKER_TERMINATION_GRACE_SECONDS,
    BrokerOperationError,
    BrokerDisconnectedError,
    INSPECTION_TIMEOUTS,
    PrivilegeBroker,
    _bounded_process,
)
from ubackup.privileged.backup import _backup_receipt, validate_backup_payload_for_root
from ubackup.privileged.configure import ConfigureError
from ubackup.privileged.inspect import validate_inspect_payload
from ubackup.privileged import inspect as privileged_inspect
from ubackup.privileged.restore import (
    _staging_target,
    _recorded_package_map,
    validate_inplace_payload,
    validate_packages_payload,
)
from ubackup.privileged.validation import line_value
from ubackup.restic_engine import RESTIC_BACKUP_TIMEOUT, RESTIC_RESTORE_TIMEOUT
from ubackup.privileged import runtime as privileged_runtime
from ubackup.privileged.runtime import CHILD_GRACE_SECONDS, ChildProcessError, Phase2Error, handle_fixed_request
from ubackup.privileged.protocol import (
    BACKUP_OPERATION,
    MAX_CONTROL_FRAME_BYTES,
    MAX_PHASE2_REQUEST_BYTES,
    ProtocolError,
    decode_control_frame,
    decode_response,
    decode_phase2_request,
    decode_phase2_response,
    encode_cancel_frame,
    encode_request_frame,
    encode_json_frame,
    encode_phase2_request,
    phase2_error_response,
    phase2_success_response,
)
from ubackup import system_scan


def request_id():
    return str(uuid.uuid4())


def _start_control_helper(tmp_path):
    source_root = Path("src").resolve()
    helper = tmp_path / "control-helper.py"
    helper.write_text(
        textwrap.dedent(
            f"""
            import os, sys, time
            sys.path.insert(0, {str(source_root)!r})
            os.environ["PKEXEC_UID"] = "1000"
            from ubackup.privileged import runtime
            runtime.os.geteuid = lambda: 0
            from ubackup.privileged.runtime import ensure_not_cancelled, run_fixed_helper

            def validate(payload):
                return dict(payload)

            def handler(request, uid, environment, ops):
                while True:
                    ensure_not_cancelled()
                    time.sleep(0.01)

            run_fixed_helper([], operation="inspect", payload_validator=validate, handler=handler)
            """
        )
    )
    return subprocess.Popen(
        [sys.executable, str(helper)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(source_root)},
    )


def _write_initial_request(process, rid):
    raw = encode_phase2_request(rid, "inspect", "/backup", {"kind": "config-inventory"})
    process.stdin.write(encode_json_frame(raw, limit=MAX_PHASE2_REQUEST_BYTES))
    process.stdin.flush()


def test_phase2_protocol_is_bounded_and_binds_action_and_request_id():
    rid = request_id()
    raw = encode_phase2_request(rid, "inspect", "/backup", {"kind": "config-inventory"})
    with pytest.raises(ProtocolError):
        decode_phase2_request(raw, expected_operation="backup")
    with pytest.raises(ProtocolError):
        decode_phase2_request(b" " * (MAX_PHASE2_REQUEST_BYTES + 1), expected_operation="inspect")
    with pytest.raises(ProtocolError):
        encode_phase2_request(rid, "inspect", "/backup[custom]", {"kind": "config-inventory"})
    with pytest.raises(ProtocolError):
        encode_phase2_request(rid, "inspect", "/backup\n", {"kind": "config-inventory"})
    with pytest.raises(ProtocolError):
        decode_phase2_request(
            (
                '{"version":1,"request_id":"'
                + rid
                + '","request_id":"'
                + request_id()
                + '","operation":"inspect","backup_root":"/backup",'
                '"payload":{"kind":"config-inventory"}}'
            ).encode(),
            expected_operation="inspect",
        )
    response = phase2_success_response(rid, "inspect", 1000, {"ok": True})
    with pytest.raises(ProtocolError):
        decode_phase2_response(response, expected_operation="inspect", expected_request_id=request_id())


def test_control_protocol_is_one_bounded_cancel_frame():
    assert decode_control_frame(encode_cancel_frame()[4:]) == "cancel"
    with pytest.raises(ProtocolError):
        decode_control_frame(b'{"type":"cancel","extra":1}')
    with pytest.raises(ProtocolError):
        decode_control_frame(b'{"type":"run-command"}')
    with pytest.raises(ProtocolError):
        encode_json_frame(b"x" * (MAX_CONTROL_FRAME_BYTES + 1), limit=MAX_CONTROL_FRAME_BYTES)


def test_directory_heap_checks_cancellation_during_large_enumeration(tmp_path, monkeypatch):
    for index in range(256):
        (tmp_path / f"entry-{index:04d}").touch()
    calls = 0

    def checkpoint():
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise Phase2Error("cancelled", "cancelled")

    monkeypatch.setattr(privileged_inspect, "ensure_not_cancelled", checkpoint)
    with pytest.raises(Phase2Error, match="cancelled"):
        privileged_inspect._children(tmp_path, 10, 0)


def test_directory_heap_returns_deterministic_sorted_pages_without_gaps(tmp_path):
    for name in ("zulu", "Alpha", "charlie", "bravo"):
        (tmp_path / name).mkdir()
    for name in ("Echo", "delta", "foxtrot", "gamma"):
        (tmp_path / name).touch()

    page_size = 4
    page_one = privileged_inspect._children(tmp_path, page_size, 0)
    page_two = privileged_inspect._children(tmp_path, page_size, page_size)

    assert [item["name"] for item in page_one] == ["Alpha", "bravo", "charlie", "zulu"]
    assert [item["name"] for item in page_two] == ["delta", "Echo", "foxtrot", "gamma"]
    assert not ({item["name"] for item in page_one} & {item["name"] for item in page_two})
    assert {item["name"] for item in page_one + page_two} == {
        "Alpha", "bravo", "charlie", "zulu", "delta", "Echo", "foxtrot", "gamma"
    }


@pytest.mark.parametrize("directory_kind", ["filesystem", "staging"])
def test_directory_heap_case_variants_are_stable_across_exact_one_item_pages(tmp_path, directory_kind):
    directory = tmp_path / directory_kind
    directory.mkdir()
    for name in ("a", "Z", "z"):
        (directory / name).touch()

    pages = [
        privileged_inspect._children(directory, 1, offset)[0]["name"]
        for offset in range(3)
    ]

    assert pages == ["a", "Z", "z"]
    assert len(pages) == len(set(pages)) == 3


def test_helper_accepts_framed_initial_request_and_cancel_control(tmp_path):
    rid = request_id()
    process = _start_control_helper(tmp_path)
    _write_initial_request(process, rid)
    process.stdin.write(encode_cancel_frame())
    process.stdin.flush()
    stdout, stderr = process.communicate(timeout=5)
    response = decode_phase2_response(stdout, expected_operation="inspect", expected_request_id=rid)
    assert process.returncode == 0, stderr.decode(errors="replace")
    assert response.error_code == "cancelled"


def test_helper_treats_eof_and_invalid_control_as_cancellation_protocols(tmp_path):
    rid = request_id()
    process = _start_control_helper(tmp_path)
    _write_initial_request(process, rid)
    process.stdin.close()
    process.wait(timeout=5)
    stdout = process.stdout.read()
    response = decode_phase2_response(stdout, expected_operation="inspect", expected_request_id=rid)
    assert response.error_code == "cancelled"

    rid = request_id()
    process = _start_control_helper(tmp_path)
    _write_initial_request(process, rid)
    process.stdin.write(encode_json_frame(b'{"type":"not-a-command"}', limit=MAX_CONTROL_FRAME_BYTES))
    process.stdin.flush()
    stdout, stderr = process.communicate(timeout=5)
    response = decode_phase2_response(stdout, expected_operation="inspect", expected_request_id=rid)
    assert process.returncode == 0, stderr.decode(errors="replace")
    assert response.error_code == "protocol_error"


def test_fixed_runtime_returns_bounded_secret_free_errors():
    rid = request_id()
    raw = encode_phase2_request(rid, "inspect", "/backup", {"kind": "config-inventory"})

    def fail(*args):
        raise RuntimeError("secret-password-do-not-return")

    response = decode_phase2_response(
        handle_fixed_request(
            raw,
            operation="inspect",
            payload_validator=validate_inspect_payload,
            handler=fail,
            environment={"PKEXEC_UID": "1000"},
            effective_uid=0,
        ),
        expected_operation="inspect",
        expected_request_id=rid,
    )
    assert response.ok is False
    assert "secret" not in (response.error_message or "")


def test_broker_exposes_fixed_phase2_actions_and_binds_response():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        request = decode_phase2_request(kwargs["input"], expected_operation="inspect")
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=phase2_success_response(request.request_id, request.operation, 1000, {"kind": "config-inventory"}),
            stderr=b"",
        )

    result = PrivilegeBroker(runner=runner, uid_getter=lambda: 1000).inspect(
        "/backup", kind="config-inventory"
    )
    assert result.uid == 1000
    assert calls == [["/usr/bin/pkexec", "/usr/libexec/ubackup-inspect"]]


def test_pure_package_discovery_does_not_need_cache_or_selection(monkeypatch):
    def fake_run(cmd, env, timeout=120):
        if cmd[0] == "apt-mark":
            return subprocess.CompletedProcess(cmd, 0, stdout="demo\n", stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="demo:amd64\t1.0\tamd64\tinstalled\n", stderr="")

    monkeypatch.setattr(system_scan, "_run", fake_run)
    records = system_scan.discover_manual_packages({})
    assert records == [
        {
            "name": "demo", "version": "1.0", "architecture": "amd64",
            "installed": True, "manual": True, "origin": "",
            "manager": "apt", "scope": "system", "channel": "",
            "reference": "", "origin_url": "", "classic": False,
        }
    ]


def test_manifest_plan_lists_metadata_without_excluding_its_parent_tree(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component("filesystem")
    for directory in (paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})
    manifest = build_privileged_state(
        paths,
        {},
        ["/home"],
        ["/home/user/cache"],
        [],
        [PackageRecord("demo", "1", "amd64", True, True)],
        [ConfigRecord("/etc/demo.conf", "unmanaged")],
        components=["filesystem"],
    )
    excludes = paths.excludes_file.read_text()
    sources = paths.sources_file.read_text().splitlines()
    assert str(root) + "/**" not in excludes
    assert str(paths.manifest_file) in sources
    assert str(paths.packages_file) not in sources
    assert manifest["domain"] == "filesystem"
    assert manifest["metadata_suffix"].endswith("manifest.json")

def test_manifest_component_selection_limits_snapshot_policy_metadata(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component("packages")
    for directory in (paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})

    manifest = build_privileged_state(
        paths,
        {},
        ["/home"],
        [],
        [],
        [PackageRecord("demo", "1", "amd64", True, True)],
        [ConfigRecord("/etc/demo.conf", "unmanaged")],
        components=["packages"],
    )

    assert manifest["domain"] == "packages"
    assert manifest["components"] == ["packages"]
    assert manifest["selected_sources"] == []
    assert manifest["selected_config_count"] == 0
    assert manifest["selected_package_count"] == 1
    apt_file = paths.current / "packages-apt.json"
    assert json.loads(apt_file.read_text())[0]["name"] == "demo"
    assert json.loads((paths.current / "packages-snap.json").read_text()) == []
    assert json.loads((paths.current / "packages-flatpak.json").read_text()) == []
    assert json.loads(paths.configs_file.read_text()) == []
    # Potentially huge inventories stay out of the bounded manifest itself.
    assert "selected_packages" not in manifest
    assert "selected_configs" not in manifest

def test_filesystem_navigation_exposes_only_matching_cached_scan(tmp_path):
    cache = CacheDB(tmp_path / "fs.sqlite3")
    cache.put_fs("/home", 1234, 10, 20, 30, 9, scanned_at=42.0)
    fresh = [{"path": "/home", "type": "dir", "size": None, "mtime_ns": 10, "inode": 20, "dev": 30}]
    stale = [{"path": "/home", "type": "dir", "size": None, "mtime_ns": 11, "inode": 20, "dev": 30}]

    privileged_inspect.enrich_filesystem_cache(fresh, cache)
    privileged_inspect.enrich_filesystem_cache(stale, cache)

    assert fresh[0]["size"] == 1234
    assert fresh[0]["scanned_at"] == 42.0
    assert fresh[0]["cache_stale"] is False
    assert stale[0]["size"] == 1234
    assert stale[0]["scanned_at"] == 42.0
    assert stale[0]["cache_stale"] is True
    cache.close()


def test_backup_and_restore_payloads_reject_unsafe_values(tmp_path):
    base = {
        "sources": ["/home"],
        "source_exclusions": [],
        "exclude_rules": [],
        "packages": [],
        "configs": [],
        "components": ["filesystem"],
        "dry_run": True,
        "credentials": {"password": "secret", "password_file": None},
    }
    with pytest.raises(Phase2Error):
        validate_backup_payload_for_root({**base, "sources": ["/backup/repositories/filesystem"]}, "/backup")
    with pytest.raises(Phase2Error):
        validate_backup_payload_for_root({**base, "sources": ["/backup[custom]"]}, "/backup")
    with pytest.raises(Phase2Error):
        validate_backup_payload_for_root({**base, "source_exclusions": ["/home/cache\n"]}, "/backup")
    assert validate_backup_payload_for_root(base, "/backup")["components"] == ["filesystem"]
    with pytest.raises(Phase2Error):
        validate_backup_payload_for_root({**base, "components": []}, "/backup")
    with pytest.raises(Phase2Error):
        validate_backup_payload_for_root({**base, "components": ["filesystem", "packages"]}, "/backup")
    with pytest.raises(Phase2Error):
        validate_backup_payload_for_root({**base, "components": ["unknown"]}, "/backup")
    with pytest.raises(Phase2Error):
        validate_packages_payload({"snapshot_id": "abcdef12", "packages": [{"manager": "apt", "scope": "system", "name": "--no-act"}], "simulate": True, "credentials": base["credentials"]})
    assert validate_inplace_payload(
        {"component": "configs", "snapshot_id": "abcdef12", "includes": ["/etc/ssh/sshd_config"], "credentials": base["credentials"]}
    )["includes"] == ["/etc/ssh/sshd_config"]
    with pytest.raises(Phase2Error):
        validate_inplace_payload(
            {"component": "configs", "snapshot_id": "abcdef12", "includes": ["/etc"], "credentials": base["credentials"]}
        )
    assert validate_inspect_payload({
        "kind": "metadata", "component": "configs", "snapshot_id": "abcdef12", "filename": "manifest.json"
    })

def test_staging_destination_is_derived_and_contained(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path / "backup")
    paths.restores.mkdir(parents=True)
    target = _staging_target(paths, request_id())
    assert paths.restores in target.parents
    assert (target.stat().st_mode & 0o777) == 0o700


def test_phase2_policies_and_installer_reference_all_fixed_helpers():
    names = {
        "inspect": "ubackup-inspect",
        "backup": "ubackup-backup",
        "restore-staging": "ubackup-restore-staging",
        "restore-inplace": "ubackup-restore-inplace",
        "packages-install": "ubackup-packages-install",
    }
    for operation, helper in names.items():
        policy = Path(f"packaging/polkit/org.ubackup.{operation}.policy").read_text()
        assert f"/usr/libexec/{helper}" in policy
        assert "<allow_any>no</allow_any>" in policy
        assert "<allow_inactive>no</allow_inactive>" in policy
        assert "<allow_active>auth_admin</allow_active>" in policy
        wrapper = Path(f"packaging/libexec/{helper}").read_text()
        assert "/usr/bin/python3 -I -B" in wrapper
        assert '"$@"' not in wrapper
    installer = Path("scripts/install_system.sh").read_text()
    assert "ubackup-inspect" in installer
    assert "ubackup-packages-install" in installer
    assert "packaging/launchers" not in installer


def test_phase2_credentials_restore_and_line_inputs_are_bounded():
    with pytest.raises(Phase2Error):
        line_value("/home/user\n/var/lib", "source-list")
    valid_credentials = {"password": "secret", "password_file": None}
    assert validate_inplace_payload(
        {"component": "filesystem", "snapshot_id": "abcdef12", "includes": ["/home/user"], "credentials": valid_credentials}
    )["credentials"] == valid_credentials
    with pytest.raises(Phase2Error):
        validate_inplace_payload(
            {"component": "configs", "snapshot_id": "abcdef12", "includes": ["/etc"], "credentials": valid_credentials}
        )
    assert set(_recorded_package_map([PackageRecord("demo", "1", "amd64", True, True).to_dict()])) == {(PackageManager.APT.value, "system", "demo")}

def test_backup_success_receipt_is_bounded():
    receipt = _backup_receipt(
        {"created_at": "now", "metadata_suffix": "/manifest.json", "effective_sources": ["x"] * 10000, "selected_packages": [], "selected_configs": []},
        {"snapshot_id": "abcdef12", "partial": False},
        False,
    )
    assert receipt["effective_source_count"] == 10000
    assert "effective_sources" not in receipt


def test_helper_deadlines_have_margin_and_realistic_inspection_windows():
    assert RESTIC_BACKUP_TIMEOUT < ACTION_TIMEOUTS["backup"]
    assert RESTIC_RESTORE_TIMEOUT < ACTION_TIMEOUTS["restore-staging"]
    assert INSPECTION_TIMEOUTS["config-inventory"] >= 600
    assert INSPECTION_TIMEOUTS["filesystem-size"] > INSPECTION_TIMEOUTS["config-inventory"]
    with pytest.raises(Phase2Error):
        validate_inspect_payload(
            {
                "kind": "snapshot-directory",
                "snapshot_id": "abcdef12",
                "directory": "/home",
                "limit": 500,
                "offset": 9_501,
                "credentials": {"password": "secret", "password_file": None},
            }
        )


def test_broker_cleanup_budget_is_explicit_and_signal_free():
    assert BROKER_TERMINATION_GRACE_SECONDS > CHILD_GRACE_SECONDS
    assert BROKER_TERMINATION_GRACE_SECONDS > 0


def test_cancelled_helper_reaps_child_and_cleans_request_artifacts(tmp_path):
    plans = tmp_path / "plans"
    plans.mkdir()
    pid_file = tmp_path / "child.pid"
    script = textwrap.dedent(
        """
        import os, shutil, sys, time
        from pathlib import Path
        from ubackup.privileged.protocol import encode_phase2_request
        from ubackup.privileged.runtime import handle_fixed_request, install_cancellation_handler
        from ubackup.restic_engine import ResticEngine

        plans = Path(sys.argv[1])
        pid_file = Path(sys.argv[2])

        def validate(payload):
            return dict(payload)

        def handler(request, uid, environment, ops):
            plan = plans / request.request_id
            plan.mkdir(mode=0o700)
            (plan / "restic-password").write_text("private")
            child = (
                "import os,time; "
                f"open({str(pid_file)!r}, 'w').write(str(os.getpid())); "
                "time.sleep(30)"
            )
            try:
                ResticEngine._stream_process([sys.executable, "-c", child], {}, lambda _: None, timeout=30)
            finally:
                shutil.rmtree(plan, ignore_errors=True)
            return {"unexpected": True}

        install_cancellation_handler()
        raw = encode_phase2_request(
            "123e4567-e89b-12d3-a456-426614174000",
            "inspect",
            "/backup",
            {"sleep": True},
        )
        response = handle_fixed_request(
            raw,
            operation="inspect",
            payload_validator=validate,
            handler=handler,
            environment={"PKEXEC_UID": "1000"},
            effective_uid=0,
        )
        sys.stdout.buffer.write(response)
        """
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(plans), str(pid_file)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(Path("src").resolve())},
    )
    deadline = time.monotonic() + 5
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pid_file.exists()
    request_plan = plans / "123e4567-e89b-12d3-a456-426614174000"
    assert (request_plan / "restic-password").exists()
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)
    assert process.returncode == 0, stderr.decode(errors="replace")
    assert b'"ok":false' in stdout
    assert b'"code":"cancelled"' in stdout
    assert not request_plan.exists()
    child_pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_child_registration_closes_pre_registration_cancellation_race(tmp_path, monkeypatch):
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        start_new_session=True,
    )
    pgid = os.getpgid(process.pid)
    monkeypatch.setattr(privileged_runtime, "_cancellation_requested", True)
    with pytest.raises(ChildProcessError) as caught:
        privileged_runtime.register_child_group(pgid, process)
    assert caught.value.code == "cancelled"
    assert process.poll() is not None
    with pytest.raises(ProcessLookupError):
        os.kill(process.pid, 0)
    assert privileged_runtime._active_child_group is None


def test_broker_timeout_uses_control_cancel_and_helper_cleans_nested_children(tmp_path, monkeypatch):
    plans = tmp_path / "plans"
    plans.mkdir()
    leader_file = tmp_path / "leader.pid"
    grandchild_file = tmp_path / "grandchild.pid"
    fake_pkexec = tmp_path / "fake-pkexec"
    source_root = Path("src").resolve()
    fake_pkexec.write_text(
        textwrap.dedent(
            f"""
            #!{sys.executable}
            import os
            import shutil
            import sys
            from pathlib import Path

            sys.path.insert(0, {str(source_root)!r})
            os.environ["PKEXEC_UID"] = "1000"
            from ubackup.privileged import runtime
            runtime.os.geteuid = lambda: 0
            from ubackup.privileged.runtime import ensure_not_cancelled, run_fixed_helper
            from ubackup.restic_engine import ResticEngine

            plans = Path({str(plans)!r})
            leader_file = Path({str(leader_file)!r})
            grandchild_file = Path({str(grandchild_file)!r})

            def validate(payload):
                return dict(payload)

            def handler(request, uid, environment, ops):
                plan = plans / request.request_id
                plan.mkdir(mode=0o700)
                (plan / "restic-password").write_text("private")
                child = (
                    "import os,signal,subprocess,sys,time; "
                    f"open({str(leader_file)!r}, 'w').write(str(os.getpid())); "
                    f"grand=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); open({str(grandchild_file)!r}, 'w').write(str(grand.pid)); "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                    "time.sleep(30)"
                )
                try:
                    ResticEngine._stream_process([sys.executable, "-c", child], {{}}, lambda _: None, timeout=30)
                finally:
                    shutil.rmtree(plan, ignore_errors=True)
                return {{"unexpected": True}}

            run_fixed_helper([], operation="inspect", payload_validator=validate, handler=handler)
            """
        )
    )
    import ubackup.privilege_broker as broker_module
    monkeypatch.setattr(broker_module, "PKEXEC_EXECUTABLE", sys.executable)
    monkeypatch.setattr(
        broker_module,
        "ALLOWED_HELPERS",
        broker_module.MappingProxyType({**broker_module.ALLOWED_HELPERS, "inspect": str(fake_pkexec)}),
    )
    monkeypatch.setattr(broker_module.os, "killpg", lambda *_args: (_ for _ in ()).throw(AssertionError("broker signalled helper")))
    with pytest.raises(BrokerOperationError) as caught:
        PrivilegeBroker(timeout=1.5, uid_getter=lambda: 1000).inspect(
            tmp_path / "backup", kind="config-inventory"
        )
    assert caught.value.code == "cancelled"
    assert leader_file.exists() and grandchild_file.exists()
    for pid_file in (leader_file, grandchild_file):
        child_pid = int(pid_file.read_text())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail(f"child {child_pid} survived helper cancellation")
    assert list(plans.iterdir()) == []


def test_broker_nonblocking_request_deadline_handles_delayed_reader(tmp_path, monkeypatch):
    """A full pipe must not turn the initial broker write into an unbounded wait."""
    fake_pkexec = tmp_path / "delayed-pkexec.py"
    fake_pkexec.write_text(
        textwrap.dedent(
            """
            import sys, time
            # Deliberately do not read stdin until after the broker deadline.
            time.sleep(0.35)
            sys.stdin.buffer.read()
            """
        )
    )
    source_root = Path("src").resolve()
    monkeypatch.setattr("ubackup.privilege_broker.PKEXEC_EXECUTABLE", sys.executable)
    monkeypatch.setattr(
        "ubackup.privilege_broker.ALLOWED_HELPERS",
        type(PrivilegeBroker.allowed_helpers)(
            {**PrivilegeBroker.allowed_helpers, BACKUP_OPERATION: str(fake_pkexec)}
        ),
    )
    monkeypatch.setattr("ubackup.privilege_broker.BROKER_CLEANUP_BUDGET_SECONDS", 1.0)

    # Larger than a normal Linux pipe, but still within the protocol bound.
    sources = [f"/home/user/project-{index:05d}" for index in range(3000)]
    started = time.monotonic()
    with pytest.raises(BrokerDisconnectedError) as caught:
        PrivilegeBroker(timeout=0.05, uid_getter=lambda: 1000).backup(
            tmp_path / "backup",
            sources=sources,
            source_exclusions=[],
            exclude_rules=[],
            packages=[],
            configs=[],
            dry_run=True,
        )
    elapsed = time.monotonic() - started
    assert caught.value.code == "request_timeout"
    assert elapsed < 2.0


def test_configure_control_cancel_stops_between_provisioning_mutations(tmp_path):
    """The retained configure pipe cancels a multi-step operation at a checkpoint."""
    source_root = Path("src").resolve()
    marker = tmp_path / "mutations"
    marker.mkdir()
    helper = tmp_path / "configure-control.py"
    helper.write_text(
        textwrap.dedent(
            f"""
            import os, time
            from pathlib import Path
            os.environ["PKEXEC_UID"] = "1000"
            os.environ["PYTHONPATH"] = {str(source_root)!r}
            from ubackup.privileged import configure
            configure.os.geteuid = lambda: 0

            def fake_provision(root, uid, *, ops=None, checkpoint=None):
                for index in range(5):
                    checkpoint()
                    (Path({str(marker)!r}) / str(index)).write_text("mutation")
                    time.sleep(0.3 if index == 0 else 0.05)
                return configure.GuiPaths.for_user(root, uid)

            configure.provision_user_runtime = fake_provision
            raise SystemExit(configure.main([]))
            """
        )
    )
    process = subprocess.Popen(
        [sys.executable, str(helper)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "PYTHONPATH": str(source_root)},
    )
    assert process.stdin is not None
    process.stdin.write(encode_request_frame("configure", str(tmp_path / "backup")))
    process.stdin.flush()
    first_mutation = marker / "0"
    deadline = time.monotonic() + 2
    while not first_mutation.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert first_mutation.exists()
    process.stdin.write(encode_cancel_frame())
    process.stdin.flush()
    stdout, stderr = process.communicate(timeout=5)
    response = decode_response(stdout, expected_operation="configure")
    assert process.returncode == 0, stderr.decode(errors="replace")
    assert response.ok is False
    assert response.error_code == "cancelled"
    assert sorted(path.name for path in marker.iterdir()) == ["0"]


def test_stale_request_cleanup_is_conservative(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path / "backup")
    paths.plans.mkdir(parents=True)
    invalid = paths.plans / "not-a-request"
    invalid.mkdir(mode=0o700)
    valid_but_not_root_owned = paths.plans / "123e4567-e89b-12d3-a456-426614174000"
    valid_but_not_root_owned.mkdir(mode=0o700)
    assert paths.cleanup_stale_request_artifacts(now=time.time() + 10, max_age_seconds=0) == []
    assert invalid.exists()
    assert valid_but_not_root_owned.exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="requires root-owned crash artifact")
def test_stale_root_owned_request_artifact_is_removed(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path / "backup")
    paths.plans.mkdir(parents=True, mode=0o700)
    request_plan = paths.plans / "123e4567-e89b-12d3-a456-426614174000"
    request_plan.mkdir(mode=0o700)
    (request_plan / "restic-password").write_text("private")
    old = time.time() - 10
    os.utime(request_plan, (old, old))
    removed = paths.cleanup_stale_request_artifacts(now=time.time(), max_age_seconds=1)
    assert removed == [request_plan]
    assert not request_plan.exists()


def test_curated_etc_component_uses_explicit_sources_without_filesystem_excludes(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component("configs")
    for directory in (paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime):
        directory.mkdir(parents=True, exist_ok=True)
    chosen = tmp_path / "sshd_config"
    # ConfigRecord paths are expected under /etc, but this unit test only checks
    # plan construction, so provide a real file and patch its recorded path.
    chosen.write_text("Port 22\n")
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})
    config = ConfigRecord("/etc/ssh/sshd_config", "unmanaged")
    monkeypatch.setattr("ubackup.manifest.Path.exists", lambda self: True)
    build_privileged_state(
        paths, {}, [], [], [], [], [config], components=["configs"]
    )
    excludes = [line for line in paths.excludes_file.read_text().splitlines() if line]
    sources = paths.sources_file.read_text().splitlines()
    assert "/etc/**" not in excludes
    assert "/etc/ssh/sshd_config" in sources

def test_filesystem_navigation_cache_marks_profile_mismatch_stale_without_hiding_values(tmp_path):
    from ubackup.fs_scan import scan_cache_key

    cache = CacheDB(tmp_path / "fs-profile.sqlite3")
    try:
        key = scan_cache_key(["**/node_modules/**"])
        cache.put_fs("/home", 1234, 10, 20, 30, 9, scanned_at=42.0, scan_key=key)
        matching = [{"path": "/home", "type": "dir", "size": None, "mtime_ns": 10, "inode": 20, "dev": 30}]
        other = [{"path": "/home", "type": "dir", "size": None, "mtime_ns": 10, "inode": 20, "dev": 30}]

        privileged_inspect.enrich_filesystem_cache(matching, cache, key)
        privileged_inspect.enrich_filesystem_cache(other, cache, scan_cache_key([]))

        assert matching[0]["size"] == 1234
        assert matching[0]["cache_stale"] is False
        assert other[0]["size"] == 1234
        assert other[0]["scanned_at"] == 42.0
        assert other[0]["cache_stale"] is True
        assert other[0]["profile_stale"] is True
    finally:
        cache.close()


def test_inspect_filesystem_size_accepts_bounded_exclusion_patterns():
    payload = privileged_inspect.validate_inspect_payload({
        "kind": "filesystem-size",
        "path": "/home",
        "exclude_patterns": ["**/node_modules/**", "/etc/**"],
        "force": True,
    })
    assert payload["exclude_patterns"] == ["**/node_modules/**", "/etc/**"]
    assert payload["force"] is True

    with pytest.raises(Phase2Error):
        privileged_inspect.validate_inspect_payload({
            "kind": "filesystem-size",
            "path": "/home",
            "exclude_patterns": ["bad\npattern"],
        })


def test_inspect_filesystem_children_is_live_only_and_allows_one_full_directory_page():
    payload = privileged_inspect.validate_inspect_payload({
        "kind": "filesystem-children",
        "path": "/home",
        "limit": 10_000,
        "offset": 0,
        "exclude_patterns": [],
    })
    assert payload["limit"] == 10_000
    assert "cache_only" not in payload

    with pytest.raises(Phase2Error):
        privileged_inspect.validate_inspect_payload({
            "kind": "filesystem-children",
            "path": "/home",
            "limit": 500,
            "offset": 0,
            "exclude_patterns": [],
            "cache_only": True,
        })


def test_inspect_filesystem_cache_accepts_bounded_paths_and_profile():
    payload = privileged_inspect.validate_inspect_payload({
        "kind": "filesystem-cache",
        "paths": ["/home", "/usr/local/bin"],
        "exclude_patterns": ["**/node_modules/**"],
    })
    assert payload == {
        "kind": "filesystem-cache",
        "paths": ["/home", "/usr/local/bin"],
        "exclude_patterns": ["**/node_modules/**"],
    }
    with pytest.raises(Phase2Error):
        privileged_inspect.validate_inspect_payload({
            "kind": "filesystem-cache",
            "paths": ["relative/path"],
            "exclude_patterns": [],
        })


def test_backup_payload_allows_large_but_still_bounded_config_policy_inventory():
    base = {
        "sources": [],
        "source_exclusions": [],
        "exclude_rules": [],
        "packages": [],
        "configs": [
            {
                "path": f"/etc/ubackup-test/{index}",
                "kind": "unmanaged",
                "package": "",
                "selected": False,
                "size": 1,
                "mtime_ns": 1,
            }
            for index in range(3000)
        ],
        "components": ["configs"],
        "dry_run": True,
        "credentials": {"password": "secret", "password_file": None},
    }
    validated = validate_backup_payload_for_root(base, "/backup")
    assert len(validated["configs"]) == 3000


def test_backup_plan_splits_ancestor_source_around_backup_root(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component("filesystem")
    for directory in (paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})
    home = tmp_path / "home"
    home.mkdir()
    # Effective sources are an input to the manifest builder after structural
    # splitting by the privileged backup planner.
    build_privileged_state(
        paths, {}, ["/"], [], [], [], [], components=["filesystem"],
        effective_filesystem_sources=[str(home)],
    )
    sources = paths.sources_file.read_text().splitlines()
    assert str(home) in sources
    assert str(paths.manifest_file) in sources
    assert "/" not in sources

def test_config_only_plan_does_not_filter_curated_etc_sources(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component("configs")
    for directory in (paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})
    monkeypatch.setattr("ubackup.manifest.Path.exists", lambda self: True)
    manifest = build_privileged_state(
        paths, {}, [], [], [], [], [ConfigRecord("/etc/example.conf", "unmanaged")],
        components=["configs"],
    )
    assert manifest["domain"] == "configs"
    assert manifest["selected_config_count"] == 1
    assert "/etc/example.conf" in paths.sources_file.read_text().splitlines()
    assert "/etc/**" not in paths.excludes_file.read_text().splitlines()

def test_multi_component_snapshot_is_rejected_by_domain_architecture(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root)
    for directory in (paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})
    with pytest.raises(ValueError, match="exactly one backup component"):
        build_privileged_state(
            paths, {}, ["/home"], [], [], [], [ConfigRecord("/etc/example.conf", "unmanaged")],
            components=["filesystem", "configs"],
        )
