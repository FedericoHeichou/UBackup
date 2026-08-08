import json
import os
import stat
import subprocess
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

import pytest

from ubackup.paths import GuiPaths, PrivilegedPaths
from ubackup.privilege_broker import BrokerError, BrokerProtocolError, BrokerSubprocessError, PrivilegeBroker
from ubackup.privileged.configure import (
    APPROVAL_MARKER_CONTENT,
    APPROVAL_MARKER_MODE,
    RootAdmission,
    ConfigureError,
    admit_backup_root,
    handle_request,
    prepare_backup_root,
    provision_user_runtime,
    validated_pkexec_uid,
    validate_backup_root,
)
from ubackup.privileged.protocol import (
    MAX_REQUEST_BYTES,
    RESERVED_UID_MAX,
    ProtocolError,
    decode_request,
    decode_response,
    encode_request,
)


def test_protocol_rejects_unknown_fields_mismatch_and_oversize():
    with pytest.raises(ProtocolError):
        decode_request(b'{"version":1,"operation":"configure","backup_root":"/b","extra":1}')
    with pytest.raises(ProtocolError) as mismatch:
        decode_request(b'{"version":1,"operation":"configure","backup_root":"/b"}', expected_operation="other")
    assert mismatch.value.code == "operation_mismatch"
    with pytest.raises(ProtocolError) as oversized:
        decode_request(b" " * (MAX_REQUEST_BYTES + 1))
    assert oversized.value.code == "message_too_large"


def test_protocol_rejects_duplicate_and_malformed_json():
    with pytest.raises(ProtocolError):
        decode_request(b'{"version":1,"version":1,"operation":"configure","backup_root":"/b"}')
    with pytest.raises(ProtocolError):
        decode_response(b'{"version":1,"operation":"configure","ok":true,"uid":1}')

    for version in (True, False):
        with pytest.raises(ProtocolError):
            decode_response(
                json.dumps(
                    {
                        "version": version,
                        "operation": "configure",
                        "ok": True,
                        "uid": 1000,
                        "user_root": "/backup/.ubackup/users/1000",
                    }
                ).encode()
            )
    for uid in (0, RESERVED_UID_MAX):
        with pytest.raises(ProtocolError):
            decode_response(
                json.dumps(
                    {
                        "version": 1,
                        "operation": "configure",
                        "ok": True,
                        "uid": uid,
                        "user_root": "/backup/.ubackup/users/1000",
                    }
                ).encode()
            )


def test_path_models_keep_gui_data_below_user_leaf(tmp_path):
    gui = GuiPaths.for_user(tmp_path / "backup", 1000)
    for field in fields(GuiPaths):
        value = getattr(gui, field.name)
        if isinstance(value, Path):
            assert value == gui.user_root or gui.user_root in value.parents

    privileged = PrivilegedPaths.for_root(tmp_path / "backup")
    assert privileged.repository != gui.user_root
    assert not hasattr(privileged, "db")


class _FakeOps:
    def __init__(self, *, non_traversable=()):
        self.owners = {}
        self.created = []
        self.chmod_calls = []
        self.chown_calls = []
        self.non_traversable = {Path(path) for path in non_traversable}

    def lstat(self, path):
        path = Path(path)
        info = os.lstat(path)
        # The seam models a root-owned, non-writable ancestry even though
        # pytest's temporary directory is normally beneath /tmp.
        mode = info.st_mode & ~0o022
        if stat.S_ISDIR(info.st_mode) and path not in self.non_traversable:
            mode |= 0o001
        return SimpleNamespace(
            st_mode=mode,
            st_uid=self.owners.get(path, 0),
            st_dev=info.st_dev,
            st_ino=info.st_ino,
        )

    def mkdir(self, path, mode):
        path = Path(path)
        os.mkdir(path, mode)
        self.owners[path] = 0
        self.created.append(path)

    def chmod(self, path, mode, **kwargs):
        self.chmod_calls.append((Path(path), mode))
        os.chmod(path, mode, follow_symlinks=False)

    def chown(self, path, uid, gid, **kwargs):
        self.chown_calls.append((Path(path), uid, gid))
        self.owners[Path(path)] = uid




def test_prepare_backup_root_creates_only_missing_default(tmp_path, monkeypatch):
    import ubackup.privileged.configure as configure

    default_root = tmp_path / "backup"
    monkeypatch.setattr(configure, "DEFAULT_BACKUP_ROOT", default_root)
    ops = _FakeOps()

    admission = prepare_backup_root(default_root, ops=ops)
    assert admission.root == default_root
    assert default_root in ops.created
    assert (default_root.stat().st_mode & 0o777) == 0o711

    custom_root = tmp_path / "custom-missing"
    with pytest.raises(ConfigureError, match="ancestry does not exist"):
        prepare_backup_root(custom_root, ops=ops)
    assert custom_root not in ops.created

def test_configure_provisions_only_requested_user_leaf(tmp_path):
    root = tmp_path / "backup"
    root.mkdir(mode=0o755)
    root.chmod(0o700)  # protected root must become traversable to the user leaf
    approval_parent = root / ".ubackup"
    approval_parent.mkdir(mode=0o700)
    approval = approval_parent / "approved"
    approval.write_bytes(b"ubackup-root-v1\n")
    approval.chmod(0o600)
    repositories = root / "repositories"
    repositories.mkdir()
    ops = _FakeOps()

    paths = provision_user_runtime(root, 1000, ops=ops)

    assert paths.user_root == root / ".ubackup" / "users" / "1000"
    assert sorted(p.name for p in (root / ".ubackup").iterdir()) == ["approved", "users"]
    assert [p.name for p in (root / ".ubackup" / "users").iterdir()] == ["1000"]
    assert (root.stat().st_mode & 0o777) == 0o711
    assert (approval_parent.stat().st_mode & 0o777) == 0o711
    assert ((approval_parent / "users").stat().st_mode & 0o777) == 0o711
    assert all((p.stat().st_mode & 0o777) == 0o700 for p in paths.directories())
    assert ops.owners[paths.user_root] == 1000
    assert repositories.exists()


def test_configure_checkpoint_stops_between_provisioning_mutations(tmp_path):
    root = tmp_path / "backup"
    root.mkdir(mode=0o755)
    root.chmod(0o700)
    approval_parent = root / ".ubackup"
    approval_parent.mkdir(mode=0o700)
    approval = approval_parent / "approved"
    approval.write_bytes(APPROVAL_MARKER_CONTENT)
    approval.chmod(APPROVAL_MARKER_MODE)
    calls = 0

    def checkpoint():
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise ConfigureError("cancelled", "cancelled")

    with pytest.raises(ConfigureError, match="cancelled"):
        provision_user_runtime(root, 1000, ops=_FakeOps(), checkpoint=checkpoint)
    assert not (root / ".ubackup" / "users").exists()


def test_default_and_system_roots_are_rejected_before_filesystem_mutation():
    ops = _FakeOps()
    for root in ("/", "/etc", "/usr", "/var", "/home", "/root", "/proc", "/sys", "/dev", "/run"):
        with pytest.raises(ConfigureError):
            provision_user_runtime(root, 1000, ops=ops)
    assert ops.created == []
    assert ops.chmod_calls == []
    assert ops.chown_calls == []


def test_approval_marker_must_exist_and_match_exact_security_contract(tmp_path):
    root = tmp_path / "approved-root"
    root.mkdir()
    ops = _FakeOps()
    with pytest.raises(ConfigureError, match="approved"):
        admit_backup_root(root, ops=ops)

    marker_parent = root / ".ubackup"
    marker_parent.mkdir(mode=0o700)
    marker = marker_parent / "approved"
    marker.write_bytes(APPROVAL_MARKER_CONTENT)
    marker.chmod(APPROVAL_MARKER_MODE)
    admission = admit_backup_root(root, ops=ops)
    assert isinstance(admission, RootAdmission)

    marker.chmod(0o644)
    with pytest.raises(ConfigureError, match="mode"):
        admit_backup_root(root, ops=ops)
    marker.chmod(APPROVAL_MARKER_MODE)
    marker.write_bytes(b"wrong\n")
    with pytest.raises(ConfigureError, match="content"):
        admit_backup_root(root, ops=ops)


def test_unsafe_ancestry_and_symlink_components_do_not_mutate(tmp_path):
    root = tmp_path / "unsafe"
    root.mkdir()
    ops = _FakeOps()
    original_lstat = ops.lstat

    def writable_root(path):
        info = original_lstat(path)
        if Path(path) == root:
            info.st_mode |= 0o002
        return info

    ops.lstat = writable_root
    with pytest.raises(ConfigureError):
        provision_user_runtime(root, 1000, ops=ops)
    assert ops.created == []
    assert ops.chmod_calls == []

    owner_ops = _FakeOps()
    owner_lstat = owner_ops.lstat

    def non_root_parent(path):
        info = owner_lstat(path)
        if Path(path) == root.parent:
            info.st_uid = 1000
        return info

    owner_ops.lstat = non_root_parent
    with pytest.raises(ConfigureError, match="root-owned"):
        provision_user_runtime(root, 1000, ops=owner_ops)
    assert owner_ops.created == []
    assert owner_ops.chmod_calls == []

    private_ancestor = tmp_path / "private-ancestor"
    private_ancestor.mkdir(mode=0o700)
    private_root = private_ancestor / "approved-root"
    private_root.mkdir()
    marker_parent = private_root / ".ubackup"
    marker_parent.mkdir(mode=0o700)
    marker = marker_parent / "approved"
    marker.write_bytes(APPROVAL_MARKER_CONTENT)
    marker.chmod(APPROVAL_MARKER_MODE)
    private_ops = _FakeOps(non_traversable={private_ancestor})
    with pytest.raises(ConfigureError, match="world-traversable"):
        provision_user_runtime(private_root, 1000, ops=private_ops)
    assert private_ops.created == []
    assert private_ops.chmod_calls == []
    assert (private_ancestor.stat().st_mode & 0o777) == 0o700

    link = tmp_path / "link"
    link.mkdir()
    linked_root = link / "backup"
    linked_root.mkdir()
    symlink_parent = tmp_path / "symlink-parent"
    symlink_parent.symlink_to(link, target_is_directory=True)
    with pytest.raises(ConfigureError):
        provision_user_runtime(symlink_parent / "backup", 1000, ops=_FakeOps())


def test_root_identity_is_revalidated_before_first_mutation(tmp_path):
    root = tmp_path / "approved-root"
    root.mkdir()
    marker_parent = root / ".ubackup"
    marker_parent.mkdir(mode=0o700)
    marker = marker_parent / "approved"
    marker.write_bytes(APPROVAL_MARKER_CONTENT)
    marker.chmod(APPROVAL_MARKER_MODE)

    class _RaceOps(_FakeOps):
        def __init__(self):
            super().__init__()
            self.root_reads = 0

        def lstat(self, path):
            info = super().lstat(path)
            if Path(path) == root:
                self.root_reads += 1
                if self.root_reads >= 2:
                    info.st_ino += 1
            return info

    ops = _RaceOps()
    with pytest.raises(ConfigureError, match="changed"):
        provision_user_runtime(root, 1000, ops=ops)
    assert ops.created == []
    assert ops.chmod_calls == []


def test_direct_non_root_configure_is_structured_and_does_not_touch_filesystem(tmp_path):
    request = encode_request("configure", "/backup")
    ops = _FakeOps()
    response = decode_response(
        handle_request(request, environment={"PKEXEC_UID": "1000"}, effective_uid=1000, ops=ops)
    )
    assert response.ok is False
    assert response.error_code == "not_root"
    assert ops.created == []
    assert ops.chmod_calls == []


def test_pkexec_uid_rejects_root_and_reserved_ceiling():
    for raw in ("0", str(RESERVED_UID_MAX), "01", "+1000"):
        with pytest.raises(ConfigureError):
            validated_pkexec_uid({"PKEXEC_UID": raw})


def test_helper_converts_filesystem_os_errors_to_bounded_response():
    class _DeniedOps:
        def lstat(self, path):
            raise PermissionError("private diagnostic should not escape")

    response = decode_response(
        handle_request(
            encode_request("configure", "/backup"),
            environment={"PKEXEC_UID": "1000"},
            effective_uid=0,
            ops=_DeniedOps(),
        )
    )
    assert response.ok is False
    assert response.error_code == "invalid_backup_root"
    assert len(response.error_message or "") < 2048


def test_backup_root_validation_rejects_unsafe_root(tmp_path):
    root = tmp_path / "backup"
    root.mkdir()
    root.chmod(0o777)
    with pytest.raises(ConfigureError):
        validate_backup_root(root)

    safe_target = tmp_path / "safe-target"
    safe_target.mkdir()
    link = tmp_path / "backup-link"
    link.symlink_to(safe_target, target_is_directory=True)
    with pytest.raises(ConfigureError):
        validate_backup_root(link)


def test_broker_uses_only_fixed_helper_and_filtered_environment(monkeypatch):
    calls = []
    monkeypatch.setenv("PATH", "/tmp/attacker")
    monkeypatch.setenv("SECRET", "do-not-pass")
    monkeypatch.setenv("LANG", "C")

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return __import__("subprocess").CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "version": 1,
                    "operation": "configure",
                    "ok": True,
                    "uid": 1000,
                    "user_root": "/backup/.ubackup/users/1000",
                }
            ).encode(),
            stderr=b"",
        )

    result = PrivilegeBroker(runner=runner, uid_getter=lambda: 1000).configure("/backup")

    assert result.uid == 1000
    assert calls[0][0] == ["/usr/bin/pkexec", "/usr/libexec/ubackup-configure"]
    assert "--keep-env" not in calls[0][0]
    assert calls[0][1]["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C"}
    assert decode_request(calls[0][1]["input"]) == decode_request(encode_request("configure", "/backup"))


def test_installed_policy_is_restrictive_and_binds_fixed_helper():
    policy = Path("packaging/polkit/org.ubackup.configure.policy").read_text()
    assert "<allow_any>no</allow_any>" in policy
    assert "<allow_inactive>no</allow_inactive>" in policy
    assert "<allow_active>auth_admin</allow_active>" in policy
    assert "/usr/libexec/ubackup-configure" in policy


def test_broker_bounds_protocol_output_and_structures_process_failure():
    def oversized(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout=b"x" * (64 * 1024 + 1), stderr=b"")

    with pytest.raises(BrokerProtocolError) as protocol_error:
        PrivilegeBroker(runner=oversized, uid_getter=lambda: 1000).configure("/backup")
    assert protocol_error.value.code == "response_too_large"

    def failed(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 126, stdout=b"", stderr=b"denied")

    with pytest.raises(BrokerSubprocessError) as process_error:
        PrivilegeBroker(runner=failed, uid_getter=lambda: 1000).configure("/backup")
    assert process_error.value.code == "helper_exit"


def test_broker_rejects_root_and_requires_exact_caller_identity():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "version": 1,
                    "operation": "configure",
                    "ok": True,
                    "uid": 1001,
                    "user_root": "/backup/.ubackup/users/1001",
                }
            ).encode(),
            stderr=b"",
        )

    with pytest.raises(BrokerProtocolError, match="identity"):
        PrivilegeBroker(runner=runner, uid_getter=lambda: 1000).configure("/backup")
    assert calls == [["/usr/bin/pkexec", "/usr/libexec/ubackup-configure"]]

    def wrong_path_runner(command, **kwargs):
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=json.dumps(
                {
                    "version": 1,
                    "operation": "configure",
                    "ok": True,
                    "uid": 1000,
                    "user_root": "/backup/.ubackup/users/other",
                }
            ).encode(),
            stderr=b"",
        )

    with pytest.raises(BrokerProtocolError, match="identity"):
        PrivilegeBroker(runner=wrong_path_runner, uid_getter=lambda: 1000).configure("/backup")

    root_calls = []

    def root_runner(*args, **kwargs):
        root_calls.append(args)
        raise AssertionError("root callers must be rejected before pkexec")

    with pytest.raises(BrokerError) as root_error:
        PrivilegeBroker(runner=root_runner, uid_getter=lambda: 0).configure("/backup")
    assert root_error.value.code == "root_caller"
    assert root_calls == []


def test_installer_is_phase1_only_and_uses_explicit_safe_inputs():
    installer = Path("scripts/install_system.sh").read_text()
    assert "/tmp" not in installer
    assert "packaging/launchers" not in installer
    assert "main.py" not in installer
    assert "SOURCE_FILES=(" in installer
    assert "find -P" in installer
    assert "cp -a" not in installer
