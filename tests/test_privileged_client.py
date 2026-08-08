from ubackup.gui.privileged_client import CredentialDescriptor, PrivilegedClient
from ubackup.privilege_broker import Phase2Result
from typing import Any, cast
import pytest


class FakeBroker:
    def __init__(self):
        self.calls = []

    def inspect(self, backup_root, **payload):
        self.calls.append((backup_root, payload))
        kind = payload["kind"]
        if kind == "snapshot-stats":
            result = {"kind": kind, "stats": {"total_size": 42, "file_count": 3}}
        elif kind == "metadata":
            result = {
                "kind": kind,
                "filename": payload["filename"],
                "value": {"schema_version": 1} if payload["filename"] == "manifest.json" else [{"name": "demo"}],
            }
        else:
            result = {"kind": kind}
        return Phase2Result("request-id", "inspect", 1000, result)


def test_snapshot_facade_unwraps_typed_phase2_envelopes_without_retaining_credentials():
    broker = FakeBroker()
    client = PrivilegedClient(cast(Any, broker), "/backup")
    credentials = CredentialDescriptor(password="secret", password_file="/run/password")

    assert client.snapshot_stats("filesystem", "abcdef12", credentials) == {"total_size": 42, "file_count": 3}
    assert client.snapshot_manifest("configs", "abcdef12", credentials) == {"schema_version": 1}
    assert client.snapshot_packages("abcdef12", credentials) == [{"name": "demo"}]
    assert "secret" not in repr(client.__dict__)
    assert all(call[1]["password"] == "secret" for call in broker.calls)
    assert all(call[1]["password_file"] == "/run/password" for call in broker.calls)
    assert [call[1].get("component") for call in broker.calls] == ["filesystem", "configs", "packages"]

def test_snapshot_facade_accepts_unwrapped_fake_envelopes_and_rejects_wrong_shapes():
    class EnvelopeBroker:
        def inspect(self, backup_root, **payload):
            if payload["kind"] == "snapshot-stats":
                return {"stats": {"total_size": 1}}
            if payload["kind"] == "metadata":
                return {"value": {} if payload["filename"] == "manifest.json" else []}
            raise AssertionError("unexpected inspect operation")

    client = PrivilegedClient(cast(Any, EnvelopeBroker()), "/backup")
    assert client.snapshot_stats("filesystem", "abcdef12") == {"total_size": 1}
    assert client.snapshot_manifest("configs", "abcdef12") == {}
    assert client.snapshot_packages("abcdef12") == []

def test_persistent_session_is_used_without_reinvoking_broker_or_resending_credentials():
    class NeverBroker:
        def __getattr__(self, name):
            raise AssertionError(f"broker fallback must not be used: {name}")

    class Session:
        def __init__(self): self.calls = []
        def request(self, operation, payload, timeout=0):
            self.calls.append((operation, payload, timeout))
            if payload.get("kind") == "repository-size": return {"size": 7, "file_count": 1}
            return {"ok": True}

    session = Session()
    client = PrivilegedClient(cast(Any, NeverBroker()), "/backup")
    client.attach_session(cast(Any, session))
    secret = CredentialDescriptor(password="do-not-resend")
    assert client.repository_size()["size"] == 7
    client.backup(
        sources=["/home"], source_exclusions=[], exclude_rules=[], packages=[], configs=[],
        components=["filesystem"], credentials=secret,
    )
    assert len(session.calls) == 2
    assert all("credentials" not in payload for _, payload, _ in session.calls)
    assert "do-not-resend" not in repr(session.calls)

def test_persistent_inventory_requests_preserve_force_without_broker_fallback():
    class NeverBroker:
        def __getattr__(self, name):
            raise AssertionError(f"broker fallback must not be used: {name}")

    class Session:
        def __init__(self):
            self.calls = []

        def request(self, operation, payload, timeout=0):
            self.calls.append((operation, payload, timeout))
            return {"records": [], "next_offset": None}

    session = Session()
    client = PrivilegedClient(cast(Any, NeverBroker()), "/backup", cast(Any, session))
    client.package_inventory(force=True)
    client.config_inventory(force=True)
    assert [payload["force"] for _, payload, _ in session.calls] == [True, True]


def test_dependency_status_populates_version_without_privilege(tmp_path, monkeypatch):
    executable = tmp_path / "restic"
    executable.write_text("#!/bin/sh\necho 'restic 9.9.9'\n")
    executable.chmod(0o755)

    def which(command, path=None):
        return str(executable) if command == "restic" else None

    monkeypatch.setattr("ubackup.gui.privileged_client.shutil.which", which)
    client = PrivilegedClient(cast(Any, object()), "/backup")
    deps = client.dependency_status()
    restic = next(item for item in deps if item.command == "restic")
    assert restic.installed is True
    assert restic.version == "restic 9.9.9"


def test_dependency_status_falls_back_when_dash_version_is_rejected(tmp_path, monkeypatch):
    executable = tmp_path / "restic"
    executable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then\n"
        "  echo 'unknown flag: --version' >&2\n"
        "  exit 1\n"
        "fi\n"
        "if [ \"$1\" = \"version\" ]; then\n"
        "  echo 'restic 0.17.3'\n"
        "  exit 0\n"
        "fi\n"
        "exit 2\n"
    )
    executable.chmod(0o755)

    def which(command, path=None):
        return str(executable) if command == "restic" else None

    monkeypatch.setattr("ubackup.gui.privileged_client.shutil.which", which)
    client = PrivilegedClient(cast(Any, object()), "/backup")
    deps = client.dependency_status()
    restic = next(item for item in deps if item.command == "restic")
    assert restic.installed is True
    assert restic.version == "restic 0.17.3"


def test_backup_facade_requires_and_sends_one_domain_to_persistent_session():
    class Session:
        def __init__(self): self.calls = []
        def request(self, operation, payload, timeout=0):
            self.calls.append((operation, payload, timeout))
            return {"receipt": {}}

    session = Session()
    client = PrivilegedClient(cast(Any, object()), "/backup", cast(Any, session))
    client.dry_run(
        sources=["/home"], source_exclusions=[], exclude_rules=[], packages=[], configs=[],
        components=["filesystem"],
    )
    assert session.calls[0][1]["components"] == ["filesystem"]

def test_production_client_never_falls_back_to_a_second_privileged_prompt():
    class Broker:
        def inspect(self, *_args, **_kwargs):
            raise AssertionError("standalone broker fallback must not run")

    client = PrivilegedClient(cast(Any, Broker()), "/backup", allow_broker_fallback=False)
    try:
        client.filesystem_children("/home")
    except RuntimeError as exc:
        assert "restart UBackup" in str(exc)
    else:
        raise AssertionError("missing persistent session must be a terminal GUI-side error")


def test_filesystem_facade_sends_exclusion_profile_to_persistent_session():
    class Session:
        def __init__(self): self.calls = []
        def request(self, operation, payload, timeout=0):
            self.calls.append((operation, payload, timeout))
            return {"records": [], "next_offset": None} if payload["kind"] == "filesystem-children" else {"size": 0, "file_count": 0}

    session = Session()
    client = PrivilegedClient(cast(Any, object()), "/backup", cast(Any, session))
    patterns = ["**/node_modules/**", "/etc/**"]
    client.filesystem_children("/home", exclude_patterns=patterns)
    client.filesystem_size("/home", exclude_patterns=patterns, force=True)
    client.filesystem_cache(["/home", "/usr/local/bin"], exclude_patterns=patterns)
    assert session.calls[0][1]["exclude_patterns"] == patterns
    assert "cache_only" not in session.calls[0][1]
    assert session.calls[0][1]["limit"] == 10_000
    assert session.calls[1][1]["exclude_patterns"] == patterns
    assert session.calls[1][1]["force"] is True
    assert session.calls[2][1] == {
        "kind": "filesystem-cache",
        "paths": ["/home", "/usr/local/bin"],
        "exclude_patterns": patterns,
    }


def test_snapshot_maintenance_uses_authenticated_session_only():
    class NeverBroker:
        def __getattr__(self, name):
            raise AssertionError(f"broker fallback must not be used: {name}")

    class Session:
        def __init__(self):
            self.calls = []
        def request(self, operation, payload, timeout=0, progress_cb=None):
            self.calls.append((operation, payload, timeout))
            return {"deleted": [payload["snapshot_id"]]}

    session = Session()
    client = PrivilegedClient(cast(Any, NeverBroker()), "/backup", cast(Any, session), allow_broker_fallback=False)
    result = client.delete_latest_snapshot("configs", "a" * 64)
    assert result["deleted"] == ["a" * 64]
    operation, payload, _timeout = session.calls[0]
    assert operation == "maintenance"
    assert payload == {"action": "delete-latest", "component": "configs", "snapshot_id": "a" * 64}


def test_snapshot_list_metadata_is_paged_before_gui_assembly():
    class Session:
        def __init__(self): self.calls = []
        def request(self, operation, payload, timeout=0):
            self.calls.append(dict(payload))
            offset = payload["offset"]
            if offset == 0:
                return {"kind": "metadata", "filename": "packages.json", "value": [{"name": "a"}], "next_offset": 1, "truncated": True}
            return {"kind": "metadata", "filename": "packages.json", "value": [{"name": "b"}], "next_offset": None, "truncated": False}

    session = Session()
    client = PrivilegedClient(cast(Any, object()), "/backup", cast(Any, session))
    assert client.snapshot_packages("abcdef12") == [{"name": "a"}, {"name": "b"}]
    assert [call["offset"] for call in session.calls] == [0, 1]
    assert all(call["limit"] == 500 for call in session.calls)
    assert all(call["component"] == "packages" for call in session.calls)


def test_client_rejects_multi_domain_backup_calls_before_rpc():
    client = PrivilegedClient(cast(Any, object()), "/backup", cast(Any, object()))
    with pytest.raises(ValueError, match="exactly one component"):
        client.backup(sources=[], source_exclusions=[], exclude_rules=[], packages=[], configs=[], components=["filesystem", "packages"])
    with pytest.raises(ValueError, match="exactly one component"):
        client.dry_run(sources=[], source_exclusions=[], exclude_rules=[], packages=[], configs=[], components=[])
