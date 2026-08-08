import os

import pytest

from ubackup.models import SnapshotRecord


def test_snapshot_gui_transport_drops_potentially_unbounded_source_paths():
    record = SnapshotRecord(
        id="a" * 64,
        time="2026-08-08T00:00:00Z",
        hostname="host",
        paths=[f"/etc/example/{index}/" + "x" * 200 for index in range(5000)],
        tags=["ubackup"],
    )

    full = record.to_dict()
    compact = record.to_gui_dict()

    assert len(full["paths"]) == 5000
    assert compact["paths"] == []
    assert compact["id"] == record.id
    assert compact["time"] == record.time


def test_repository_initialized_probe_distinguishes_new_and_existing_repository(tmp_path):
    from ubackup.paths import PrivilegedPaths
    from ubackup.privileged.startup import _repository_initialized

    paths = PrivilegedPaths.for_root(tmp_path)
    assert _repository_initialized(paths) is False

    paths.repository.mkdir(parents=True)
    config = paths.repository / "config"
    config.write_text("restic-config")
    config.chmod(0o644)

    assert _repository_initialized(
        paths,
        expected_uid=os.getuid(),
    ) is True


def test_repository_initialized_probe_rejects_untrusted_owner(tmp_path):
    from ubackup.paths import PrivilegedPaths
    from ubackup.privileged.configure import ConfigureError
    from ubackup.privileged.startup import _repository_initialized

    paths = PrivilegedPaths.for_root(tmp_path)
    paths.repository.mkdir(parents=True)
    config = paths.repository / "config"
    config.write_text("restic-config")
    config.chmod(0o644)

    wrong_uid = os.getuid() + 1
    with pytest.raises(ConfigureError, match="trusted root-owned file"):
        _repository_initialized(paths, expected_uid=wrong_uid)
