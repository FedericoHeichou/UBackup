import uuid
from pathlib import Path

import pytest

from ubackup.privileged.filesystem_navigation import admitted_children, children, protected_path
from ubackup.privileged.protocol import (
    ProtocolError, StartupFrameParser, navigation_ready_frame, navigation_result_frame,
    startup_done_frame, startup_ready_response,
)


class Admission:
    def __init__(self, root):
        self.root = root
        self.calls = 0
    def revalidate(self, ops=None):
        self.calls += 1


def test_navigation_protocol_requires_done_ready_and_matching_ids():
    sid = str(uuid.uuid4()); rid = str(uuid.uuid4())
    parser = StartupFrameParser(sid)
    parser.feed(startup_ready_response(1000, "/backup/u", sid))
    with pytest.raises(ProtocolError):
        parser.feed(navigation_result_frame(sid, rid, [], None, True))
    parser.feed(startup_done_frame(sid) + navigation_ready_frame(sid))
    parser.feed(navigation_result_frame(sid, rid, [], None, True))


def test_shared_listing_marks_backup_root_direct_entry(tmp_path):
    backup = tmp_path / "backup"; backup.mkdir()
    (tmp_path / "ordinary").mkdir()
    records = children(tmp_path, 10, 0, root=backup)
    marked = next(item for item in records if item["path"] == str(backup))
    assert marked["blocked"] and marked["type"] == "blocked-dir"
    admission = Admission(tmp_path)
    with pytest.raises(Exception):
        admitted_children(admission, str(tmp_path), 10, 0)
    assert admission.calls == 1


def test_shared_protected_path_rejects_pseudo_and_symlink(tmp_path):
    root = tmp_path / "backup"; root.mkdir()
    with pytest.raises(Exception):
        protected_path("/proc", root)
    link = tmp_path / "link"; link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(Exception):
        protected_path(str(link), root)


def test_shared_listing_non_regular_file_size_matches_backup_accounting(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"payload")
    link = tmp_path / "link"
    link.symlink_to(target)

    records = children(tmp_path, 10, 0)
    by_name = {record["name"]: record for record in records}
    assert by_name["target"]["size"] == 7
    assert by_name["target"]["symlink"] is False
    assert by_name["link"]["size"] == 0
    assert by_name["link"]["symlink"] is True
