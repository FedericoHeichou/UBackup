from __future__ import annotations

import os
import sys

from ubackup.restic_engine import ResticEngine, _restic_failure_message
from ubackup.telemetry import gate_restic_backup_progress, human_bytes, staged_progress_fraction


def test_human_bytes_uses_nearest_binary_unit():
    assert human_bytes(987) == "987 B"
    assert human_bytes(5 * 1024**2) == "5.0 MiB"
    assert human_bytes(3 * 1024**3) == "3.0 GiB"


def test_staged_backup_progress_is_monotonic_across_components_and_local_reestimates():
    previous = 0.0
    observed = []
    for stage, local_values in ((0, (0.2, 0.6, 0.5, 1.0)), (1, (0.1, 0.8, 1.0)), (2, (0.05, 1.0))):
        for local in local_values:
            previous = staged_progress_fraction(stage, 3, local, previous)
            observed.append(previous)
    assert observed == sorted(observed)
    assert observed[3] == 1 / 3
    assert observed[4] > 1 / 3
    assert observed[-1] == 1.0


def test_restic_backup_percentage_is_hidden_until_scan_finished():
    scan_finished = False
    first, scan_finished = gate_restic_backup_progress(
        {
            "message_type": "status",
            "percent_done": 0.93,
            "bytes_done": 19,
            "total_bytes": 20,
        },
        scan_finished,
    )
    assert scan_finished is False
    assert "percent_done" not in first
    assert first["progress_phase"] == "scanning"
    assert first["bytes_done"] == 19
    assert first["total_bytes"] == 20

    scan_event, scan_finished = gate_restic_backup_progress(
        {"message_type": "verbose_status", "action": "scan_finished", "total_files": 123},
        scan_finished,
    )
    assert scan_finished is True
    assert scan_event["action"] == "scan_finished"

    stable, scan_finished = gate_restic_backup_progress(
        {"message_type": "status", "percent_done": 0.925, "bytes_done": 20, "total_bytes": 22},
        scan_finished,
    )
    assert scan_finished is True
    assert stable["percent_done"] == 0.925


def test_restic_json_stderr_is_reduced_to_actionable_failure():
    stderr = (
        '{"message_type":"error","error":{"message":"permission denied"},'
        '"during":"archival","item":"/home/user/private"}\n'
    )
    assert _restic_failure_message(stderr, "fallback") == (
        "Restic archival for /home/user/private: permission denied"
    )


def test_restic_plain_stderr_and_fallback_are_preserved():
    assert _restic_failure_message("fatal repository error\n", "fallback") == "fatal repository error"
    assert _restic_failure_message("", "restic backup exited with status 1") == "restic backup exited with status 1"


def test_streamed_restic_output_is_not_limited_by_aggregate_stdout_size(monkeypatch):
    # Reproduce the old failure cheaply by shrinking the legacy aggregate cap.
    # _stream_process must ignore that cap because JSONL is consumed as a stream.
    import ubackup.restic_engine as restic_engine

    monkeypatch.setattr(restic_engine, "MAX_RESTIC_STDOUT_BYTES", 128)
    child = (
        "import json\n"
        "for i in range(200):\n"
        "    print(json.dumps({\"message_type\": \"verbose_status\", \"item\": f\"/file-{i:04d}\"}))\n"
    )
    lines: list[str] = []
    code, stderr = ResticEngine._stream_process(
        [sys.executable, "-c", child],
        dict(os.environ),
        lines.append,
        timeout=10,
    )
    assert code == 0
    assert stderr == ""
    assert len(lines) == 200
    assert sum(len(line.encode()) for line in lines) > 128


def test_streamed_restic_output_rejects_one_oversized_line(monkeypatch):
    import pytest
    import ubackup.restic_engine as restic_engine
    from ubackup.restic_engine import ResticError

    monkeypatch.setattr(restic_engine, "MAX_RESTIC_STREAM_LINE_BYTES", 128)
    child = "import sys; sys.stdout.write('x' * 256 + '\\n')"
    with pytest.raises(ResticError, match="oversized output line"):
        ResticEngine._stream_process(
            [sys.executable, "-c", child], dict(os.environ), lambda _line: None, timeout=10
        )
