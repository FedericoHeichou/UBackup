from __future__ import annotations

from numbers import Real
from typing import Any, Mapping


def human_bytes(value: int | None) -> str:
    """Render a byte count using the nearest practical binary unit."""
    if value is None:
        return "—"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(size) < 1024 or unit == "PiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return "—"


def staged_progress_fraction(
    stage_index: int,
    stage_count: int,
    percent_done: Real | None,
    previous: float = 0.0,
) -> float:
    """Map one component's progress into a monotonic overall task fraction.

    Restic reports progress independently for each repository/component.  A
    multi-component UBackup backup runs those repositories sequentially, so
    forwarding each raw percentage would reset the UI at every component
    boundary.  Each component therefore owns one equal progress segment and
    the published fraction is clamped monotonically within the task.
    """
    if stage_count <= 0 or stage_index < 0 or stage_index >= stage_count:
        raise ValueError("invalid progress stage")
    baseline = max(0.0, min(1.0, float(previous)))
    if percent_done is None or isinstance(percent_done, bool) or not isinstance(percent_done, Real):
        return baseline
    local = float(percent_done)
    if local > 1.0:
        local /= 100.0
    local = max(0.0, min(1.0, local))
    overall = (stage_index + local) / stage_count
    return max(baseline, min(1.0, overall))


def gate_restic_backup_progress(
    message: Mapping[str, Any],
    scan_finished: bool,
) -> tuple[dict[str, Any], bool]:
    """Hide Restic's unstable percentage until its initial scan completes.

    Restic scans the backup set concurrently with the backup itself.  During
    that scan ``total_bytes`` is still being discovered, so ``percent_done``
    can start very high or move backwards even though the operation is
    healthy.  With ``--verbose=2`` Restic emits a ``scan_finished`` verbose
    event; only percentages observed after that point have a stable
    denominator suitable for a determinate GUI progress bar.

    The original message is never mutated.  Other telemetry (bytes/items,
    current files, warnings) continues flowing while progress is indeterminate.
    """
    value = dict(message)
    if value.get("message_type") == "verbose_status" and value.get("action") == "scan_finished":
        scan_finished = True
    if value.get("message_type") == "status" and not scan_finished:
        value.pop("percent_done", None)
        value["progress_phase"] = "scanning"
    return value, scan_finished
