from __future__ import annotations

"""Shared safe directory listing for explicit inspect and startup navigation."""

import heapq
import os
import stat
from pathlib import Path
from typing import Any

from ubackup.restic_engine import MAX_DIRECTORY_NODES
from .runtime import Phase2Error, ensure_not_cancelled
from .validation import absolute_path

PSEUDO_ROOTS = ("/proc", "/sys", "/dev", "/run")
HEAP_CHECKPOINT_INTERVAL = 64


class _LargestKey:
    def __init__(self, value): self.value = value
    def __lt__(self, other): return self.value > other.value


def protected_path(value: Any, root: Path) -> Path:
    path = absolute_path(value, "path")
    candidate = Path(path)
    if any(path == item or path.startswith(item + "/") for item in PSEUDO_ROOTS):
        raise Phase2Error("invalid_path", "pseudo-filesystem access is prohibited")
    if candidate == root or root in candidate.parents:
        raise Phase2Error("invalid_path", "backup-root access is prohibited")
    if Path(os.path.realpath(candidate)) != candidate:
        raise Phase2Error("invalid_path", "symlinked inspection paths are prohibited")
    return candidate


def _blocked(path: Path, root: Path) -> bool:
    text = str(path)
    return path == root or root in path.parents or any(text == item or text.startswith(item + "/") for item in PSEUDO_ROOTS)


def children(
    path: Path,
    limit: int,
    offset: int,
    *,
    probe: bool = False,
    root: Path | None = None,
    checkpoint=None,
) -> list[dict[str, Any]]:
    if offset < 0 or limit < 1 or offset + limit > MAX_DIRECTORY_NODES:
        raise Phase2Error("invalid_schema", "pagination window exceeds the directory limit")
    checkpoint = ensure_not_cancelled if checkpoint is None else checkpoint
    try:
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise Phase2Error("invalid_path", "inspection path is not a directory")
        extra = 1 if probe else 0
        keep = offset + limit + extra
        with os.scandir(path) as iterator:
            entries: list[tuple[_LargestKey, int, Any]] = []
            for sequence, item in enumerate(iterator, 1):
                if sequence % HEAP_CHECKPOINT_INTERVAL == 0:
                    checkpoint()
                key = (not item.is_dir(follow_symlinks=False), item.name.casefold(), item.name)
                candidate = (_LargestKey(key), sequence, item)
                if len(entries) < keep:
                    heapq.heappush(entries, candidate)
                elif key < entries[0][0].value:
                    heapq.heapreplace(entries, candidate)
            checkpoint()
            entries.sort(key=lambda value: (value[2].is_dir(follow_symlinks=False) is False, value[2].name.casefold(), value[2].name))
            selected = [value[2] for value in entries]
    except Phase2Error:
        raise
    except OSError as exc:
        raise Phase2Error("filesystem_error", "inspection path cannot be read") from exc
    output: list[dict[str, Any]] = []
    for entry in selected[offset:offset + limit + extra]:
        try:
            item_info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise Phase2Error("filesystem_error", "inspection entry cannot be read") from exc
        item_path = Path(entry.path)
        is_symlink = entry.is_symlink()
        is_dir = entry.is_dir(follow_symlinks=False) and not is_symlink
        blocked = bool(root is not None and _blocked(item_path, root))
        direct_size = None if is_dir else (item_info.st_size if stat.S_ISREG(item_info.st_mode) else 0)
        output.append({"path": entry.path, "name": entry.name,
                       "type": "blocked-dir" if blocked and is_dir else ("dir" if is_dir else "file"),
                       "blocked": blocked, "symlink": is_symlink, "size": direct_size,
                       "mtime_ns": item_info.st_mtime_ns, "inode": item_info.st_ino,
                       "dev": item_info.st_dev, "mode": stat.S_IMODE(item_info.st_mode)})
    return output


def admitted_children(admission, path: Any, limit: int, offset: int, *, ops=None) -> list[dict[str, Any]]:
    admission.revalidate(ops)
    candidate = protected_path(path, admission.root)
    return children(candidate, limit, offset, probe=True, root=admission.root)
