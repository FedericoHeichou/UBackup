from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Callable

from .cache import CacheDB
from .profiles import system_hard_exclude_patterns


DEFAULT_SKIP_PREFIXES = ("/proc", "/sys", "/dev", "/run")
CACHEDIR_TAG_NAME = "CACHEDIR.TAG"
CACHEDIR_TAG_SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
FS_SCAN_CACHE_ALGORITHM = "flat-v2-restic-cachedir"


def scan_cache_key(exclude_patterns: tuple[str, ...] | list[str]) -> str:
    # Include scanner semantics in the key. Restic's --exclude-caches behavior
    # affects effective Size even when the visible exclusion profile is unchanged.
    encoded = json.dumps(
        (FS_SCAN_CACHE_ALGORITHM, tuple(str(pattern) for pattern in exclude_patterns)),
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def human_size(n: int | None) -> str:
    if n is None:
        return "…"
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(value) < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{n} B"


class SizeScanner:
    PROGRESS_INTERVAL_SECONDS = 0.25
    CHECKPOINT_INTERVAL_ITEMS = 512

    def __init__(self, cache: CacheDB, backup_root: Path, exclude_patterns: tuple[str, ...] | list[str] = ()):
        self.cache = cache
        self.backup_root = backup_root.resolve()
        self._backup_root_text = str(self.backup_root)
        self.exclude_patterns = tuple(str(pattern) for pattern in exclude_patterns)
        self.scan_key = scan_cache_key(self.exclude_patterns)
        self._compiled_excludes = tuple(self._compile_pattern(raw) for raw in self.exclude_patterns)
        self._compiled_hard = tuple(self._compile_pattern(raw) for raw in system_hard_exclude_patterns())
        self.last_source = "filesystem"

    @staticmethod
    def _compile_pattern(raw: str) -> tuple[bool, str, str]:
        negative = raw.startswith("!")
        pattern = raw[1:] if negative else raw
        if pattern.endswith("/**"):
            base = pattern[:-3].rstrip("/") or "/"
            if base.startswith("**/"):
                needle = base[3:]
                if not any(char in needle for char in "*?[]{}"):
                    return negative, "segment", needle
            elif not any(char in base for char in "*?[]{}"):
                return negative, "prefix", base
        if not any(char in pattern for char in "*?[]{}"):
            return negative, "exact", pattern
        return negative, "glob", pattern

    @staticmethod
    def _pattern_matches(text: str, compiled: tuple[bool, str, str]) -> bool:
        _negative, kind, value = compiled
        if kind == "prefix":
            return text == value or text.startswith(value.rstrip("/") + "/")
        if kind == "segment":
            padded = text.rstrip("/") + "/"
            return f"/{value}/" in padded or text.endswith("/" + value)
        if kind == "exact":
            return text == value
        return fnmatchcase(text, value)

    def _excluded_by_profile(self, text: str) -> bool:
        excluded = False
        for compiled in self._compiled_excludes:
            if self._pattern_matches(text, compiled):
                excluded = not compiled[0]
        return excluded

    def scan(self, path: Path, force: bool = False,
             progress: Callable[[str, int, int], None] | None = None,
             checkpoint: Callable[[], None] | None = None,
             cancel: Callable[[], None] | None = None,
             cache_progress: Callable[[str, int, int], None] | None = None,
             cache_progress_detailed: Callable[[str, int, int, int, int], None] | None = None) -> tuple[int, int]:
        """Calculate exclusion-aware recursive size with monotonic telemetry.

        Cached aggregates remain usable until the user explicitly requests
        ``Recalculate``. Filesystem identity and exclusion-profile changes are
        presentation-level staleness signals; ordinary navigation must not turn
        either into an implicit recursive scan.
        """
        path = path.resolve()
        progress = progress or (lambda _p, _s, _c: None)
        checkpoint = checkpoint or cancel or (lambda: None)
        checkpoint()
        if self._hard_skip(path):
            return 0, 0

        if not force:
            cached = self.cache.get_fs(str(path), max_age=None)
            if cached is not None and cached.get("total_size") is not None:
                self.last_source = (
                    "cache" if str(cached.get("scan_key", "") or "") == self.scan_key
                    else "cache-stale-profile"
                )
                return int(cached.get("size", 0) or 0), int(cached.get("file_count", 0) or 0)

        state = {
            "bytes": 0,
            "items": 0,
            "last_emit": 0.0,
            "next_checkpoint": self.CHECKPOINT_INTERVAL_ITEMS,
        }

        def account(current: str, byte_delta: int = 0, item_delta: int = 0, *, force_emit: bool = False) -> None:
            state["bytes"] += max(0, int(byte_delta))
            state["items"] += max(0, int(item_delta))
            if state["items"] >= state["next_checkpoint"]:
                checkpoint()
                while state["next_checkpoint"] <= state["items"]:
                    state["next_checkpoint"] += self.CHECKPOINT_INTERVAL_ITEMS
            now = time.monotonic()
            if force_emit or now - state["last_emit"] >= self.PROGRESS_INTERVAL_SECONDS:
                progress(current, state["bytes"], state["items"])
                state["last_emit"] = now

        self.last_source = "filesystem"
        self._pending_cache_rows: list[dict] = []
        self._scan_timestamp = time.time()
        try:
            size, count, _total_size, _total_count = self._scan_recursive(
                path, checkpoint, cache_progress, cache_progress_detailed, account, state,
                effective_enabled=not self._excluded_by_profile(str(path)),
            )
            self._flush_cache_rows()
        finally:
            # Do not leak partial writer state if cancellation/error interrupts a scan.
            self._pending_cache_rows = []
        account(str(path), force_emit=True)
        return size, count

    def _queue_cache_row(
        self, path: str, size: int, st, file_count: int, *,
        total_size: int, total_file_count: int,
    ) -> None:
        self._pending_cache_rows.append({
            "path": path, "size": int(size), "total_size": int(total_size),
            "mtime_ns": int(st.st_mtime_ns), "inode": int(st.st_ino), "dev": int(st.st_dev),
            "file_count": int(file_count), "total_file_count": int(total_file_count),
            "scanned_at": float(self._scan_timestamp), "scan_key": self.scan_key,
        })
        if len(self._pending_cache_rows) >= 512:
            self._flush_cache_rows()

    def _flush_cache_rows(self) -> None:
        if not self._pending_cache_rows:
            return
        rows, self._pending_cache_rows = self._pending_cache_rows, []
        self.cache.put_fs_many(rows)

    def _hard_skip_text(self, text: str) -> bool:
        root = self._backup_root_text
        if text == root or text.startswith(root.rstrip("/") + "/"):
            return True
        if any(text == prefix or text.startswith(prefix + "/") for prefix in DEFAULT_SKIP_PREFIXES):
            return True
        return any(self._pattern_matches(text, compiled) for compiled in self._compiled_hard)

    def _skip_text(self, text: str) -> bool:
        """Return whether a path contributes to the exclusion-aware size."""
        return self._hard_skip_text(text) or self._excluded_by_profile(text)

    def _hard_skip(self, path: Path) -> bool:
        return self._hard_skip_text(str(path))

    def _skip(self, path: Path) -> bool:
        return self._skip_text(str(path))

    @staticmethod
    def _has_valid_cachedir_tag(path: Path) -> bool:
        """Match Restic --exclude-caches marker semantics for Size preview."""
        marker = path / CACHEDIR_TAG_NAME
        try:
            with marker.open("rb") as handle:
                return handle.read(len(CACHEDIR_TAG_SIGNATURE)) == CACHEDIR_TAG_SIGNATURE
        except OSError:
            return False

    def _scan_recursive(
        self,
        path: Path,
        checkpoint: Callable[[], None],
        cache_progress,
        cache_progress_detailed,
        account,
        state,
        *,
        effective_enabled: bool,
    ) -> tuple[int, int, int, int]:
        """Return effective and profile-independent totals in one traversal.

        Hard/system exclusions and the backup root are never traversed. User
        and preconfigured exclusions suppress only the effective backup size;
        the same filesystem walk still records ``total_size`` so the GUI can
        show a stable physical total without launching a second recursive scan.
        """
        checkpoint()
        try:
            st = os.lstat(path)
        except OSError:
            return 0, 0, 0, 0
        path_text = str(path)
        if not os.path.isdir(path) or os.path.islink(path):
            total_size = st.st_size if os.path.isfile(path) else 0
            total_count = 1
            size = total_size if effective_enabled else 0
            count = total_count if effective_enabled else 0
            account(path_text, total_size, total_count)
            self._queue_cache_row(
                path_text, size, st, count,
                total_size=total_size, total_file_count=total_count,
            )
            if cache_progress is not None:
                cache_progress(path_text, size, count)
            if cache_progress_detailed is not None:
                cache_progress_detailed(path_text, size, count, state["bytes"], state["items"])
            return size, count, total_size, total_count

        total = 0
        count = 0
        total_size = 0
        total_count = 0
        # Restic is invoked with --exclude-caches. A valid CACHEDIR.TAG keeps
        # the marker itself but excludes the directory's remaining contents
        # from the logical backup set. We still traverse for physical Total size.
        cachedir = effective_enabled and self._has_valid_cachedir_tag(path)
        try:
            entries = os.scandir(path)
        except (PermissionError, OSError):
            self._queue_cache_row(path_text, 0, st, 0, total_size=0, total_file_count=0)
            if cache_progress is not None:
                cache_progress(path_text, 0, 0)
            if cache_progress_detailed is not None:
                cache_progress_detailed(path_text, 0, 0, state["bytes"], state["items"])
            return 0, 0, 0, 0
        with entries:
            for entry in entries:
                child_text = entry.path
                try:
                    est = entry.stat(follow_symlinks=False)
                    is_symlink = entry.is_symlink()
                    is_dir = entry.is_dir(follow_symlinks=False) and not is_symlink
                    is_regular = stat.S_ISREG(est.st_mode) and not is_symlink
                    # Hard/system paths are never traversed or counted as
                    # backup data. Live navigation still lists them directly.
                    if self._hard_skip_text(child_text):
                        continue
                    if is_symlink:
                        total_count += 1
                        child_enabled = (
                            effective_enabled
                            and (not cachedir or entry.name == CACHEDIR_TAG_NAME)
                            and not self._excluded_by_profile(child_text)
                        )
                        if child_enabled:
                            count += 1
                        account(child_text, 0, 1)
                        self._queue_cache_row(
                            child_text, 0, est, 1 if child_enabled else 0,
                            total_size=0, total_file_count=1,
                        )
                    elif is_dir:
                        child_enabled = (
                            effective_enabled
                            and not cachedir
                            and not self._excluded_by_profile(child_text)
                        )
                        child_size, child_count, child_total_size, child_total_count = self._scan_recursive(
                            Path(child_text), checkpoint, cache_progress, cache_progress_detailed, account, state,
                            effective_enabled=child_enabled,
                        )
                        total += child_size
                        count += child_count
                        total_size += child_total_size
                        total_count += child_total_count
                    elif is_regular:
                        child_total = int(est.st_size)
                        total_size += child_total
                        total_count += 1
                        child_enabled = (
                            effective_enabled
                            and (not cachedir or entry.name == CACHEDIR_TAG_NAME)
                            and not self._excluded_by_profile(child_text)
                        )
                        if child_enabled:
                            total += child_total
                            count += 1
                        account(child_text, child_total, 1)
                        self._queue_cache_row(
                            child_text, child_total if child_enabled else 0, est,
                            1 if child_enabled else 0,
                            total_size=child_total, total_file_count=1,
                        )
                except OSError:
                    continue
        self._queue_cache_row(
            path_text, total, st, count,
            total_size=total_size, total_file_count=total_count,
        )
        if cache_progress is not None:
            cache_progress(path_text, total, count)
        if cache_progress_detailed is not None:
            cache_progress_detailed(path_text, total, count, state["bytes"], state["items"])
        return total, count, total_size, total_count


def list_children(path: Path, cache: CacheDB) -> list[tuple[Path, bool, int | None, int]]:
    out = []
    try:
        entries = list(os.scandir(path))
    except OSError:
        return out
    entries.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.casefold()))
    for e in entries:
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        child = Path(e.path)
        is_dir = e.is_dir(follow_symlinks=False) and not e.is_symlink()
        cached = cache.get_fs(str(child), max_age=None)
        size = cached["size"] if cached else (st.st_size if not is_dir else None)
        out.append((child, is_dir, size, st.st_mtime_ns))
    return out
