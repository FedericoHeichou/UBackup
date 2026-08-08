from __future__ import annotations

import json
import heapq
import os
import re
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

from .models import DryRunSummary, SnapshotRecord
from .paths import AppPaths, PrivilegedPaths
from .privileged.runtime import (
    CHILD_GRACE_SECONDS,
    ChildProcessError,
    cancellation_requested,
    child_process_preexec,
    register_child_group,
    unregister_child_group,
)


class ResticError(RuntimeError):
    pass


def _restic_failure_message(stderr: str, fallback: str) -> str:
    """Extract a concise actionable message from Restic's stderr stream."""
    messages: list[str] = []
    for raw_line in str(stderr or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            messages.append(line)
            continue
        if not isinstance(value, dict):
            messages.append(line)
            continue
        nested = value.get("error")
        message = nested.get("message") if isinstance(nested, dict) else None
        if not message:
            message = value.get("message") or value.get("text")
        if not message:
            continue
        detail = str(message).strip()
        during = str(value.get("during") or "").strip()
        item = str(value.get("item") or "").strip()
        context = "Restic"
        if during:
            context += f" {during}"
        if item:
            context += f" for {item}"
        messages.append(f"{context}: {detail}")
    if messages:
        # The final stderr line normally contains the fatal reason while earlier
        # lines may describe recoverable per-file read errors.
        return messages[-1]
    return fallback


SNAPSHOT_ID_RE = re.compile(r"^[0-9a-f]{8,64}$")
RESTIC_BACKUP_TIMEOUT = 3300
RESTIC_RESTORE_TIMEOUT = 1650
MAX_RESTIC_STDOUT_BYTES = 64 * 1024 * 1024
MAX_RESTIC_STDERR_BYTES = 64 * 1024
MAX_RESTIC_STREAM_LINE_BYTES = 1024 * 1024
MAX_DIRECTORY_NODES = 10_000


class _ReverseHeapNode:
    __slots__ = ("key", "item")

    def __init__(self, key: tuple[bool, str, str], item: dict):
        self.key = key
        self.item = item

    def __lt__(self, other: "_ReverseHeapNode") -> bool:
        return self.key > other.key


def _terminate_child(process: subprocess.Popen, pgid: int, code: str) -> None:
    """Terminate only the registered child group, then reap its leader."""
    try:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=CHILD_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        else:
            # The leader can exit while a descendant still owns a pipe.
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        unregister_child_group(pgid)
    raise ChildProcessError(code, f"child process {code}")


def _wait_with_cancellation(process: subprocess.Popen, pgid: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        if cancellation_requested():
            _terminate_child(process, pgid, "cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_child(process, pgid, "timeout")
        try:
            process.wait(timeout=min(0.1, remaining))
        except subprocess.TimeoutExpired:
            continue
        if cancellation_requested():
            _terminate_child(process, pgid, "cancelled")
        return


def _escalate_helper_group(_env: dict[str, str]) -> None:
    """Compatibility no-op: child deadlines never signal the helper group."""
    return None


def validate_external_password_file(path: Path) -> Path:
    if Path(os.path.realpath(path)) != path:
        raise ResticError("External password file contains symlinked path components")
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise ResticError("External password file is not readable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise ResticError("External password file is not secure")
    return path


class ResticEngine:
    def __init__(self, paths: AppPaths | PrivilegedPaths, env: dict[str, str]):
        self.paths = paths
        self.env = env.copy()
        self.password_file = Path(self.env.get("RESTIC_PASSWORD_FILE", str(paths.password_file)))
        self.session_password = self.password_file == paths.password_file

    def repository_exists(self) -> bool:
        return (self.paths.repository / "config").exists()

    def password_exists(self) -> bool:
        try:
            info = os.lstat(self.password_file)
        except OSError:
            return False
        return (
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and not info.st_mode & 0o022
            and info.st_size > 0
        )

    def set_external_password_file(self, path: Path) -> None:
        """Reject external paths; privileged callers must copy through a safe fd."""
        raise ResticError("External password paths must be copied to request-private storage")

    def set_password(self, password: str) -> None:
        if not password:
            raise ValueError("Password is empty")
        if not self.session_password:
            raise ResticError("The external password file is read-only for UBackup")
        old = os.umask(0o077)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(self.password_file, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(password + "\n")
            os.chmod(self.password_file, 0o600)
        finally:
            os.umask(old)

    def clear_session_password(self) -> None:
        if self.session_password:
            try:
                self.password_file.unlink(missing_ok=True)
            except OSError:
                pass

    def init_repository(self) -> None:
        if self.repository_exists():
            return
        if not self.password_exists():
            raise ResticError("Restic password is not configured")
        p = self._run(["restic", "init", "--repo", str(self.paths.repository),
                       "--password-file", str(self.password_file)], timeout=120)
        if p.returncode != 0:
            raise ResticError((p.stderr or p.stdout).strip())

    def _base(self) -> list[str]:
        return ["restic", "--repo", str(self.paths.repository), "--password-file", str(self.password_file),
                "--cache-dir", str(self.paths.cache / "restic")]

    def _run(self, cmd: list[str], timeout: int = RESTIC_BACKUP_TIMEOUT) -> subprocess.CompletedProcess[str]:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.env,
            start_new_session=True,
            preexec_fn=child_process_preexec(),
        )
        pgid = os.getpgid(process.pid)
        try:
            register_child_group(pgid, process)
        except ChildProcessError:
            raise
        except BaseException:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        overflow = {"stdout": False, "stderr": False}

        def drain(stream, buffer: bytearray, limit: int, name: str) -> None:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                remaining = max(0, limit - len(buffer))
                if remaining:
                    buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow[name] = True

        stdout_thread = threading.Thread(
            target=drain, args=(process.stdout, stdout_buffer, MAX_RESTIC_STDOUT_BYTES, "stdout"), daemon=True
        )
        stderr_thread = threading.Thread(
            target=drain, args=(process.stderr, stderr_buffer, MAX_RESTIC_STDERR_BYTES, "stderr"), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()
        try:
            _wait_with_cancellation(process, pgid, timeout)
        finally:
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            unregister_child_group(pgid)
        if overflow["stdout"] or overflow["stderr"]:
            raise ResticError("Restic output exceeds the internal limit")
        stdout = bytes(stdout_buffer).decode("utf-8", "replace")
        stderr = bytes(stderr_buffer).decode("utf-8", "replace")
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)

    @staticmethod
    def _stream_process(
        cmd: list[str],
        env: dict[str, str],
        on_stdout: Callable[[str], None],
        *,
        timeout: int,
    ) -> tuple[int, str]:
        """Run a long Restic command with bounded-memory streaming.

        JSON-lines output is intentionally unbounded in aggregate: ``backup
        --verbose=2`` emits one event per filesystem item and a legitimate large
        backup can therefore produce hundreds of MiB.  The previous 64 MiB
        cumulative cap aborted healthy backups.  Bound each individual line
        instead, while draining stdout continuously and retaining only a bounded
        stderr tail for diagnostics.
        """
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            bufsize=0,
            start_new_session=True,
            preexec_fn=child_process_preexec(),
        )
        pgid = os.getpgid(process.pid)
        try:
            register_child_group(pgid, process)
        except ChildProcessError:
            raise
        except BaseException:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise

        stderr_tail = bytearray()
        stdout_error: list[BaseException] = []

        def drain_stdout() -> None:
            if process.stdout is None:
                return
            pending = bytearray()
            dropping_oversized_line = False
            try:
                while True:
                    chunk = process.stdout.read(65536)
                    if not chunk:
                        break
                    start_index = 0
                    while start_index < len(chunk):
                        newline = chunk.find(b"\n", start_index)
                        end_index = len(chunk) if newline < 0 else newline + 1
                        segment = chunk[start_index:end_index]
                        start_index = end_index
                        if dropping_oversized_line:
                            if newline >= 0:
                                dropping_oversized_line = False
                            continue
                        if len(pending) + len(segment) > MAX_RESTIC_STREAM_LINE_BYTES:
                            pending.clear()
                            stdout_error.append(ResticError("Restic emitted an oversized output line"))
                            if newline < 0:
                                dropping_oversized_line = True
                            continue
                        pending.extend(segment)
                        if newline >= 0:
                            on_stdout(bytes(pending).decode("utf-8", "replace"))
                            pending.clear()
                if pending and not dropping_oversized_line:
                    on_stdout(bytes(pending).decode("utf-8", "replace"))
            except BaseException as exc:
                stdout_error.append(exc)
                # Continue draining if the callback failed so Restic cannot block
                # forever on a full stdout pipe while the parent is waiting.
                try:
                    while process.stdout.read(65536):
                        pass
                except BaseException:
                    pass

        def drain_stderr() -> None:
            if process.stderr is None:
                return
            while True:
                chunk = process.stderr.read(65536)
                if not chunk:
                    return
                stderr_tail.extend(chunk)
                if len(stderr_tail) > MAX_RESTIC_STDERR_BYTES:
                    del stderr_tail[:-MAX_RESTIC_STDERR_BYTES]

        stdout_thread = threading.Thread(target=drain_stdout, daemon=True)
        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        try:
            _wait_with_cancellation(process, pgid, timeout)
        finally:
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            unregister_child_group(pgid)
        if stdout_error:
            first = stdout_error[0]
            if isinstance(first, ResticError):
                raise first
            raise ResticError(f"Restic output processing failed: {first}") from first
        stderr = bytes(stderr_tail).decode("utf-8", "replace")
        if len(stderr_tail) == MAX_RESTIC_STDERR_BYTES:
            stderr = "[earlier stderr truncated]\n" + stderr
        return process.returncode, stderr

    def backup(self, sources_file: Path, excludes_file: Path, dry_run: bool,
               on_message: Callable[[dict], None] | None = None) -> DryRunSummary:
        self.init_repository()
        cmd = self._base() + ["backup", "--json", "--verbose=2", "--exclude-caches",
                              "--files-from-verbatim", str(sources_file),
                              "--exclude-file", str(excludes_file), "--tag", "ubackup"]
        if dry_run:
            cmd.append("--dry-run")
        summary = DryRunSummary()
        def consume(line: str) -> None:
            line = line.strip()
            if not line:
                return
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                msg = {"message_type": "text", "text": line}
            if on_message:
                on_message(msg)
            if msg.get("message_type") == "summary":
                if msg.get("snapshot_id"):
                    summary.snapshot_id = str(msg["snapshot_id"])
                for field in ("total_bytes_processed", "data_added", "data_added_packed",
                              "files_new", "files_changed", "files_unmodified"):
                    if field in msg:
                        setattr(summary, field, int(msg[field]))
        code, stderr = self._stream_process(cmd, self.env, consume, timeout=RESTIC_BACKUP_TIMEOUT)
        if code not in (0, 3):
            raise ResticError(_restic_failure_message(stderr, f"restic backup exited with status {code}"))
        if code == 3 and on_message:
            on_message({"message_type": "warning", "text": "Incomplete snapshot: some files could not be read"})
        summary.partial = code == 3
        return summary

    def snapshots(self, limit: int | None = None, offset: int = 0) -> list[SnapshotRecord]:
        if not self.repository_exists() or not self.password_exists():
            return []
        p = self._run(self._base() + ["snapshots", "--json", "--tag", "ubackup"], timeout=120)
        if p.returncode != 0:
            raise ResticError((p.stderr or p.stdout).strip())
        raw = json.loads(p.stdout or "[]")
        result = []
        for s in raw:
            summary = s.get("summary") or {}
            result.append(SnapshotRecord(
                id=s.get("id", ""), time=s.get("time", ""), hostname=s.get("hostname", ""),
                paths=s.get("paths", []), tags=s.get("tags", []), parent=s.get("parent", ""),
                total_bytes_processed=int(summary.get("total_bytes_processed", 0) or 0),
                data_added=int(summary.get("data_added", 0) or 0),
                data_added_packed=int(summary.get("data_added_packed", 0) or 0),
            ))
        ordered = sorted(result, key=lambda x: x.time, reverse=True)
        if offset < 0:
            raise ValueError("negative snapshot offset")
        return ordered[offset:] if limit is None else ordered[offset:offset + max(0, min(limit, 5000))]

    def list_snapshot(self, snapshot_id: str, limit: int | None = None, offset: int = 0) -> list[dict]:
        if not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
            raise ResticError("Invalid snapshot id")
        p = self._run(self._base() + ["ls", snapshot_id, "--json"], timeout=600)
        if p.returncode != 0:
            raise ResticError((p.stderr or p.stdout).strip())
        items = []
        for line in p.stdout.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                raise ResticError("Restic ls produced invalid JSON")
            if obj.get("struct_type") == "node" or "path" in obj:
                items.append(obj)
        if offset < 0:
            raise ValueError("negative snapshot offset")
        return items[offset:] if limit is None else items[offset:offset + max(0, min(limit, 10000))]


    def list_directory(
        self,
        snapshot_id: str,
        directory: str,
        limit: int | None = None,
        offset: int = 0,
        *,
        probe: bool = False,
    ) -> list[dict]:
        """List only immediate children of an absolute snapshot directory."""
        from pathlib import PurePosixPath
        if not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
            raise ResticError("Invalid snapshot id")
        directory = directory if directory.startswith("/") else "/" + directory
        directory = str(PurePosixPath(directory))
        if offset < 0 or offset > MAX_DIRECTORY_NODES:
            raise ValueError("negative directory offset")
        requested_limit = MAX_DIRECTORY_NODES if limit is None else max(0, min(limit, MAX_DIRECTORY_NODES))
        if limit is not None and offset + requested_limit > MAX_DIRECTORY_NODES:
            raise ResticError("directory pagination window exceeds the limit")
        extra = 1 if probe else 0
        keep = offset + requested_limit + extra
        heap: list[_ReverseHeapNode] = []
        parse_error = False

        def consume(line: str) -> None:
            nonlocal parse_error
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_error = True
                return
            if obj.get("struct_type") != "node":
                return
            node_path = obj.get("path", "")
            if not node_path or node_path == directory:
                return
            if str(PurePosixPath(node_path).parent) == directory:
                name = str(obj.get("name", ""))
                key = (obj.get("type") != "dir", name.casefold(), name)
                candidate = _ReverseHeapNode(key, obj)
                if len(heap) < keep:
                    heapq.heappush(heap, candidate)
                elif candidate.key < heap[0].key:
                    heapq.heapreplace(heap, candidate)

        # Put subcommand flags before positional arguments for compatibility
        # with older distro builds. Keep the explicit directory filter even
        # for '/' so a root browse never streams the whole snapshot just to
        # discover its immediate children.
        cmd = self._base() + ["ls", "--json", snapshot_id, directory]
        code, stderr = self._stream_process(
            cmd,
            self.env,
            consume,
            timeout=600,
        )
        if code != 0:
            raise ResticError(stderr.strip() or f"restic ls exit {code}")
        if parse_error:
            raise ResticError("Restic ls produced invalid JSON")
        out = [node.item for node in sorted(heap, key=lambda node: node.key)]
        if limit is None and len(out) > MAX_DIRECTORY_NODES:
            raise ResticError("directory listing requires pagination")
        return out[offset:offset + requested_limit + extra]

    @staticmethod
    def _manifest_candidate_from_source(path: str) -> str | None:
        if not isinstance(path, str):
            return None
        marker = "/.ubackup/state/"
        if marker not in path:
            return None
        prefix, suffix = path.split(marker, 1)
        domain, sep, tail = suffix.partition("/current/")
        if not sep or domain not in {"filesystem", "configs", "packages"} or not tail:
            return None
        return f"{prefix}{marker}{domain}/current/manifest.json"

    @classmethod
    def _is_manifest_source(cls, path: str) -> bool:
        candidate = cls._manifest_candidate_from_source(path)
        return bool(candidate is not None and candidate == path)

    def find_manifest_path(self, snapshot_id: str) -> str | None:
        """Locate UBackup metadata without walking a potentially huge snapshot.

        The manifest is always passed to Restic as an explicit backup source.
        Restic records those source paths in snapshot metadata, so use that
        bounded source list first.  The recursive ``ls`` fallback is retained
        only as a defensive locator for snapshots produced by the current
        domain-specific layout when source metadata is unavailable.
        """
        if not SNAPSHOT_ID_RE.fullmatch(snapshot_id):
            raise ResticError("Invalid snapshot id")
        for record in self.snapshots():
            if record.id == snapshot_id:
                for source in record.paths:
                    candidate = self._manifest_candidate_from_source(source)
                    if candidate is not None:
                        return candidate
                break

        found: str | None = None
        parse_error = False

        def consume(line: str) -> None:
            nonlocal found, parse_error
            if found is not None:
                return
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                parse_error = True
                return
            path = item.get("path", "") if isinstance(item, dict) else ""
            if self._is_manifest_source(path):
                found = path

        code, stderr = self._stream_process(
            self._base() + ["ls", "--json", snapshot_id], self.env, consume, timeout=600
        )
        if code != 0:
            raise ResticError(stderr.strip() or f"restic ls exit {code}")
        if parse_error:
            raise ResticError("Restic ls produced invalid JSON")
        return found

    def load_manifest(self, snapshot_id: str) -> dict:
        path = self.find_manifest_path(snapshot_id)
        if not path:
            raise ResticError("UBackup manifest was not found in the snapshot")
        value = self.dump_json(snapshot_id, path)
        if not isinstance(value, dict):
            raise ResticError("UBackup manifest has an invalid shape")
        return value

    def forget_snapshots(
        self,
        snapshot_ids: Iterable[str],
        *,
        prune: bool,
        on_message: Callable[[dict], None] | None = None,
    ) -> None:
        ids = list(dict.fromkeys(snapshot_ids))
        if not ids:
            return
        if any(not SNAPSHOT_ID_RE.fullmatch(value) for value in ids):
            raise ResticError("Invalid snapshot id")
        cmd = self._base() + ["forget", *ids]
        if prune:
            cmd.append("--prune")

        def consume(line: str) -> None:
            text = line.strip()
            if text and on_message:
                on_message({"message_type": "text", "current_item": text, "text": text})

        code, stderr = self._stream_process(cmd, self.env, consume, timeout=RESTIC_BACKUP_TIMEOUT)
        if code != 0:
            raise ResticError(stderr.strip() or f"restic forget exit {code}")

    def dump_json(self, snapshot_id: str, path: str) -> dict:
        p = self._run(self._base() + ["dump", snapshot_id, path], timeout=120)
        if p.returncode != 0:
            raise ResticError((p.stderr or p.stdout).strip())
        return json.loads(p.stdout)

    def restore(self, snapshot_id: str, target: Path, includes: Iterable[str],
                on_message: Callable[[dict], None] | None = None) -> None:
        target.mkdir(parents=True, exist_ok=True)
        cmd = self._base() + ["restore", snapshot_id, "--target", str(target), "--json"]
        for inc in includes:
            cmd.extend(["--include", inc])
        def consume(line: str) -> None:
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                msg = {"message_type": "text", "text": line.strip()}
            if on_message:
                on_message(msg)
        code, stderr = self._stream_process(cmd, self.env, consume, timeout=RESTIC_RESTORE_TIMEOUT)
        if code != 0:
            raise ResticError(stderr.strip() or f"restic restore exit {code}")

    def stats(self, snapshot_id: str) -> dict:
        p = self._run(self._base() + ["stats", snapshot_id, "--json"], timeout=300)
        if p.returncode != 0:
            raise ResticError((p.stderr or p.stdout).strip())
        return json.loads(p.stdout or "{}")
