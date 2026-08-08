from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable

from .models import SelectionPolicy


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS fs_cache (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    total_size INTEGER,
    mtime_ns INTEGER NOT NULL,
    inode INTEGER NOT NULL,
    dev INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    total_file_count INTEGER,
    scanned_at REAL NOT NULL,
    scan_key TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS selections (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    selected INTEGER NOT NULL,
    PRIMARY KEY (kind, key)
);
CREATE TABLE IF NOT EXISTS path_policies (
    path TEXT PRIMARY KEY,
    policy TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS known_paths (
    path TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    recorded_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS fixed_selection_members (
    root TEXT NOT NULL,
    path TEXT NOT NULL,
    is_dir INTEGER NOT NULL,
    captured_at REAL NOT NULL,
    PRIMARY KEY (root, path)
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS packages_cache (
    name TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    cache_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS package_inventory_cache (
    cache_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    cache_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS configs_cache (
    path TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    cache_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshot_manifest (
    snapshot_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""


class CacheDB:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._closed = False
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate_fs_cache_scan_key()
            self._migrate_fs_cache_total_columns()
            self._migrate_source_selections()
            self._migrate_fixed_selection_semantics()
            self._conn.commit()


    def _migrate_fs_cache_scan_key(self) -> None:
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(fs_cache)").fetchall()}
        if "scan_key" not in columns:
            self._conn.execute("ALTER TABLE fs_cache ADD COLUMN scan_key TEXT NOT NULL DEFAULT ''")

    def _migrate_fs_cache_total_columns(self) -> None:
        """Add profile-independent totals without guessing values for old rows."""
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(fs_cache)").fetchall()}
        if "total_size" not in columns:
            self._conn.execute("ALTER TABLE fs_cache ADD COLUMN total_size INTEGER")
        if "total_file_count" not in columns:
            self._conn.execute("ALTER TABLE fs_cache ADD COLUMN total_file_count INTEGER")

    def _migrate_fixed_selection_semantics(self) -> None:
        """Upgrade legacy frozen folder selections to the new recursive checkbox semantics."""
        roots = [
            row[0] for row in self._conn.execute(
                "SELECT DISTINCT root FROM fixed_selection_members WHERE root=path AND is_dir=1"
            ).fetchall()
        ]
        if not roots:
            return
        self._conn.executemany(
            "UPDATE path_policies SET policy=? WHERE path=? AND policy=?",
            [(SelectionPolicy.INCLUDE_RECURSIVE.value, root, SelectionPolicy.INCLUDE.value) for root in roots],
        )
        self._conn.execute("DELETE FROM fixed_selection_members")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._conn.close()
            self._closed = True

    def get_fs(self, path: str, max_age: float | None = None, scan_key: str | None = None):
        with self._lock:
            row = self._conn.execute("SELECT * FROM fs_cache WHERE path=?", (path,)).fetchone()
        if row is None:
            return None
        if max_age is not None and time.time() - row["scanned_at"] > max_age:
            return None
        if scan_key is not None and str(row["scan_key"] or "") != str(scan_key):
            return None
        return dict(row)

    def get_fs_many(
        self, paths: Iterable[str], *, scan_key: str | None = None,
    ) -> dict[str, dict]:
        """Return cache rows for a bounded set of paths with batched SELECTs.

        Filesystem navigation only needs metadata for the direct children that
        were just observed by ``scandir``.  Reading the complete cached tree is
        both unnecessary and expensive, so callers fetch exactly those rows.
        """
        normalized = list(dict.fromkeys(str(Path(path)) for path in paths if path))
        if not normalized:
            return {}
        out: dict[str, dict] = {}
        with self._lock:
            for offset in range(0, len(normalized), 400):
                batch = normalized[offset:offset + 400]
                placeholders = ",".join("?" for _ in batch)
                if scan_key is None:
                    rows = self._conn.execute(
                        f"SELECT * FROM fs_cache WHERE path IN ({placeholders})",
                        batch,
                    ).fetchall()
                else:
                    rows = self._conn.execute(
                        f"SELECT * FROM fs_cache WHERE scan_key=? AND path IN ({placeholders})",
                        (str(scan_key), *batch),
                    ).fetchall()
                out.update((str(row["path"]), dict(row)) for row in rows)
        return out

    def put_fs(self, path: str, size: int, mtime_ns: int, inode: int, dev: int,
               file_count: int, scanned_at: float | None = None, scan_key: str = "",
               total_size: int | None = None, total_file_count: int | None = None) -> None:
        total_size = int(size) if total_size is None else int(total_size)
        total_file_count = int(file_count) if total_file_count is None else int(total_file_count)
        with self._lock:
            self._conn.execute(
                """INSERT INTO fs_cache(path,size,total_size,mtime_ns,inode,dev,file_count,total_file_count,scanned_at,scan_key)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET size=excluded.size,total_size=excluded.total_size,
                   mtime_ns=excluded.mtime_ns,inode=excluded.inode,dev=excluded.dev,file_count=excluded.file_count,
                   total_file_count=excluded.total_file_count,scanned_at=excluded.scanned_at,scan_key=excluded.scan_key""",
                (path, size, total_size, mtime_ns, inode, dev, file_count, total_file_count,
                 scanned_at or time.time(), str(scan_key)),
            )
            self._conn.commit()

    def put_fs_many(self, rows: Iterable[dict]) -> None:
        """Upsert filesystem cache rows in one transaction.

        Recursive scans cache every file and directory they encounter.  A
        commit per path makes large scans SQLite-bound; batch commits keep the
        cache granular without turning persistence into the dominant cost.
        """
        values = []
        for row in rows:
            size = int(row.get("size", 0) or 0)
            file_count = int(row.get("file_count", 0) or 0)
            total_size = row.get("total_size")
            total_file_count = row.get("total_file_count")
            values.append((
                str(row["path"]), size,
                size if total_size is None else int(total_size),
                int(row.get("mtime_ns", 0) or 0), int(row.get("inode", 0) or 0),
                int(row.get("dev", 0) or 0), file_count,
                file_count if total_file_count is None else int(total_file_count),
                float(row.get("scanned_at", time.time()) or time.time()),
                str(row.get("scan_key", "") or ""),
            ))
        if not values:
            return
        with self._lock:
            self._conn.executemany(
                """INSERT INTO fs_cache(path,size,total_size,mtime_ns,inode,dev,file_count,total_file_count,scanned_at,scan_key)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(path) DO UPDATE SET size=excluded.size,total_size=excluded.total_size,
                   mtime_ns=excluded.mtime_ns,inode=excluded.inode,dev=excluded.dev,file_count=excluded.file_count,
                   total_file_count=excluded.total_file_count,scanned_at=excluded.scanned_at,scan_key=excluded.scan_key""",
                values,
            )
            self._conn.commit()


    def _migrate_source_selections(self) -> None:
        """Migrate the legacy source boolean model without discarding user intent."""
        count = self._conn.execute("SELECT COUNT(*) FROM path_policies").fetchone()[0]
        if count:
            return
        rows = self._conn.execute("SELECT key, selected FROM selections WHERE kind='source'").fetchall()
        for row in rows:
            policy = SelectionPolicy.INCLUDE_RECURSIVE if bool(row["selected"]) else SelectionPolicy.EXCLUDE
            self._conn.execute(
                "INSERT OR IGNORE INTO path_policies(path, policy) VALUES(?, ?)",
                (row["key"], policy.value),
            )

    def set_path_policy(self, path: str, policy: SelectionPolicy) -> None:
        if not isinstance(policy, SelectionPolicy):
            policy = SelectionPolicy(str(policy))
        with self._lock:
            if policy is SelectionPolicy.DEFAULT:
                self._conn.execute("DELETE FROM path_policies WHERE path=?", (path,))
            else:
                self._conn.execute(
                    "INSERT INTO path_policies(path, policy) VALUES(?, ?) "
                    "ON CONFLICT(path) DO UPDATE SET policy=excluded.policy",
                    (path, policy.value),
                )
            self._conn.commit()

    def get_path_policy(self, path: str) -> SelectionPolicy:
        with self._lock:
            row = self._conn.execute("SELECT policy FROM path_policies WHERE path=?", (path,)).fetchone()
        if row is None:
            return SelectionPolicy.DEFAULT
        try:
            return SelectionPolicy(row[0])
        except ValueError:
            return SelectionPolicy.DEFAULT

    def path_policy_rows(self) -> list[tuple[str, SelectionPolicy]]:
        with self._lock:
            rows = self._conn.execute("SELECT path, policy FROM path_policies ORDER BY path").fetchall()
        out: list[tuple[str, SelectionPolicy]] = []
        for row in rows:
            try:
                out.append((row[0], SelectionPolicy(row[1])))
            except ValueError:
                continue
        return out

    def replace_fixed_selection(self, root: str, members: Iterable[tuple[str, bool]]) -> None:
        """Atomically replace the frozen membership for a non-recursive INCLUDE policy.

        The root itself is always recorded, even for an empty directory, so an
        empty catalog is distinguishable from a legacy INCLUDE policy that has
        never been captured.
        """
        root = str(Path(root))
        now = time.time()
        normalized: dict[str, bool] = {root: True}
        for path, is_dir in members:
            value = str(Path(path))
            if value == root or value.startswith(root.rstrip("/") + "/"):
                normalized[value] = bool(is_dir)
        rows = [(root, path, int(is_dir), now) for path, is_dir in normalized.items()]
        with self._lock:
            try:
                self._conn.execute("BEGIN")
                self._conn.execute("DELETE FROM fixed_selection_members WHERE root=?", (root,))
                self._conn.executemany(
                    "INSERT INTO fixed_selection_members(root,path,is_dir,captured_at) VALUES(?,?,?,?)",
                    rows,
                )
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    def clear_fixed_selection(self, root: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM fixed_selection_members WHERE root=?", (str(Path(root)),))
            self._conn.commit()

    def has_fixed_selection(self, root: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM fixed_selection_members WHERE root=? LIMIT 1", (str(Path(root)),)
            ).fetchone()
        return row is not None

    def is_fixed_selection_member(self, root: str, path: str) -> bool | None:
        root = str(Path(root)); path = str(Path(path))
        with self._lock:
            catalog = self._conn.execute(
                "SELECT 1 FROM fixed_selection_members WHERE root=? LIMIT 1", (root,)
            ).fetchone()
            if catalog is None:
                return None
            row = self._conn.execute(
                "SELECT 1 FROM fixed_selection_members WHERE root=? AND path=?", (root, path)
            ).fetchone()
        return row is not None

    def fixed_selection_members(self, root: str) -> list[tuple[str, bool]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT path,is_dir FROM fixed_selection_members WHERE root=? ORDER BY path",
                (str(Path(root)),),
            ).fetchall()
        return [(row[0], bool(row[1])) for row in rows]

    def fixed_selection_roots(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute("SELECT DISTINCT root FROM fixed_selection_members").fetchall()
        return {row[0] for row in rows}

    def is_known_path(self, path: str, snapshot_id: str | None = None) -> bool:
        with self._lock:
            if snapshot_id:
                row = self._conn.execute(
                    "SELECT 1 FROM known_paths WHERE path=? AND snapshot_id=?",
                    (path, snapshot_id),
                ).fetchone()
            else:
                row = self._conn.execute("SELECT 1 FROM known_paths WHERE path=?", (path,)).fetchone()
        return row is not None

    def mark_paths_known(self, paths: Iterable[str], snapshot_id: str) -> None:
        now = time.time()
        rows = [(str(path), snapshot_id, now) for path in set(paths) if path]
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO known_paths(path,snapshot_id,recorded_at) VALUES(?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET snapshot_id=excluded.snapshot_id,recorded_at=excluded.recorded_at",
                rows,
            )
            self._conn.commit()

    def known_paths(self, snapshot_id: str | None = None) -> set[str]:
        with self._lock:
            if snapshot_id:
                rows = self._conn.execute(
                    "SELECT path FROM known_paths WHERE snapshot_id=?", (snapshot_id,)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT path FROM known_paths").fetchall()
        return {row[0] for row in rows}

    def known_paths_for(self, paths: Iterable[str], snapshot_id: str) -> set[str]:
        """Return only requested paths known in one snapshot.

        GUI tree refreshes can involve thousands of visible rows while the
        snapshot inventory itself may contain far more entries.  Fetching the
        entire inventory on the Qt thread is unnecessary and was itself a
        source of UI stalls.  Keep the query bounded and batch around SQLite's
        host-parameter limit instead.
        """
        normalized = list(dict.fromkeys(str(Path(path)) for path in paths if path))
        if not normalized or not snapshot_id:
            return set()
        known: set[str] = set()
        with self._lock:
            for offset in range(0, len(normalized), 400):
                batch = normalized[offset:offset + 400]
                placeholders = ",".join("?" for _ in batch)
                rows = self._conn.execute(
                    f"SELECT path FROM known_paths WHERE snapshot_id=? AND path IN ({placeholders})",
                    (snapshot_id, *batch),
                ).fetchall()
                known.update(row[0] for row in rows)
        return known

    def set_selected(self, kind: str, key: str, selected: bool) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO selections(kind,key,selected) VALUES(?,?,?)
                   ON CONFLICT(kind,key) DO UPDATE SET selected=excluded.selected""",
                (kind, key, int(selected)),
            )
            self._conn.commit()

    def get_selected(self, kind: str, key: str, default: bool) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT selected FROM selections WHERE kind=? AND key=?", (kind, key)
            ).fetchone()
        return bool(row[0]) if row else default

    def selection_value(self, kind: str, key: str) -> bool | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT selected FROM selections WHERE kind=? AND key=?", (kind, key)
            ).fetchone()
        return bool(row[0]) if row else None

    def selection_rows(self, kind: str) -> list[tuple[str, bool]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key,selected FROM selections WHERE kind=? ORDER BY key", (kind,)
            ).fetchall()
        return [(r[0], bool(r[1])) for r in rows]

    def selected_keys(self, kind: str) -> list[str]:
        return [key for key, selected in self.selection_rows(kind) if selected]

    def put_kv(self, key: str, value) -> None:
        raw = json.dumps(value, ensure_ascii=False)
        with self._lock:
            self._conn.execute(
                "INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, raw),
            )
            self._conn.commit()

    def get_kv(self, key: str, default=None):
        with self._lock:
            row = self._conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default


    @staticmethod
    def _snapshot_stats_key(snapshot_id: str, component: str = "filesystem") -> str:
        # Snapshot IDs live in independent Restic repositories. Namespace the
        # GUI cache key by domain so an identical hash in two repositories can
        # never cross-contaminate displayed statistics.
        return f"{component}:{snapshot_id}"

    def put_snapshot_stats(self, snapshot_id: str, payload: dict, component: str = "filesystem") -> None:
        cache_key = self._snapshot_stats_key(snapshot_id, component)
        with self._lock:
            self._conn.execute(
                "INSERT INTO snapshot_manifest(snapshot_id,created_at,payload) VALUES(?,?,?) "
                "ON CONFLICT(snapshot_id) DO UPDATE SET created_at=excluded.created_at,payload=excluded.payload",
                (cache_key, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), json.dumps(payload, ensure_ascii=False)),
            )
            self._conn.commit()

    def get_snapshot_stats(self, snapshot_id: str, component: str = "filesystem") -> dict | None:
        cache_key = self._snapshot_stats_key(snapshot_id, component)
        with self._lock:
            row = self._conn.execute("SELECT payload FROM snapshot_manifest WHERE snapshot_id=?", (cache_key,)).fetchone()
        return json.loads(row[0]) if row else None

    def replace_cached_records(self, table: str, key_field: str, records: Iterable[dict], cache_key: str) -> None:
        if table not in {"packages_cache", "package_inventory_cache", "configs_cache"}:
            raise ValueError(table)
        rows = [
            (str(r[key_field]), json.dumps(r, ensure_ascii=False), cache_key)
            for r in records
        ]
        with self._lock:
            try:
                self._conn.execute("BEGIN")
                self._conn.execute(f"DELETE FROM {table}")
                self._conn.executemany(
                    f"INSERT INTO {table}({key_field},payload,cache_key) VALUES(?,?,?)",
                    rows,
                )
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    def load_cached_records(self, table: str, cache_key: str) -> list[dict] | None:
        if table not in {"packages_cache", "package_inventory_cache", "configs_cache"}:
            raise ValueError(table)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT payload,cache_key FROM {table} ORDER BY 1"
            ).fetchall()
        if not rows or any(r["cache_key"] != cache_key for r in rows):
            return None
        return [json.loads(r["payload"]) for r in rows]
