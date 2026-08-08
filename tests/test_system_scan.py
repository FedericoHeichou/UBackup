import sqlite3
import subprocess
from pathlib import Path
import os
from types import SimpleNamespace

import pytest

from ubackup import system_scan
from ubackup.cache import CacheDB
from ubackup.fs_scan import SizeScanner


def test_scan_manual_packages_deduplicates_normalized_names(tmp_path, monkeypatch):
    cache = CacheDB(tmp_path / "cache.sqlite")

    def fake_run(cmd, env, timeout=120):
        if cmd[0] == "apt-mark":
            return subprocess.CompletedProcess(cmd, 0, stdout="demo\n", stderr="")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=(
                "demo:amd64\t1.0\tamd64\tinstalled\n"
                "demo\t1.0\tamd64\tinstalled\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(system_scan, "_run", fake_run)
    monkeypatch.setattr(system_scan, "package_cache_key", lambda: "test-key")

    records = system_scan.scan_manual_packages(cache, {}, force=True)

    assert [record.name for record in records] == ["demo"]
    assert cache.load_cached_records("packages_cache", "test-key") is not None
    cache.close()


def test_replace_cached_records_rolls_back_failed_refresh(tmp_path):
    cache = CacheDB(tmp_path / "cache.sqlite")
    existing = {"name": "demo", "version": "1.0", "architecture": "amd64"}
    cache.replace_cached_records("packages_cache", "name", [existing], "old-key")

    with pytest.raises(sqlite3.IntegrityError):
        cache.replace_cached_records(
            "packages_cache",
            "name",
            [existing, {**existing, "version": "2.0"}],
            "new-key",
        )

    assert cache.load_cached_records("packages_cache", "old-key") == [existing]
    cache.close()


def test_recursive_size_scan_honors_cancellation_checkpoint(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    for index in range(20):
        branch = root / f"branch-{index}"
        branch.mkdir()
        (branch / "payload").write_bytes(b"x")
    cache = CacheDB(tmp_path / "cache.sqlite")
    calls = 0

    class ScanCancelled(RuntimeError):
        pass

    def checkpoint():
        nonlocal calls
        calls += 1
        if calls >= 3:
            raise ScanCancelled

    with pytest.raises(ScanCancelled):
        SizeScanner(cache, tmp_path / "backup").scan(root, checkpoint=checkpoint)
    assert calls >= 3
    cache.close()


def test_real_mounted_filesystems_filters_pseudo_bind_and_desktop_mounts(monkeypatch):
    mounts = "\n".join([
        # Put the bind alias before / to prove canonical mount selection does
        # not depend on /proc/self/mounts ordering.
        "/dev/sda2 /var/snap/firefox/common/host-hunspell ext4 rw,bind 0 0",
        "/dev/sda2 / ext4 rw 0 0",
        "none /sys/fs/bpf bpf rw 0 0",
        "lxcfs /var/lib/lxcfs fuse.lxcfs rw 0 0",
        "gvfsd-fuse /run/user/1000/gvfs fuse.gvfsd-fuse rw 0 0",
        "/dev/sdb1 /data ext4 rw 0 0",
    ])
    devices = {
        "/": 1,
        "/var/snap/firefox/common/host-hunspell": 1,
        "/data": 2,
    }
    monkeypatch.setattr(system_scan.os, "stat", lambda path: SimpleNamespace(st_dev=devices[path]))
    monkeypatch.setattr(
        system_scan.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=100, used=60, free=40),
    )

    rows = system_scan.real_mounted_filesystems(mounts)

    assert [row["mount"] for row in rows] == ["/", "/data"]


def test_recursive_size_scan_reports_directories_when_cache_is_committed(tmp_path):
    root = tmp_path / "tree"
    child = root / "child"
    child.mkdir(parents=True)
    (child / "payload").write_bytes(b"abc")
    cache = CacheDB(tmp_path / "cache.sqlite")
    committed = []

    SizeScanner(cache, tmp_path / "backup").scan(
        root,
        cache_progress=lambda path, size, count: committed.append((path, size, count)),
    )

    assert str(child) in {row[0] for row in committed}
    assert str(root) in {row[0] for row in committed}
    cache.close()


def test_dependency_status_falls_back_to_dpkg_package_version(monkeypatch):
    monkeypatch.setattr(system_scan.shutil, "which", lambda command: f"/usr/bin/{command}")
    monkeypatch.setattr(system_scan, "_version", lambda command, env: "")
    monkeypatch.setattr(system_scan, "_dpkg_package_version", lambda package: f"pkg-{package}-1.0")
    rows = system_scan.dependency_status({})
    assert all(row.version for row in rows)
    assert rows[0].version == "pkg-restic-1.0"


def test_recursive_size_scan_matches_restic_cachedir_tag_exclusion(tmp_path):
    root = tmp_path / "tree-cachedir"
    cached = root / "generated-cache"
    keep = root / "keep"
    cached.mkdir(parents=True, mode=0o755)
    keep.mkdir(mode=0o755)
    os.chmod(root, 0o755)
    os.chmod(cached, 0o755)
    os.chmod(keep, 0o755)
    marker = cached / "CACHEDIR.TAG"
    marker.write_bytes(
        b"Signature: 8a477f597d28d172789f06886806bc55\n"
        b"# cache directory\n"
    )
    payload = cached / "large-generated.bin"
    payload.write_bytes(b"x" * 1000)
    kept = keep / "document.bin"
    kept.write_bytes(b"y" * 10)
    for path in (marker, payload, kept):
        os.chmod(path, 0o644)

    cache = CacheDB(tmp_path / "cachedir.sqlite3")
    try:
        scanner = SizeScanner(cache, tmp_path / "backup", [])
        size, count = scanner.scan(root, force=True)
        marker_size = marker.stat().st_size
        assert size == marker_size + 10
        assert count == 2
        row = cache.get_fs(str(root), scan_key=scanner.scan_key)
        assert row is not None
        assert row["size"] == marker_size + 10
        assert row["total_size"] == marker_size + 1010
        cached_row = cache.get_fs(str(cached), scan_key=scanner.scan_key)
        assert cached_row is not None
        assert cached_row["size"] == marker_size
        assert cached_row["total_size"] == marker_size + 1000
        payload_row = cache.get_fs(str(payload), scan_key=scanner.scan_key)
        assert payload_row is not None and payload_row["size"] == 0 and payload_row["total_size"] == 1000
    finally:
        cache.close()


def test_recursive_size_scan_excludes_profile_paths_and_keys_cache(tmp_path):
    root = tmp_path / "tree"
    keep = root / "keep"
    excluded = root / "node_modules"
    keep.mkdir(parents=True)
    excluded.mkdir()
    (keep / "payload.bin").write_bytes(b"a" * 10)
    (excluded / "payload.bin").write_bytes(b"b" * 100)
    cache = CacheDB(tmp_path / "cache.sqlite")
    try:
        filtered = SizeScanner(cache, tmp_path / "backup", ["**/node_modules/**"])
        size, _count = filtered.scan(root)
        assert size == 10
        filtered_row = cache.get_fs(str(root), scan_key=filtered.scan_key)
        assert filtered_row is not None and filtered_row["size"] == 10
        assert filtered_row["total_size"] == 110
        assert filtered_row["total_file_count"] == 2
        excluded_row = cache.get_fs(str(excluded), scan_key=filtered.scan_key)
        assert excluded_row is not None
        assert excluded_row["size"] == 0
        assert excluded_row["total_size"] == 100

        unfiltered = SizeScanner(cache, tmp_path / "backup", [])
        assert cache.get_fs(str(root), scan_key=unfiltered.scan_key) is None
        size, _count = unfiltered.scan(root)
        assert size == 10
        assert unfiltered.last_source == "cache-stale-profile"
        size, _count = unfiltered.scan(root, force=True)
        assert size == 110
    finally:
        cache.close()


def test_recursive_size_cache_has_no_time_ttl_when_identity_and_profile_match(tmp_path):
    root = tmp_path / "tree-old-cache"
    root.mkdir()
    (root / "payload.bin").write_bytes(b"x" * 17)
    info = os.lstat(root)
    cache = CacheDB(tmp_path / "old-cache.sqlite3")
    scanner = SizeScanner(cache, tmp_path / "backup", [])
    try:
        cache.put_fs(
            str(root), 17, info.st_mtime_ns, info.st_ino, info.st_dev, 1,
            scanned_at=1.0, scan_key=scanner.scan_key,
        )
        size, count = scanner.scan(root)
        assert (size, count) == (17, 1)
        assert cache.get_fs(str(root), scan_key=scanner.scan_key)["scanned_at"] == 1.0
    finally:
        cache.close()


def test_existing_flat_size_cache_is_reused_without_topology_rebuild(tmp_path):
    root = tmp_path / "tree-legacy-topology"
    root.mkdir(mode=0o755)
    os.chmod(root, 0o755)
    payload = root / "payload.bin"
    payload.write_bytes(b"legacy")
    os.chmod(payload, 0o644)
    info = os.lstat(root)
    cache = CacheDB(tmp_path / "legacy-topology.sqlite3")
    scanner = SizeScanner(cache, tmp_path / "backup")
    try:
        cache.put_fs(
            str(root), 6, info.st_mtime_ns, info.st_ino, info.st_dev, 1,
            scanned_at=1.0, scan_key=scanner.scan_key, total_size=6, total_file_count=1,
        )
        size, count = scanner.scan(root)
        assert (size, count) == (6, 1)
        assert cache.get_fs(str(root), scan_key=scanner.scan_key)["scanned_at"] == 1.0
    finally:
        cache.close()


def test_recursive_size_scan_progress_is_global_monotonic_and_tracks_files(tmp_path):
    root = tmp_path / "tree-progress"
    first = root / "first"
    second = root / "second"
    first.mkdir(parents=True)
    second.mkdir()
    for index in range(20):
        (first / f"a-{index:03d}").write_bytes(b"a" * 10)
        (second / f"b-{index:03d}").write_bytes(b"b" * 20)

    cache = CacheDB(tmp_path / "progress.sqlite3")
    events = []
    committed = []
    scanner = SizeScanner(cache, tmp_path / "backup")
    scanner.PROGRESS_INTERVAL_SECONDS = 0.0
    try:
        size, count = scanner.scan(
            root,
            progress=lambda path, bytes_done, items_done: events.append((path, bytes_done, items_done)),
            cache_progress=lambda path, subtree_size, subtree_count: committed.append((path, subtree_size, subtree_count)),
        )
    finally:
        cache.close()

    assert size == 600
    assert count == 40
    assert events
    assert all(left[1] <= right[1] for left, right in zip(events, events[1:]))
    assert all(left[2] <= right[2] for left, right in zip(events, events[1:]))
    assert any(Path(path).name.startswith(("a-", "b-")) for path, _bytes, _items in events)
    assert events[-1][1:] == (600, 40)
    assert {str(first), str(second), str(root)} <= {row[0] for row in committed}


def test_filesystem_cache_schema_migrates_total_columns_without_fabricating_old_totals(tmp_path):
    db = tmp_path / "legacy-fs-cache.sqlite3"
    con = sqlite3.connect(db)
    con.execute(
        """CREATE TABLE fs_cache (
            path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            inode INTEGER NOT NULL,
            dev INTEGER NOT NULL,
            file_count INTEGER NOT NULL,
            scanned_at REAL NOT NULL,
            scan_key TEXT NOT NULL DEFAULT ''
        )"""
    )
    con.execute(
        "INSERT INTO fs_cache(path,size,mtime_ns,inode,dev,file_count,scanned_at,scan_key) VALUES(?,?,?,?,?,?,?,?)",
        ("/legacy", 42, 1, 2, 3, 4, 5.0, "old-profile"),
    )
    con.commit()
    con.close()

    cache = CacheDB(db)
    try:
        row = cache.get_fs("/legacy")
        assert row is not None
        assert row["size"] == 42
        assert row["total_size"] is None
        assert row["total_file_count"] is None
    finally:
        cache.close()


def test_recursive_size_scan_persists_flat_cache_for_files_and_directories(tmp_path):
    root = tmp_path / "tree-index"
    child = root / "child"
    root.mkdir(mode=0o755)
    child.mkdir(mode=0o755)
    os.chmod(root, 0o755)
    os.chmod(child, 0o755)
    payload = child / "payload.bin"
    payload.write_bytes(b"abc")
    os.chmod(payload, 0o644)
    direct = root / "direct.bin"
    direct.write_bytes(b"hello")
    os.chmod(direct, 0o644)
    link = root / "payload-link"
    link.symlink_to("direct.bin")

    cache = CacheDB(tmp_path / "tree-index.sqlite3")
    scanner = SizeScanner(cache, tmp_path / "backup")
    try:
        scanner.scan(root, force=True)
        rows = cache.get_fs_many([str(root), str(child), str(payload), str(direct), str(link)])
        assert rows[str(root)]["total_size"] == 8
        assert rows[str(child)]["total_size"] == 3
        assert rows[str(payload)]["total_size"] == 3
        assert rows[str(direct)]["total_size"] == 5
        assert rows[str(link)]["total_size"] == 0
        assert rows[str(payload)]["file_count"] == 1
        assert rows[str(link)]["file_count"] == 1
    finally:
        cache.close()


def test_live_listing_observes_new_membership_and_marks_cached_aggregate_stale(tmp_path):
    from ubackup.privileged.filesystem_navigation import children
    from ubackup.privileged.inspect import enrich_filesystem_cache

    root = tmp_path / "tree-stale"
    root.mkdir(mode=0o755)
    os.chmod(root, 0o755)
    first = root / "first"
    first.write_bytes(b"1")
    os.chmod(first, 0o644)
    cache = CacheDB(tmp_path / "tree-stale.sqlite3")
    scanner = SizeScanner(cache, tmp_path / "backup")
    try:
        scanner.scan(root, force=True)
        initial = children(root, 100, 0)
        enrich_filesystem_cache(initial, cache, scanner.scan_key)
        assert {record["name"] for record in initial} == {"first"}

        second = root / "second"
        second.write_bytes(b"2")
        os.chmod(second, 0o644)
        # Do not rely on filesystem timestamp granularity or the host umask.
        current = os.lstat(root)
        os.utime(root, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000))

        live = children(root, 100, 0)
        enrich_filesystem_cache(live, cache, scanner.scan_key)
        assert {record["name"] for record in live} == {"first", "second"}
        by_name = {record["name"]: record for record in live}
        assert by_name["first"]["cache_present"] is True
        assert by_name["second"]["cache_present"] is True

        root_row = cache.get_fs(str(root))
        assert root_row is not None
        assert int(root_row["mtime_ns"]) != int(os.lstat(root).st_mtime_ns)
    finally:
        cache.close()


def test_policy_change_keeps_cached_size_stale_without_filesystem_walk(monkeypatch, tmp_path):
    """Changing EXCLUDE policy must not implicitly rescan a cached subtree."""
    root = tmp_path / "home" / "federico"
    steam = root / ".steam"
    docs = root / "Documents"
    steam.mkdir(parents=True, mode=0o755)
    docs.mkdir(mode=0o755)
    os.chmod(root.parent, 0o755)
    os.chmod(root, 0o755)
    os.chmod(steam, 0o755)
    os.chmod(docs, 0o755)
    steam_payload = steam / "library.bin"
    docs_payload = docs / "keep.bin"
    steam_payload.write_bytes(b"s" * 100)
    docs_payload.write_bytes(b"d" * 25)
    os.chmod(steam_payload, 0o644)
    os.chmod(docs_payload, 0o644)

    cache = CacheDB(tmp_path / "reprofile.sqlite3")
    try:
        initial = SizeScanner(cache, tmp_path / "backup", [])
        assert initial.scan(root, force=True)[0] == 125

        # A new manual exclusion changes only the effective profile. Cached
        # aggregates remain displayable (stale) until explicit Recalculate.
        late = docs / "appeared-after-scan.bin"
        late.write_bytes(b"late")
        os.chmod(late, 0o644)
        current = os.lstat(root)
        os.utime(root, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000))
        reprofiled = SizeScanner(cache, tmp_path / "backup", [str(steam) + "/**"])
        monkeypatch.setattr(os, "scandir", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected filesystem walk")))
        size, count = reprofiled.scan(root, force=False)

        assert (size, count) == (125, 2)
        assert reprofiled.last_source == "cache-stale-profile"
        assert cache.get_fs(str(root), scan_key=reprofiled.scan_key) is None
        root_row = cache.get_fs(str(root))
        assert root_row is not None and root_row["size"] == 125 and root_row["total_size"] == 125
    finally:
        cache.close()
