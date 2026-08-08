from __future__ import annotations

import contextlib
import json
import subprocess
from types import SimpleNamespace

from ubackup import system_scan
from ubackup.cache import CacheDB
from ubackup.manifest import build_privileged_state
from ubackup.models import BackupComponent, PackageManager, PackageRecord
from ubackup.paths import PrivilegedPaths
from ubackup.privileged.metadata import load_snapshot_metadata
from ubackup.profiles import DEFAULT_RULES, matches_resticish
from ubackup.restore_engine import RestoreEngine


def _completed(command, stdout=""):
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def test_unified_package_inventory_discovers_apt_snap_and_flatpak(monkeypatch):
    monkeypatch.setattr(system_scan.shutil, "which", lambda command, path=None: f"/usr/bin/{command}")
    monkeypatch.setattr(
        system_scan.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(pw_dir="/home/user", pw_name="user", pw_gid=1000),
    )
    calls = []
    monkeypatch.setattr(system_scan, "command_as_uid", lambda command, uid: ["asuid", str(uid), *command])

    def fake_run(command, env, timeout=120):
        target_uid = int(command[1]) if command and command[0] == "asuid" else None
        actual = command[2:] if target_uid is not None else command
        calls.append((list(actual), target_uid, dict(env)))
        command = actual
        if command[:2] == ["apt-mark", "showmanual"]:
            return _completed(command, "curl\n")
        if command[0] == "dpkg-query":
            return _completed(command, "curl:amd64\t8.0\tamd64\tinstalled\n")
        if command[:2] == ["snap", "list"]:
            return _completed(command, "Name Version Rev Tracking Publisher Notes\nfirefox 1.2 42 latest/stable mozilla** classic\n")
        if command[:2] == ["flatpak", "remotes"]:
            return _completed(command, "flathub\thttps://dl.flathub.org/repo/\tuser\n")
        if command[:2] == ["flatpak", "list"]:
            return _completed(
                command,
                "org.example.App\t2.0\tx86_64\tstable\tflathub\tuser\tapp/org.example.App/x86_64/stable\n",
            )
        raise AssertionError(command)

    monkeypatch.setattr(system_scan, "_run", fake_run)
    records = system_scan.discover_package_inventory({"PATH": "/usr/bin"}, 1000)
    assert [(row["manager"], row["name"]) for row in records] == [
        ("apt", "curl"), ("flatpak", "org.example.App"), ("snap", "firefox")
    ]
    flatpak = next(row for row in records if row["manager"] == "flatpak")
    assert flatpak["scope"] == "user"
    assert flatpak["origin"] == "flathub"
    assert flatpak["origin_url"] == "https://dl.flathub.org/repo/"
    snap = next(row for row in records if row["manager"] == "snap")
    assert snap["channel"] == "latest/stable"
    assert snap["classic"] is True
    flatpak_calls = [call for call in calls if call[0][0] == "flatpak"]
    assert flatpak_calls and all(call[1] == 1000 for call in flatpak_calls)
    assert all(call[2]["HOME"] == "/home/user" for call in flatpak_calls)


def test_package_inventory_cache_keeps_same_name_from_different_managers(tmp_path, monkeypatch):
    cache = CacheDB(tmp_path / "cache.sqlite3")
    try:
        monkeypatch.setattr(system_scan, "package_inventory_cache_key", lambda uid: "same-key")
        monkeypatch.setattr(
            system_scan,
            "discover_package_inventory",
            lambda env, uid: [
                PackageRecord("demo", "1", "amd64", True, True, manager=PackageManager.APT).to_dict(),
                PackageRecord("demo", "2", "", True, True, manager=PackageManager.SNAP).to_dict(),
            ],
        )
        fresh = system_scan.cached_package_inventory(cache, {}, 1000, force=True)
        cached = system_scan.cached_package_inventory(cache, {}, 1000, force=False)
        assert {(row["manager"], row["scope"], row["name"]) for row in fresh} == {
            ("apt", "system", "demo"), ("snap", "system", "demo")
        }
        assert cached == fresh
    finally:
        cache.close()


def test_package_snapshot_writes_one_metadata_file_per_manager(tmp_path, monkeypatch):
    root = tmp_path / "backup"
    paths = PrivilegedPaths.for_root(root).for_component(BackupComponent.PACKAGES.value)
    for directory in (paths.internal, paths.state, paths.current.parent, paths.current, paths.cache, paths.runtime):
        directory.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("ubackup.manifest.collect_system_inventory", lambda env: {"host": "test"})
    packages = [
        PackageRecord("curl", "1", "amd64", True, True, manager=PackageManager.APT),
        PackageRecord("firefox", "2", "", True, True, manager=PackageManager.SNAP, channel="latest/stable"),
        PackageRecord(
            "org.example.App", "3", "x86_64", True, True, manager=PackageManager.FLATPAK,
            scope="user", origin="flathub", origin_url="https://dl.flathub.org/repo/",
        ),
    ]
    build_privileged_state(paths, {}, [], [], [], packages, [], components=["packages"])
    assert not paths.packages_file.exists()
    for manager, expected in (("apt", "curl"), ("snap", "firefox"), ("flatpak", "org.example.App")):
        rows = json.loads((paths.current / f"packages-{manager}.json").read_text())
        assert [row["name"] for row in rows] == [expected]


def test_logical_package_metadata_combines_manager_files_and_accepts_legacy(tmp_path):
    paths = PrivilegedPaths.for_root(tmp_path).for_component("packages")

    class Engine:
        def __init__(self, legacy=False):
            self.legacy = legacy
        def dump_json(self, snapshot_id, path):
            from ubackup.restic_engine import ResticError
            name = path.rsplit("/", 1)[-1]
            if self.legacy:
                if name == "packages.json":
                    return [{"manager": "apt", "scope": "system", "name": "legacy"}]
                raise ResticError("missing")
            values = {
                "packages-apt.json": [{"manager": "apt", "scope": "system", "name": "curl"}],
                "packages-snap.json": [{"manager": "snap", "scope": "system", "name": "firefox"}],
                "packages-flatpak.json": [{"manager": "flatpak", "scope": "user", "name": "org.example.App"}],
            }
            if name not in values:
                raise ResticError("missing")
            return values[name]

    rows, recovered = load_snapshot_metadata(Engine(), paths, "abcdef12", "packages.json")
    assert recovered is False
    assert {(row["manager"], row["name"]) for row in rows} == {
        ("apt", "curl"), ("snap", "firefox"), ("flatpak", "org.example.App")
    }
    legacy, _ = load_snapshot_metadata(Engine(legacy=True), paths, "abcdef12", "packages.json")
    assert legacy[0]["name"] == "legacy"


def test_restore_dispatches_each_package_manager_without_mutating_flatpak_dry_run(monkeypatch):
    import ubackup.restore_engine as restore_engine_module
    monkeypatch.setattr(restore_engine_module, "command_as_uid", lambda command, uid: ["asuid", str(uid), *command])
    engine = RestoreEngine(object(), {"PATH": "/usr/bin"}, desktop_uid=1000)
    monkeypatch.setattr(engine, "_package_user_env", lambda: {"PATH": "/usr/bin", "HOME": "/home/user"})
    calls = []

    def fake_run(command, *, env=None):
        target_uid = int(command[1]) if command and command[0] == "asuid" else None
        actual = command[2:] if target_uid is not None else command
        calls.append((list(actual), target_uid, dict(env or {})))
        if "remotes" in actual:
            return _completed(actual, "flathub\n")
        return _completed(actual, "ok\n")

    monkeypatch.setattr(engine, "_run_package_command", fake_run)
    packages = [
        PackageRecord("curl", "1", "amd64", True, True, manager=PackageManager.APT),
        PackageRecord("firefox", "2", "", True, True, manager=PackageManager.SNAP, channel="latest/stable", classic=True),
        PackageRecord(
            "org.example.App", "3", "x86_64", True, True, manager=PackageManager.FLATPAK,
            scope="user", origin="flathub", reference="app/org.example.App/x86_64/stable",
            origin_url="https://dl.flathub.org/repo/",
        ),
    ]
    engine.restore_packages(packages, dry_run=True)
    commands = [row[0] for row in calls]
    assert ["apt-get", "install", "-y", "--simulate", "--", "curl"] in commands
    assert ["snap", "info", "firefox"] in commands
    assert ["flatpak", "--user", "remotes", "--columns=name"] in commands
    assert ["flatpak", "--user", "remote-info", "flathub", "app/org.example.App/x86_64/stable"] in commands
    assert not any("remote-add" in command for command in commands)
    assert all(uid == 1000 for command, uid, _env in calls if command[0] == "flatpak")

    calls.clear()
    engine.restore_packages(packages, dry_run=False)
    commands = [row[0] for row in calls]
    assert ["snap", "install", "--channel", "latest/stable", "--classic", "firefox"] in commands
    assert [
        "flatpak", "--user", "remote-add", "--if-not-exists", "flathub", "https://dl.flathub.org/repo/"
    ] in commands
    assert [
        "flatpak", "--user", "install", "-y", "flathub", "app/org.example.App/x86_64/stable"
    ] in commands


def test_package_manager_payload_paths_are_preconfigured_exclusions_but_user_data_is_retained():
    patterns = {rule.pattern for rule in DEFAULT_RULES if rule.default_enabled}
    expected = {
        "/var/cache/apt/**", "/var/lib/apt/**", "/var/lib/dpkg/**", "/snap/**",
        "/var/lib/snapd/snaps/**", "/var/lib/snapd/cache/**",
        "/var/lib/flatpak/app/**", "/var/lib/flatpak/runtime/**", "/var/lib/flatpak/repo/**",
        "**/.local/share/flatpak/app/**", "**/.local/share/flatpak/runtime/**", "**/.local/share/flatpak/repo/**",
    }
    assert expected <= patterns
    assert not matches_resticish("/home/user/snap/firefox/common/profile", "/snap/**")
    assert not any(matches_resticish("/home/user/.var/app/org.example.App/data/file", pattern) for pattern in patterns)


def test_command_as_uid_uses_fixed_root_owned_setpriv_argv(monkeypatch):
    from types import SimpleNamespace
    from ubackup.privileged import runtime

    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runtime.os, "lstat", lambda path: SimpleNamespace(st_mode=0o100755, st_uid=0))
    import pwd
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_gid=1000))
    assert runtime.command_as_uid(["flatpak", "--user", "list"], 1000) == [
        "/usr/bin/setpriv", "--reuid=1000", "--regid=1000", "--init-groups", "--",
        "flatpak", "--user", "list",
    ]


def test_command_as_uid_rejects_untrusted_setpriv(monkeypatch):
    from types import SimpleNamespace
    from ubackup.privileged import runtime

    monkeypatch.setattr(runtime.os, "geteuid", lambda: 0)
    monkeypatch.setattr(runtime.os, "lstat", lambda path: SimpleNamespace(st_mode=0o100777, st_uid=0))
    import pytest
    with pytest.raises(RuntimeError):
        runtime.command_as_uid(["flatpak", "list"], 1000)
