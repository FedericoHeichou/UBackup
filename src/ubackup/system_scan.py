from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import pwd
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Callable

from .cache import CacheDB
from .models import ConfigRecord, DependencyStatus, PackageManager, PackageRecord
from .privileged.runtime import command_as_uid, run_cancellable_subprocess


PSEUDO_FILESYSTEM_TYPES = frozenset({
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "pstore",
    "securityfs", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs",
    "autofs", "rpc_pipefs", "binfmt_misc", "squashfs", "ramfs", "nsfs", "overlay",
    "fuse.portal", "bpf", "fuse.lxcfs", "lxcfs", "fuse.gvfsd-fuse", "fuse.gvfs-fuse-daemon",
})

NON_STORAGE_MOUNT_PATTERNS = (
    "/sys/fs/bpf",
    "/var/lib/lxcfs",
    "/run/user/*/gvfs",
    "/run/user/*/doc",
    "/var/snap/*/common/host-hunspell",
)


def _non_storage_mount(path: str) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in NON_STORAGE_MOUNT_PATTERNS)


def real_mounted_filesystems(mounts_text: str | None = None) -> list[dict]:
    """Return one capacity row per real backing device.

    The dashboard is about storage capacity, not namespace plumbing.  Pseudo
    filesystems, desktop portal/GVFS mounts and duplicate bind mounts are
    therefore suppressed.  Distinct partitions/network mounts still have a
    distinct ``st_dev`` and remain visible.
    """
    if mounts_text is None:
        try:
            mounts_text = Path("/proc/self/mounts").read_text(errors="replace")
        except OSError:
            mounts_text = ""
    candidates: list[tuple[str, str]] = []
    for line in mounts_text.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] in PSEUDO_FILESYSTEM_TYPES:
            continue
        mount = parts[1].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
        if _non_storage_mount(mount):
            continue
        candidates.append((mount, parts[2]))

    # Prefer canonical/shallower mount points when the same backing device is
    # exposed again through a bind mount. This prevents a bind alias from
    # occupying the device slot merely because it happened to appear first in
    # /proc/self/mounts.
    candidates.sort(key=lambda value: (value[0].count("/"), len(value[0]), value[0]))
    found: list[dict] = []
    seen_devices: set[int] = set()
    for mount, fstype in candidates:
        try:
            info = os.stat(mount)
            if info.st_dev in seen_devices:
                continue
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        seen_devices.add(info.st_dev)
        found.append({
            "mount": mount,
            "fstype": fstype,
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
        })
    return found


def _run(
    cmd: list[str],
    env: dict[str, str],
    timeout: int = 120,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    return run_cancellable_subprocess(cmd, env, timeout=timeout, checkpoint=checkpoint)


def _desktop_user_env(env: dict[str, str], uid: int) -> dict[str, str]:
    """Return the minimal real-user environment needed by per-user package stores."""
    account = pwd.getpwuid(uid)
    value = dict(env)
    value.update({
        "HOME": account.pw_dir,
        "USER": account.pw_name,
        "LOGNAME": account.pw_name,
        "XDG_DATA_HOME": str(Path(account.pw_dir) / ".local" / "share"),
        "XDG_CONFIG_HOME": str(Path(account.pw_dir) / ".config"),
        "XDG_CACHE_HOME": str(Path(account.pw_dir) / ".cache"),
    })
    runtime = Path("/run/user") / str(uid)
    if runtime.is_dir():
        value["XDG_RUNTIME_DIR"] = str(runtime)
    else:
        value.pop("XDG_RUNTIME_DIR", None)
    return value


def _version(command: str, env: dict[str, str]) -> str:
    p = _run([command, "--version"], env, timeout=10)
    text = (p.stdout or p.stderr).strip().splitlines()
    res = text[0] if text else ""
    if '--version' in res:
        p = _run([command, "version"], env, timeout=10)
        text = (p.stdout or p.stderr).strip().splitlines()
        res = text[0] if text else ""
    return res




def _dpkg_package_version(package: str) -> str:
    """Return an installed Debian package version without consulting user PATH."""
    try:
        completed = subprocess.run(
            ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=5, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""

def dependency_status(env: dict[str, str]) -> list[DependencyStatus]:
    specs = [
        ("Restic", "restic", "restic", True, "sudo apt install restic"),
        ("debsums", "debsums", "debsums", True, "sudo apt install debsums"),
        ("APT manual marks", "apt-mark", "apt", True, "provided by apt"),
        ("dpkg-query", "dpkg-query", "dpkg", True, "provided by dpkg"),
        ("apt-get", "apt-get", "apt", True, "provided by apt"),
        ("Snap inventory", "snap", "snapd", False, "sudo apt install snapd"),
        ("Flatpak inventory", "flatpak", "flatpak", False, "sudo apt install flatpak"),
        ("apt-clone compatibility export", "apt-clone", "apt-clone", False, "sudo apt install apt-clone"),
    ]
    result = []
    for name, cmd, package, required, hint in specs:
        path = shutil.which(cmd)
        version = (_version(cmd, env) or _dpkg_package_version(package)) if path else ""
        result.append(DependencyStatus(name, cmd, required, bool(path), version, hint))
    return result


def package_cache_key() -> str:
    h = hashlib.sha256()
    for p in (Path("/var/lib/dpkg/status"), Path("/var/lib/apt/extended_states")):
        try:
            st = p.stat()
            h.update(f"{p}:{st.st_mtime_ns}:{st.st_size}".encode())
        except OSError:
            h.update(f"{p}:missing".encode())
    return h.hexdigest()


def discover_manual_packages(env: dict[str, str]) -> list[dict]:
    """Read package inventory without CacheDB or user-selection policy."""
    def plain(record: PackageRecord) -> dict:
        value = record.to_dict()
        value.pop("selected", None)
        return value

    manual = set(_run(["apt-mark", "showmanual"], env).stdout.split())
    p = _run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"], env)
    records: list[dict] = []
    seen = set()
    for line in p.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        name, version, arch, status = parts
        base = name.split(":", 1)[0]
        if base not in manual and name not in manual:
            continue
        if base in seen:
            continue
        seen.add(base)
        records.append(plain(PackageRecord(base, version, arch, status == "installed", True, manager=PackageManager.APT)))
    # Preserve manual marks that no longer have an installed dpkg record, if any.
    for name in sorted(manual):
        base = name.split(":", 1)[0]
        if base in seen:
            continue
        seen.add(base)
        records.append(plain(PackageRecord(base, "", "", False, True, manager=PackageManager.APT)))
    records.sort(key=lambda x: x["name"])
    return records


def discover_snap_packages(env: dict[str, str]) -> list[dict]:
    """Return installed Snap applications as package-plan records."""
    if not shutil.which("snap", path=env.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")):
        return []
    try:
        result = _run(["snap", "list", "--color=never", "--unicode=never"], env, timeout=120)
    except Exception:
        return []
    records: list[dict] = []
    for index, line in enumerate(result.stdout.splitlines()):
        if index == 0 or not line.strip():
            continue
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        name, version, _revision, tracking, publisher = parts[:5]
        notes = parts[5] if len(parts) > 5 else ""
        record = PackageRecord(
            name=name, version=version, architecture="", installed=True, manual=True,
            origin=publisher, manager=PackageManager.SNAP, scope="system",
            channel=tracking, classic="classic" in {part.strip() for part in notes.split(",")},
        )
        records.append(record.to_dict())
    return records


def discover_flatpak_packages(env: dict[str, str], uid: int) -> list[dict]:
    """Return installed Flatpak apps plus the remote URL needed to rebuild them."""
    if not shutil.which("flatpak", path=env.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")):
        return []
    user_env = _desktop_user_env(env, uid)

    # Keep remote metadata with the package inventory. A fresh system may not
    # have the same Flatpak remotes configured, and excluding the Flatpak
    # OSTree repository from the filesystem backup would otherwise make a
    # restore depend on unversioned local state.
    remote_urls: dict[tuple[str, str], str] = {}
    try:
        remotes = _run(
            command_as_uid(["flatpak", "remotes", "--columns=name,url,installation"], uid),
            user_env, timeout=120,
        )
        for line in remotes.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            name, url, installation = (value.strip() for value in parts[:3])
            if name.lower() == "name":
                continue
            scope = installation or "system"
            if scope.lower() in {"system", "user"}:
                scope = scope.lower()
            remote_urls[(scope, name)] = url
    except Exception:
        # Package enumeration remains useful even if a particular Flatpak
        # version cannot expose remote URLs; restore will then require the
        # remote to already exist.
        remote_urls = {}

    try:
        result = _run(
            command_as_uid(["flatpak", "list", "--app", "--columns=application,version,arch,branch,origin,installation,ref"], uid),
            user_env, timeout=180,
        )
    except Exception:
        return []
    records: list[dict] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        app_id, version, arch, branch, origin, installation, reference = (value.strip() for value in parts[:7])
        if app_id.lower() in {"application", "app"}:
            continue
        scope = installation or "system"
        if scope.lower() in {"system", "user"}:
            scope = scope.lower()
        records.append(PackageRecord(
            name=app_id, version=version, architecture=arch,
            installed=True, manual=True, origin=origin, manager=PackageManager.FLATPAK,
            scope=scope, channel=branch, reference=reference,
            origin_url=remote_urls.get((scope, origin), ""),
        ).to_dict())
    return records


def package_inventory_cache_key(uid: int) -> str:
    h = hashlib.sha256()
    paths = [
        Path("/var/lib/dpkg/status"), Path("/var/lib/apt/extended_states"),
        Path("/var/lib/snapd/state.json"), Path("/var/lib/flatpak/app"),
        Path("/var/lib/flatpak/runtime"), Path("/var/lib/flatpak/repo/config"),
        Path("/etc/flatpak/installations.d"),
    ]
    try:
        home = Path(pwd.getpwuid(uid).pw_dir)
        paths.extend([
            home / ".local/share/flatpak/app", home / ".local/share/flatpak/runtime",
            home / ".local/share/flatpak/repo/config",
        ])
    except KeyError:
        pass
    for path in paths:
        try:
            st = path.stat()
            h.update(f"{path}:{st.st_mtime_ns}:{st.st_size}".encode())
        except OSError:
            h.update(f"{path}:missing".encode())
    h.update(f"uid:{uid}".encode())
    return h.hexdigest()


def discover_package_inventory(env: dict[str, str], uid: int) -> list[dict]:
    records = discover_manual_packages(env)
    records.extend(discover_snap_packages(env))
    records.extend(discover_flatpak_packages(env, uid))
    records.sort(key=lambda item: (str(item.get("manager", "apt")), str(item.get("name", "")), str(item.get("scope", ""))))
    return records


def cached_package_inventory(
    cache: CacheDB, env: dict[str, str], uid: int, force: bool = False
) -> list[dict]:
    key = package_inventory_cache_key(uid)
    if not force:
        cached = cache.load_cached_records("package_inventory_cache", key)
        if cached is not None:
            for value in cached:
                value.pop("cache_id", None)
            return cached
    records = discover_package_inventory(env, uid)
    cache_records = []
    for record in records:
        value = dict(record)
        value["cache_id"] = f"{value.get('manager', 'apt')}|{value.get('scope', 'system')}|{value.get('name', '')}"
        cache_records.append(value)
    cache.replace_cached_records("package_inventory_cache", "cache_id", cache_records, key)
    for value in cache_records:
        value.pop("cache_id", None)
    return cache_records


def cached_manual_package_inventory(
    cache: CacheDB, env: dict[str, str], force: bool = False
) -> list[dict]:
    """Cache raw package discovery separately from per-user selection policy."""
    key = package_cache_key()
    if not force:
        cached = cache.load_cached_records("packages_cache", key)
        if cached is not None:
            return cached
    records = discover_manual_packages(env)
    cache.replace_cached_records("packages_cache", "name", records, key)
    return records


def scan_manual_packages(cache: CacheDB, env: dict[str, str], force: bool = False) -> list[PackageRecord]:
    records = [PackageRecord(**r) for r in cached_manual_package_inventory(cache, env, force)]
    # Selection is user state and can change independently of expensive
    # discovery. Never resurrect a stale checkbox value from cached payload.
    for record in records:
        record.selected = cache.get_selected("package", record.name, record.selected)
    return records


def _managed_etc_paths(
    *, checkpoint: Callable[[], None] | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[set[str], dict[str, str]]:
    checkpoint = checkpoint or (lambda: None)
    progress = progress or (lambda _x: None)
    managed: set[str] = set()
    owner: dict[str, str] = {}
    info = Path("/var/lib/dpkg/info")
    for index, list_file in enumerate(info.glob("*.list")):
        checkpoint()
        if index % 64 == 0:
            progress(str(list_file))
        package = list_file.name[:-5].split(":", 1)[0]
        try:
            for line in list_file.read_text(errors="surrogateescape").splitlines():
                if len(managed) % 256 == 0:
                    checkpoint()
                if line == "/etc" or line.startswith("/etc/"):
                    managed.add(line)
                    owner.setdefault(line, package)
        except (OSError, UnicodeError):
            continue
    return managed, owner


def config_cache_key(ttl_bucket_seconds: int = 21600) -> str:
    """Avoid a full /etc walk more than once per bucket unless forced."""
    status = Path("/var/lib/dpkg/status")
    try:
        st = status.stat()
        base = f"{st.st_mtime_ns}:{st.st_size}"
    except OSError:
        base = "missing"
    bucket = int(time.time() // ttl_bucket_seconds)
    return hashlib.sha256(f"{base}:{bucket}".encode()).hexdigest()


def discover_configs(
    env: dict[str, str],
    progress: Callable[[str], None] | None = None,
    *,
    checkpoint: Callable[[], None] | None = None,
    cancel: Callable[[], None] | None = None,
) -> list[dict]:
    """Discover config candidates without CacheDB or checkbox policy."""
    progress = progress or (lambda _x: None)
    checkpoint = checkpoint or cancel or (lambda: None)
    checkpoint()
    progress("Checking modified configurations with debsums…")
    changed_run = _run(["debsums", "-ce"], env, timeout=600, checkpoint=checkpoint)
    modified = {line.strip() for line in changed_run.stdout.splitlines() if line.strip().startswith("/etc/")}

    checkpoint()
    progress("Indexing /etc files managed by dpkg…")
    managed, owner = _managed_etc_paths(checkpoint=checkpoint, progress=progress)
    records: dict[str, ConfigRecord] = {}
    for path in sorted(modified):
        try:
            st = os.lstat(path)
            size = st.st_size
            mtime = st.st_mtime_ns
        except OSError:
            size = mtime = 0
        records[path] = ConfigRecord(path, "modified-conffile", owner.get(path, ""), True, size, mtime)

    progress("Searching for /etc files not owned by packages…")
    last_progress = 0.0
    for root, dirs, files in os.walk("/etc", topdown=True, followlinks=False):
        checkpoint()
        now = time.monotonic()
        if now - last_progress >= 0.25:
            progress(root)
            last_progress = now
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
        for name in files:
            if len(records) % 128 == 0:
                checkpoint()
            path = os.path.join(root, name)
            if path in managed or path in records:
                continue
            try:
                st = os.lstat(path)
            except OSError:
                continue
            records[path] = ConfigRecord(path, "unmanaged", "", True, st.st_size, st.st_mtime_ns)

    out = sorted(records.values(), key=lambda x: (x.kind, x.path))
    return [{key: value for key, value in record.to_dict().items() if key != "selected"} for record in out]


def cached_config_inventory(
    cache: CacheDB, env: dict[str, str], force: bool = False,
    progress: Callable[[str], None] | None = None,
    *, checkpoint: Callable[[], None] | None = None,
) -> list[dict]:
    """Cache raw /etc discovery without mixing it with GUI selection policy."""
    key = config_cache_key()
    if not force:
        cached = cache.load_cached_records("configs_cache", key)
        if cached is not None:
            if progress is not None:
                progress("Using cached /etc inventory…")
            return cached
    records = discover_configs(env, progress, checkpoint=checkpoint)
    cache.replace_cached_records("configs_cache", "path", records, key)
    return records


def scan_configs(cache: CacheDB, env: dict[str, str], force: bool = False,
                 progress: Callable[[str], None] | None = None) -> list[ConfigRecord]:
    out = [ConfigRecord(**record) for record in cached_config_inventory(cache, env, force, progress)]
    # Cached discovery and current user policy are intentionally separate.
    for record in out:
        record.selected = cache.get_selected("config", record.path, record.selected)
    return out


def collect_system_inventory(env: dict[str, str]) -> dict:
    def output(cmd):
        try:
            return _run(cmd, env, timeout=60).stdout.strip()
        except Exception:
            return ""

    return {
        "hostname": socket.gethostname(),
        "os_release": Path("/etc/os-release").read_text(errors="replace") if Path("/etc/os-release").exists() else "",
        "kernel": output(["uname", "-a"]),
        "apt_manual": output(["apt-mark", "showmanual"]).splitlines(),
        "dpkg_packages": output(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"]).splitlines(),
        "snap": output(["snap", "list"]) if shutil.which("snap") else "",
        "flatpak": output(["flatpak", "list", "--app", "--columns=application,branch,origin"]) if shutil.which("flatpak") else "",
    }


def export_apt_clone(destination: Path, env: dict[str, str]) -> tuple[bool, str]:
    if not shutil.which("apt-clone"):
        return False, "apt-clone is not installed"
    destination.parent.mkdir(parents=True, exist_ok=True)
    p = _run(["apt-clone", "clone", str(destination)], env, timeout=600)
    return p.returncode == 0, (p.stdout + "\n" + p.stderr).strip()
