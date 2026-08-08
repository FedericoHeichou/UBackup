from __future__ import annotations

import os
import shutil
import stat
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator


USER_UID_MIN = 1
RESERVED_UID_MAX = (1 << 32) - 1
MAX_USER_UID = RESERVED_UID_MAX - 1


def _absolute_root(backup_root: str | os.PathLike[str]) -> Path:
    """Return an absolute path without following a backup-root symlink.

    The privileged configure helper performs the authoritative ownership and
    symlink checks.  Path models deliberately do not create anything and do
    not silently turn a path supplied by another component into a different
    path by resolving symlinks.
    """
    value = os.fspath(backup_root)
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    return Path(os.path.abspath(os.path.expanduser(value)))


def is_contained(path: Path, parent: Path) -> bool:
    """Lexical/model containment only; unsuitable for privileged authorization.

    This helper intentionally does not inspect symlinks, ownership, device or
    inode identity.  Privileged filesystem decisions must use the helper's
    lstat-based admission and revalidation paths instead.
    """
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class GuiPaths:
    """Paths writable by one unprivileged GUI user.

    Every path in this model is below ``.ubackup/users/<uid>``.  Constructing
    this object is side-effect free; the root helper is responsible for
    provisioning the directory tree and assigning its ownership.
    """

    uid: int
    user_root: Path
    cache: Path
    state: Path
    runtime: Path
    sandbox_home: Path
    tmp: Path
    logs: Path
    xdg_cache: Path
    xdg_config: Path
    xdg_data: Path
    db: Path

    @classmethod
    def for_user(cls, backup_root: str | os.PathLike[str], uid: int) -> "GuiPaths":
        if isinstance(uid, bool) or not isinstance(uid, int) or not (USER_UID_MIN <= uid <= MAX_USER_UID):
            raise ValueError("uid must be a valid non-reserved user UID")
        root = _absolute_root(backup_root)
        internal = root / ".ubackup"
        users = internal / "users"
        user_root = users / str(uid)
        cache = user_root / "cache"
        state = user_root / "state"
        runtime = user_root / "runtime"
        return cls(
            uid=uid,
            user_root=user_root,
            cache=cache,
            state=state,
            runtime=runtime,
            sandbox_home=runtime / "home",
            tmp=runtime / "tmp",
            logs=user_root / "logs",
            xdg_cache=cache / "xdg",
            xdg_config=state / "xdg-config",
            xdg_data=state / "xdg-data",
            db=state / "cache.sqlite3",
        )

    # ``create`` is retained as a convenient, side-effect-free constructor;
    # callers must explicitly invoke the privileged provisioning operation.
    create = for_user

    @property
    def root(self) -> Path:
        """The backup root context (not a GUI-owned writable path)."""
        return self.user_root.parents[2]

    @property
    def internal(self) -> Path:
        """Root-owned parent used only by the configure helper."""
        return self.root / ".ubackup"

    @property
    def users(self) -> Path:
        """Root-owned execute-only parent used only by the configure helper."""
        return self.user_root.parent

    def directories(self) -> Iterator[Path]:
        """Directories the configure helper may provision for this user."""
        yield from (
            self.user_root,
            self.cache,
            self.state,
            self.runtime,
            self.logs,
            self.xdg_cache,
            self.xdg_config,
            self.xdg_data,
            self.sandbox_home,
            self.tmp,
        )

    def is_user_path(self, path: str | os.PathLike[str]) -> bool:
        """Model containment only; symlink/ownership checks remain required."""
        return is_contained(_absolute_root(path), self.user_root)

    def prepare_environment(self, base: dict[str, str] | None = None) -> dict[str, str]:
        """Return the GUI runtime environment with writable state below this user's leaf.

        The inherited ``XDG_RUNTIME_DIR`` is the exception: when available,
        retain the logged-in session's runtime directory so Qt can access its
        existing Wayland display socket.  Without one, use the private
        fallback runtime directory below the backup root.

        In particular this deliberately does not set any Restic repository or
        password variables.  Restic is executed by the privileged facade and
        receives credentials per request.
        """
        source = os.environ if base is None else base
        env = dict(source)
        for key in tuple(env):
            if key == "RESTIC_REPOSITORY" or key == "RESTIC_CACHE_DIR" or key.startswith("RESTIC_PASSWORD"):
                env.pop(key, None)
        env.update({
            "HOME": str(self.sandbox_home),
            "XDG_CACHE_HOME": str(self.xdg_cache),
            "XDG_CONFIG_HOME": str(self.xdg_config),
            "XDG_DATA_HOME": str(self.xdg_data),
            "TMPDIR": str(self.tmp),
            "TEMP": str(self.tmp),
            "TMP": str(self.tmp),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        # This is a display-session integration point, not application state:
        # preserve the user's existing runtime directory when one was
        # inherited, and only fall back to our private runtime directory when
        # the session did not provide one.
        if not env.get("XDG_RUNTIME_DIR"):
            env["XDG_RUNTIME_DIR"] = str(self.runtime)
        for directory in (self.sandbox_home, self.tmp, self.xdg_cache, self.xdg_config, self.xdg_data):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return env


@dataclass(frozen=True, slots=True)
class PrivilegedPaths:
    """Root-owned repository, plan, restore, and helper-runtime paths.

    This model intentionally contains no GUI-user cache or SQLite path.  It
    is also side-effect free: domain helpers decide explicitly which of these
    directories need to be created for an operation.
    """

    root: Path
    internal: Path
    repository: Path
    state: Path
    current: Path
    cache: Path
    runtime: Path
    sandbox_home: Path
    tmp: Path
    logs: Path
    secrets: Path
    restores: Path
    password_file: Path
    excludes_file: Path
    sources_file: Path
    manifest_file: Path
    packages_file: Path
    configs_file: Path
    system_file: Path
    plans: Path
    lock_file: Path

    @classmethod
    def for_root(cls, backup_root: str | os.PathLike[str]) -> "PrivilegedPaths":
        root = _absolute_root(backup_root)
        internal = root / ".ubackup"
        state = internal / "state"
        current = state / "filesystem" / "current"
        cache = internal / "cache"
        runtime = internal / "runtime"
        return cls(
            root=root,
            internal=internal,
            repository=root / "repositories" / "filesystem",
            state=state,
            current=current,
            cache=cache,
            runtime=runtime,
            sandbox_home=runtime / "home",
            tmp=runtime / "tmp",
            logs=internal / "logs",
            secrets=internal / "secrets",
            restores=root / "restores",
            password_file=runtime / "restic-password.session",
            excludes_file=current / "restic-excludes.txt",
            sources_file=current / "restic-sources.txt",
            manifest_file=current / "manifest.json",
            packages_file=current / "packages.json",
            configs_file=current / "configs.json",
            system_file=current / "system.json",
            plans=internal / "plans",
            lock_file=internal / "backup.lock",
        )

    def for_component(self, component: str) -> "PrivilegedPaths":
        """Return domain-specific Restic/state paths for one backup component.

        UBackup deliberately uses independent repositories for filesystem, /etc
        configuration and package metadata.  The password/runtime/cache remain
        session-global, while repository and versioned metadata paths are scoped
        to the selected domain.
        """
        if component not in {"filesystem", "configs", "packages"}:
            raise ValueError("invalid backup component")
        current = self.state / component / "current"
        return replace(
            self,
            repository=self.root / "repositories" / component,
            current=current,
            excludes_file=current / "restic-excludes.txt",
            sources_file=current / "restic-sources.txt",
            manifest_file=current / "manifest.json",
            packages_file=current / "packages.json",
            configs_file=current / "configs.json",
            system_file=current / "system.json",
            lock_file=self.internal / f"backup-{component}.lock",
        )

    from_backup_root = for_root
    for_backup_root = for_root
    create = for_root

    def is_privileged_path(self, path: str | os.PathLike[str]) -> bool:
        """Model containment only; never use as restore authorization."""
        candidate = _absolute_root(path)
        user_area = self.internal / "users"
        return is_contained(candidate, self.root) and not is_contained(candidate, user_area)

    def cleanup_stale_request_artifacts(
        self,
        *,
        active_request_id: str | None = None,
        now: float | None = None,
        max_age_seconds: float = 24 * 60 * 60,
    ) -> list[Path]:
        """Remove only old, root-private UUID plan directories after a crash.

        This is deliberately not used for normal request cleanup.  A fresh
        request owns and removes its own directory in its context manager.
        """
        current_time = time.time() if now is None else now
        removed: list[Path] = []
        try:
            plans_info = os.lstat(self.plans)
            if (
                stat.S_ISLNK(plans_info.st_mode)
                or not stat.S_ISDIR(plans_info.st_mode)
                or plans_info.st_uid != 0
                or stat.S_IMODE(plans_info.st_mode) != 0o700
            ):
                return removed
            entries = tuple(self.plans.iterdir())
        except OSError:
            return removed
        for entry in entries:
            if active_request_id is not None and entry.name == active_request_id:
                continue
            try:
                parsed = uuid.UUID(entry.name)
                info = os.lstat(entry)
            except (OSError, ValueError):
                continue
            if (
                parsed.int == 0
                or str(parsed) != entry.name
                or not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_dev != plans_info.st_dev
                or current_time - info.st_mtime <= max_age_seconds
            ):
                continue
            try:
                shutil.rmtree(entry)
            except OSError:
                continue
            removed.append(entry)
        return removed

    def prepare_environment(self, base: dict[str, str] | None = None) -> dict[str, str]:
        """Prepare root-owned helper runtime paths under the privileged root.

        This is intentionally separate from :class:`AppPaths`: privileged
        helpers never inherit the GUI user's writable cache, XDG, or temporary
        directories.  The backup-root admission check must run before calling
        this mutating method.
        """
        directories = (
            (self.internal, 0o711),
            (self.root / "repositories", 0o700),
            (self.state, 0o700),
            (self.current.parent, 0o700),
            (self.current, 0o700),
            (self.cache, 0o700),
            (self.runtime, 0o700),
            (self.sandbox_home, 0o700),
            (self.tmp, 0o700),
            (self.logs, 0o700),
            (self.secrets, 0o700),
            (self.restores, 0o700),
            (self.cache / "xdg", 0o700),
            (self.internal / "xdg-config", 0o700),
            (self.internal / "xdg-data", 0o700),
            (self.cache / "restic", 0o700),
            (self.plans, 0o700),
        )
        old_umask = os.umask(0o077)
        try:
            try:
                repository_info = os.lstat(self.repository)
            except FileNotFoundError:
                repository_info = None
            if repository_info is not None and (
                stat.S_ISLNK(repository_info.st_mode)
                or not stat.S_ISDIR(repository_info.st_mode)
                or repository_info.st_uid != 0
                or repository_info.st_mode & 0o022
            ):
                raise OSError("privileged repository path is not root-private")
            for directory, required_mode in directories:
                try:
                    info = os.lstat(directory)
                except FileNotFoundError:
                    directory.mkdir(mode=required_mode)
                    info = os.lstat(directory)
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    raise OSError(f"privileged runtime path is not a directory: {directory}")
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise OSError(f"privileged runtime path is not root-private: {directory}")
                if stat.S_IMODE(info.st_mode) != required_mode:
                    os.chmod(directory, required_mode, follow_symlinks=False)
        finally:
            os.umask(old_umask)

        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
        source = os.environ if base is None else base
        for key in ("LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LANGUAGE"):
            value = source.get(key)
            if isinstance(value, str) and value:
                env[key] = value
        env.update(
            {
                "HOME": str(self.sandbox_home),
                "XDG_CACHE_HOME": str(self.cache / "xdg"),
                "XDG_CONFIG_HOME": str(self.internal / "xdg-config"),
                "XDG_DATA_HOME": str(self.internal / "xdg-data"),
                "TMPDIR": str(self.tmp),
                "TEMP": str(self.tmp),
                "TMP": str(self.tmp),
                "RESTIC_CACHE_DIR": str(self.cache / "restic"),
                "RESTIC_REPOSITORY": str(self.repository),
                "RESTIC_PASSWORD_FILE": str(self.password_file),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        return env


@dataclass(frozen=True, slots=True)
class AppPaths:
    root: Path
    internal: Path
    repository: Path
    state: Path
    current: Path
    cache: Path
    runtime: Path
    sandbox_home: Path
    tmp: Path
    logs: Path
    secrets: Path
    restores: Path
    db: Path
    password_file: Path
    excludes_file: Path
    sources_file: Path
    manifest_file: Path
    packages_file: Path
    configs_file: Path
    system_file: Path

    @classmethod
    def create(cls, backup_root: str | os.PathLike[str]) -> "AppPaths":
        root = Path(backup_root).expanduser().resolve()
        internal = root / ".ubackup"
        state = internal / "state"
        current = state / "filesystem" / "current"
        cache = internal / "cache"
        runtime = internal / "runtime"
        paths = cls(
            root=root,
            internal=internal,
            repository=root / "repositories" / "filesystem",
            state=state,
            current=current,
            cache=cache,
            runtime=runtime,
            sandbox_home=runtime / "home",
            tmp=runtime / "tmp",
            logs=internal / "logs",
            secrets=internal / "secrets",
            restores=root / "restores",
            db=state / "cache.sqlite3",
            password_file=runtime / "restic-password.session",
            excludes_file=current / "restic-excludes.txt",
            sources_file=current / "restic-sources.txt",
            manifest_file=current / "manifest.json",
            packages_file=current / "packages.json",
            configs_file=current / "configs.json",
            system_file=current / "system.json",
        )
        old_umask = os.umask(0o077)
        try:
            for p in (
                paths.root, paths.internal, paths.root / "repositories", paths.state, paths.current.parent, paths.current, paths.cache,
                paths.runtime, paths.sandbox_home, paths.tmp, paths.logs, paths.secrets, paths.restores,
            ):
                p.mkdir(parents=True, exist_ok=True, mode=0o700)
        finally:
            os.umask(old_umask)
        return paths

    def for_component(self, component: str) -> "AppPaths":
        if component not in {"filesystem", "configs", "packages"}:
            raise ValueError("invalid backup component")
        current = self.state / component / "current"
        return replace(
            self,
            repository=self.root / "repositories" / component,
            current=current,
            excludes_file=current / "restic-excludes.txt",
            sources_file=current / "restic-sources.txt",
            manifest_file=current / "manifest.json",
            packages_file=current / "packages.json",
            configs_file=current / "configs.json",
            system_file=current / "system.json",
        )

    def prepare_environment(self) -> dict[str, str]:
        """Route caches/temp generated by this process and children into backup root."""
        env = os.environ.copy()
        env.update({
            "HOME": str(self.sandbox_home),
            "XDG_CACHE_HOME": str(self.cache / "xdg"),
            "XDG_CONFIG_HOME": str(self.internal / "xdg-config"),
            "XDG_DATA_HOME": str(self.internal / "xdg-data"),
            "TMPDIR": str(self.tmp),
            "TEMP": str(self.tmp),
            "TMP": str(self.tmp),
            "RESTIC_CACHE_DIR": str(self.cache / "restic"),
            "RESTIC_REPOSITORY": str(self.repository),
            "RESTIC_PASSWORD_FILE": str(self.password_file),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        for key in ("XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "RESTIC_CACHE_DIR"):
            Path(env[key]).mkdir(parents=True, exist_ok=True, mode=0o700)
        return env
