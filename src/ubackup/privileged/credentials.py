from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path
from typing import Iterator, Mapping

from ..paths import PrivilegedPaths
from ..restic_engine import ResticEngine
from .runtime import Phase2Error


MAX_EXTERNAL_PASSWORD_BYTES = 4096


def _safe_ancestor(info: os.stat_result, owner: int, caller_uid: int) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
        raise Phase2Error("invalid_credentials", "external password file ancestry is unsafe")
    if info.st_uid not in ({0} if owner == 0 else {0, caller_uid}):
        raise Phase2Error("invalid_credentials", "external password file ancestry has unsafe ownership")


def _open_external_password_file(path: Path, caller_uid: int) -> tuple[int, os.stat_result]:
    """Open and pin a credential file without resolving caller-controlled paths."""
    if not path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise Phase2Error("invalid_credentials", "external password file path is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    path_flags = getattr(os, "O_PATH", os.O_RDONLY)
    parent_fd = os.open(os.sep, path_flags | os.O_DIRECTORY | nofollow | cloexec)
    try:
        root_info = os.fstat(parent_fd)
        components = path.parts[1:]
        if not components:
            raise Phase2Error("invalid_credentials", "external password file is not regular")
        current_fd = parent_fd
        opened_parents: list[int] = []
        parent_infos: list[os.stat_result] = [root_info]
        try:
            for component in components[:-1]:
                next_fd = os.open(
                    component,
                    path_flags | os.O_DIRECTORY | nofollow | cloexec,
                    dir_fd=current_fd,
                )
                opened_parents.append(next_fd)
                parent_infos.append(os.fstat(next_fd))
                current_fd = next_fd
            final_fd = os.open(
                components[-1],
                os.O_RDONLY | nofollow | cloexec,
                dir_fd=current_fd,
            )
        finally:
            for descriptor in reversed(opened_parents):
                os.close(descriptor)
        final_info = os.fstat(final_fd)
        owner = final_info.st_uid
        try:
            if owner not in {0, caller_uid}:
                raise Phase2Error("invalid_credentials", "external password file ownership is unsafe")
            if not stat.S_ISREG(final_info.st_mode) or stat.S_IMODE(final_info.st_mode) & 0o077:
                raise Phase2Error("invalid_credentials", "external password file mode is unsafe")
            # Root-owned credentials must have an entirely root-owned ancestry.
            for parent_info in parent_infos:
                _safe_ancestor(parent_info, owner, caller_uid)
            return final_fd, final_info
        except BaseException:
            os.close(final_fd)
            raise
    except OSError as exc:
        raise Phase2Error("invalid_credentials", "external password file is not accessible") from exc
    finally:
        os.close(parent_fd)


def _copy_external_password(path: Path, secret: Path, caller_uid: int) -> None:
    fd, pinned = _open_external_password_file(path, caller_uid)
    try:
        if pinned.st_size <= 0 or pinned.st_size > MAX_EXTERNAL_PASSWORD_BYTES:
            raise Phase2Error("invalid_credentials", "external password file is too large")
        chunks: list[bytes] = []
        remaining = MAX_EXTERNAL_PASSWORD_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        current = os.fstat(fd)
        if (current.st_dev, current.st_ino, current.st_uid, current.st_mode, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
            pinned.st_dev, pinned.st_ino, pinned.st_uid, pinned.st_mode, pinned.st_size, pinned.st_mtime_ns, pinned.st_ctime_ns
        ):
            raise Phase2Error("invalid_credentials", "external password file changed during read")
        if len(content) > MAX_EXTERNAL_PASSWORD_BYTES or not content or b"\x00" in content or b"\r" in content:
            raise Phase2Error("invalid_credentials", "external password material is invalid")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        cloexec = getattr(os, "O_CLOEXEC", 0)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | cloexec
        secret_fd = os.open(secret, flags, 0o600)
        try:
            view = memoryview(content)
            while view:
                written = os.write(secret_fd, view)
                view = view[written:]
            os.fsync(secret_fd)
        finally:
            os.close(secret_fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def credentialed_engine(
    paths: PrivilegedPaths,
    environment: Mapping[str, str],
    request_id: str,
    credentials: Mapping[str, str | None],
    caller_uid: int,
    *,
    request_dir: Path | None = None,
) -> Iterator[ResticEngine]:
    """Create a request-private Restic password channel and clean it up."""
    directory = request_dir or (paths.plans / request_id)
    created_directory = False
    secret = directory / "restic-password"
    engine: ResticEngine | None = None
    session_secret_created = False
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        directory.mkdir(mode=0o700, parents=False)
        info = os.lstat(directory)
        created_directory = True
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Phase2Error("invalid_credentials", "request credential directory is unsafe")
    try:
        if secret.exists() or secret.is_symlink():
            raise Phase2Error("invalid_credentials", "request credential channel already exists")
        engine = ResticEngine(paths, dict(environment))
        password = credentials.get("password")
        password_file = credentials.get("password_file")
        if password is not None:
            if "\n" in password or "\r" in password or "\x00" in password:
                raise Phase2Error("invalid_credentials", "password contains forbidden control characters")
            engine.password_file = secret
            engine.session_password = True
            session_secret_created = True
            engine.env["RESTIC_PASSWORD_FILE"] = str(secret)
            engine.set_password(password)
        elif password_file is not None:
            path = Path(password_file)
            engine.password_file = secret
            engine.session_password = True
            session_secret_created = True
            engine.env["RESTIC_PASSWORD_FILE"] = str(secret)
            _copy_external_password(path, secret, caller_uid)
        else:
            raise Phase2Error("invalid_credentials", "one password source is required")
        yield engine
    finally:
        if engine is not None and session_secret_created:
            engine.clear_session_password()
        try:
            if secret.exists() or secret.is_symlink():
                secret.unlink()
            if created_directory:
                directory.rmdir()
        except OSError:
            pass
