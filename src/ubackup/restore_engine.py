from __future__ import annotations

import subprocess
import pwd
from pathlib import Path
from typing import Callable

from .models import PackageManager, PackageRecord

from .restic_engine import ResticEngine, ResticError
from .privileged.runtime import ChildProcessError, command_as_uid, run_cancellable_subprocess


APT_TIMEOUT_SECONDS = 1650
MAX_APT_OUTPUT_BYTES = 64 * 1024


class PackageCommandError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class RestoreEngine:
    def __init__(self, restic: ResticEngine, env: dict[str, str], desktop_uid: int | None = None):
        self.restic = restic
        self.env = env
        self.desktop_uid = desktop_uid

    def metadata_json(self, snapshot_id: str, filename: str):
        path = self.restic.find_manifest_path(snapshot_id)
        if not path:
            raise ResticError("UBackup manifest was not found in the snapshot")
        base = path.rsplit("/", 1)[0]
        return self.restic.dump_json(snapshot_id, base + "/" + filename)

    def manifest(self, snapshot_id: str) -> dict:
        return self.metadata_json(snapshot_id, "manifest.json")

    def package_records(self, snapshot_id: str) -> list[dict]:
        records: list[dict] = []
        for manager in PackageManager:
            try:
                value = self.metadata_json(snapshot_id, f"packages-{manager.value}.json")
            except Exception:
                continue
            if isinstance(value, list):
                records.extend(item for item in value if isinstance(item, dict))
        if records:
            return records
        # Read-only compatibility with the former combined package inventory.
        try:
            legacy = self.metadata_json(snapshot_id, "packages.json")
        except Exception:
            return []
        return [item for item in legacy if isinstance(item, dict)] if isinstance(legacy, list) else []

    def restore_files(self, snapshot_id: str, paths: list[str], target: Path,
                      on_message: Callable[[dict], None] | None = None) -> None:
        self.restic.restore(snapshot_id, target, paths, on_message)

    def _package_user_env(self) -> dict[str, str]:
        if self.desktop_uid is None:
            raise PackageCommandError("missing_user", "desktop user is unavailable for per-user package restore")
        account = pwd.getpwuid(self.desktop_uid)
        env = dict(self.env)
        env.update({
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "XDG_DATA_HOME": str(Path(account.pw_dir) / ".local" / "share"),
            "XDG_CONFIG_HOME": str(Path(account.pw_dir) / ".config"),
            "XDG_CACHE_HOME": str(Path(account.pw_dir) / ".cache"),
        })
        runtime = Path("/run/user") / str(self.desktop_uid)
        if runtime.is_dir():
            env["XDG_RUNTIME_DIR"] = str(runtime)
        else:
            env.pop("XDG_RUNTIME_DIR", None)
        return env

    def _run_package_command(
        self, command: list[str], *, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = run_cancellable_subprocess(
                command, env or self.env, timeout=APT_TIMEOUT_SECONDS,
                output_limit=MAX_APT_OUTPUT_BYTES,
            )
        except ChildProcessError:
            raise
        except Exception as exc:
            raise PackageCommandError("package_command_failed", f"could not run {command[0]}") from exc
        if result.returncode != 0:
            raise PackageCommandError("package_command_failed", f"{command[0]} exited with status {result.returncode}")
        return result

    @staticmethod
    def _flatpak_scope_args(scope: str) -> list[str]:
        if scope == "user":
            return ["--user"]
        if scope in {"system", "default"}:
            return ["--system"]
        return [f"--installation={scope}"]

    def restore_packages(
        self, packages: list[PackageRecord], dry_run: bool = False,
        progress: Callable[[dict], None] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not packages:
            return subprocess.CompletedProcess([], 0, "", "")
        outputs: list[str] = []
        errors: list[str] = []
        processed = 0

        apt_names = [record.name for record in packages if record.manager is PackageManager.APT]
        if apt_names:
            cmd = ["apt-get", "install", "-y"]
            if dry_run:
                cmd.append("--simulate")
            cmd.append("--")
            cmd.extend(apt_names)
            result = self._run_package_command(cmd)
            outputs.append(result.stdout or "")
            errors.append(result.stderr or "")
            processed += len(apt_names)
            if progress is not None:
                progress({"current_item": "APT packages validated" if dry_run else "APT packages installed", "items_processed": processed})

        for record in packages:
            if record.manager is PackageManager.APT:
                continue
            if record.manager is PackageManager.SNAP:
                if dry_run:
                    cmd = ["snap", "info", record.name]
                else:
                    cmd = ["snap", "install"]
                    if record.channel and record.channel != "-":
                        cmd.extend(["--channel", record.channel])
                    if record.classic:
                        cmd.append("--classic")
                    cmd.append(record.name)
                result = self._run_package_command(cmd)
            elif record.manager is PackageManager.FLATPAK:
                if (
                    not record.origin or not record.origin[0].isalnum()
                    or any(not (char.isalnum() or char in "._-") for char in record.origin)
                ):
                    raise PackageCommandError("invalid_remote", f"invalid Flatpak remote for {record.name}")
                if record.reference and not record.reference.startswith("app/"):
                    raise PackageCommandError("invalid_reference", f"invalid Flatpak reference for {record.name}")
                if record.origin_url.startswith("-") or any(ord(char) < 0x20 for char in record.origin_url):
                    raise PackageCommandError("invalid_remote", f"invalid Flatpak remote URL for {record.name}")
                scope_args = self._flatpak_scope_args(record.scope)
                command_env = self._package_user_env() if record.scope == "user" else self.env
                def scoped(command: list[str]) -> list[str]:
                    if record.scope == "user":
                        if self.desktop_uid is None:
                            raise PackageCommandError("missing_user", "desktop user is unavailable for per-user Flatpak restore")
                        return command_as_uid(command, self.desktop_uid)
                    return command
                reference = record.reference or (f"{record.name}//{record.channel}" if record.channel else record.name)
                if not record.origin:
                    raise PackageCommandError("missing_remote", f"Flatpak remote is missing for {record.name}")
                if dry_run:
                    # Dry-run must remain non-mutating. If the original remote
                    # still exists, remote-info verifies the ref. If it is no
                    # longer configured but we recorded its URL, report the
                    # planned remote recreation without modifying Flatpak.
                    remotes = self._run_package_command(
                        scoped(["flatpak", *scope_args, "remotes", "--columns=name"]),
                        env=command_env,
                    )
                    configured = {line.strip() for line in (remotes.stdout or "").splitlines() if line.strip()}
                    if record.origin in configured:
                        result = self._run_package_command(
                            scoped(["flatpak", *scope_args, "remote-info", record.origin, reference]),
                            env=command_env,
                        )
                    elif record.origin_url:
                        result = subprocess.CompletedProcess(
                            ["flatpak", "remote-add"], 0,
                            f"Would add Flatpak remote {record.origin} from {record.origin_url} and install {reference}\n", "",
                        )
                    else:
                        raise PackageCommandError(
                            "missing_remote", f"Flatpak remote {record.origin} is not configured and its URL was not recorded"
                        )
                else:
                    if record.origin_url:
                        self._run_package_command(
                            scoped(["flatpak", *scope_args, "remote-add", "--if-not-exists", record.origin, record.origin_url]),
                            env=command_env,
                        )
                    cmd = ["flatpak", *scope_args, "install", "-y", record.origin, reference]
                    result = self._run_package_command(scoped(cmd), env=command_env)
            else:
                raise PackageCommandError("unsupported_manager", f"unsupported package manager: {record.manager}")
            outputs.append(result.stdout or "")
            errors.append(result.stderr or "")
            processed += 1
            if progress is not None:
                action = "Validated" if dry_run else "Installed"
                progress({"current_item": f"{action} {record.manager.value}: {record.name}", "items_processed": processed})

        return subprocess.CompletedProcess(
            ["ubackup-package-restore"], 0, "\n".join(text for text in outputs if text),
            "\n".join(text for text in errors if text),
        )
