from __future__ import annotations

"""Small, non-Qt facade for the fixed privileged broker operations."""

from dataclasses import dataclass
import os
import shutil
import subprocess
from typing import Any, Callable

from ..privilege_broker import Phase2Result, PrivilegeBroker, StartupSession
from ..privileged.protocol import (
    INSPECT_OPERATION, BACKUP_OPERATION, RESTORE_STAGING_OPERATION,
    RESTORE_INPLACE_OPERATION, PACKAGES_INSTALL_OPERATION, MAINTENANCE_OPERATION,
)
from ..models import DependencyStatus


@dataclass(frozen=True, slots=True)
class CredentialDescriptor:
    """Credential input used to bootstrap the authenticated helper session.

    In the production GUI the secret is sent once during startup; later RPCs
    reuse the bound helper-side credential and do not carry it again.
    """

    password: str | None = None
    password_file: str | None = None

    def payload(self) -> dict[str, str | None]:
        return {"password": self.password, "password_file": self.password_file}


class PrivilegedClient:
    def __init__(
        self, broker: PrivilegeBroker, backup_root: str, session: StartupSession | None = None,
        *, allow_broker_fallback: bool = True,
    ):
        self._broker = broker
        self._backup_root = backup_root
        self._session = session
        # Standalone helper invocations remain useful to tests/maintenance, but
        # the production GUI deliberately disables them.  Once UBackup has
        # authenticated its persistent startup helper, a lost/unavailable
        # session must surface as an error rather than silently invoking a new
        # pkexec flow and asking for authentication again.
        self._allow_broker_fallback = bool(allow_broker_fallback)

    def set_broker_fallback_enabled(self, enabled: bool) -> None:
        self._allow_broker_fallback = bool(enabled)

    def _require_broker_fallback(self) -> None:
        if not self._allow_broker_fallback:
            raise RuntimeError(
                "The privileged startup session is unavailable; restart UBackup to authenticate again."
            )

    @property
    def uses_persistent_session(self) -> bool:
        return self._session is not None

    def attach_session(self, session: StartupSession) -> None:
        if self._session is not None and self._session is not session:
            raise RuntimeError("a privileged session is already attached")
        self._session = session

    def _session_request(
        self, operation: str, payload: dict[str, Any], *, timeout: float = 3600.0,
        progress_cb: Callable[[dict[str, Any]], None] | None = None,
    ):
        if self._session is None:
            return None
        if progress_cb is None:
            # Keep the facade compatible with simple/fake StartupSession
            # implementations used by tests and downstream integrations.
            return self._session.request(operation, payload, timeout=timeout)
        return self._session.request(operation, payload, timeout=timeout, progress_cb=progress_cb)

    @staticmethod
    def _credentials(credentials: CredentialDescriptor | None) -> dict[str, str | None]:
        return (credentials or CredentialDescriptor()).payload()

    @staticmethod
    def _value(response: Any) -> Any:
        """Accept the typed broker result while keeping test/fake brokers simple."""
        return response.result if isinstance(response, Phase2Result) else response

    @staticmethod
    def _command_version(path: str) -> str:
        """Read a dependency version without privilege escalation.

        Dependency discovery is a GUI-side operation.  Keep it unprivileged
        and bounded, and never invoke a shell.  Some tools expose ``version``
        instead of ``--version`` so a small fixed fallback is permitted.
        """
        env = {"PATH": "/usr/bin:/bin"}
        for key in ("LANG", "LC_ALL"):
            value = os.environ.get(key)
            if value:
                env[key] = value
        for argv in ([path, "--version"], [path, "version"]):
            try:
                completed = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5,
                    check=False,
                    env=env,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if completed.returncode != 0:
                continue
            lines = (completed.stdout or completed.stderr or "").strip().splitlines()
            if lines:
                return lines[0].strip()
        return ""

    @staticmethod
    def _package_version(package: str) -> str:
        try:
            completed = subprocess.run(
                ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return completed.stdout.strip() if completed.returncode == 0 else ""

    @classmethod
    def _inspect_inner(cls, response: Any, field: str, expected_type: type[Any]) -> Any:
        """Unwrap a fixed inspect envelope and enforce its public facade type."""
        envelope = cls._value(response)
        if not isinstance(envelope, dict):
            raise TypeError("privileged inspect response is not an envelope")
        value = envelope.get(field)
        if not isinstance(value, expected_type):
            raise TypeError(f"privileged inspect response has an invalid {field} value")
        return value

    def dependency_status(self) -> Any:
        specs = (
            ("Restic", "restic", "restic", True, "sudo apt install restic"),
            ("debsums", "debsums", "debsums", True, "sudo apt install debsums"),
            ("APT manual marks", "apt-mark", "apt", True, "provided by apt"),
            ("dpkg-query", "dpkg-query", "dpkg", True, "provided by dpkg"),
            ("apt-get", "apt-get", "apt", True, "provided by apt"),
            ("Snap inventory", "snap", "snapd", False, "sudo apt install snapd"),
            ("Flatpak inventory", "flatpak", "flatpak", False, "sudo apt install flatpak"),
            ("apt-clone compatibility export", "apt-clone", "apt-clone", False, "sudo apt install apt-clone"),
        )
        result: list[DependencyStatus] = []
        system_path = "/usr/sbin:/usr/bin:/sbin:/bin"
        for name, command, package, required, hint in specs:
            # Dependency probes are executable, so never resolve them through a
            # user-controlled PATH. UBackup expects these system packages in
            # standard system locations.
            path = shutil.which(command, path=system_path)
            result.append(
                DependencyStatus(
                    name,
                    command,
                    required,
                    bool(path),
                    (self._command_version(path) or self._package_version(package)) if path else "",
                    hint,
                )
            )
        return result

    def package_inventory(self, *, limit=500, offset=0, force=False, progress_cb=None) -> Any:
        payload = {"kind": "package-inventory", "limit": limit, "offset": offset, "force": bool(force)}
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, payload, timeout=300.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        return self._value(self._broker.inspect(
            self._backup_root, kind="package-inventory", limit=limit, offset=offset, force=bool(force)
        ))

    def config_inventory(self, *, limit=500, offset=0, force=False, progress_cb=None) -> Any:
        payload = {"kind": "config-inventory", "limit": limit, "offset": offset, "force": bool(force)}
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, payload, timeout=900.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        return self._value(self._broker.inspect(
            self._backup_root, kind="config-inventory", limit=limit, offset=offset, force=bool(force)
        ))

    def filesystem_children(
        self, path: str, *, limit=10_000, offset=0, exclude_patterns=None,
    ) -> Any:
        payload = {
            "kind": "filesystem-children", "path": path, "limit": limit, "offset": offset,
        }
        if exclude_patterns is not None:
            payload["exclude_patterns"] = list(exclude_patterns)
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, payload, timeout=300.0)
        self._require_broker_fallback()
        return self._value(self._broker.inspect(
            self._backup_root, kind="filesystem-children", path=path, limit=limit, offset=offset,
            exclude_patterns=list(exclude_patterns or []),
        ))

    def filesystem_size(self, path: str, *, progress_cb=None, exclude_patterns=None, force: bool = False) -> Any:
        payload = {"kind": "filesystem-size", "path": path, "force": bool(force)}
        if exclude_patterns is not None:
            payload["exclude_patterns"] = list(exclude_patterns)
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, payload, timeout=1800.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        return self._value(self._broker.inspect(
            self._backup_root, kind="filesystem-size", path=path, exclude_patterns=list(exclude_patterns or []), force=bool(force)
        ))

    def filesystem_cache(self, paths: list[str], *, exclude_patterns=None) -> Any:
        payload = {"kind": "filesystem-cache", "paths": list(paths)}
        if exclude_patterns is not None:
            payload["exclude_patterns"] = list(exclude_patterns)
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, payload, timeout=300.0)
        self._require_broker_fallback()
        return self._value(self._broker.inspect(
            self._backup_root, kind="filesystem-cache", paths=list(paths),
            exclude_patterns=list(exclude_patterns or []),
        ))

    def snapshots(self, component: str, credentials: CredentialDescriptor | None = None, *, limit=500, offset=0) -> Any:
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, {"kind": "snapshots", "component": component, "limit": limit, "offset": offset}, timeout=300.0)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        return self._value(self._broker.inspect(self._backup_root, kind="snapshots", component=component, password=c["password"], password_file=c["password_file"], limit=limit, offset=offset))

    def snapshot_stats(self, component: str, snapshot_id: str, credentials: CredentialDescriptor | None = None) -> Any:
        if self._session is not None:
            response = self._session_request(INSPECT_OPERATION, {"kind": "snapshot-stats", "component": component, "snapshot_id": snapshot_id}, timeout=300.0)
            return self._inspect_inner(response, "stats", dict)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        response = self._broker.inspect(self._backup_root, kind="snapshot-stats", component=component, snapshot_id=snapshot_id, password=c["password"], password_file=c["password_file"])
        return self._inspect_inner(response, "stats", dict)

    def snapshot_directory(self, component: str, snapshot_id: str, directory: str, credentials: CredentialDescriptor | None = None, *, limit=500, offset=0) -> Any:
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, {"kind": "snapshot-directory", "component": component, "snapshot_id": snapshot_id, "directory": directory, "limit": limit, "offset": offset}, timeout=900.0)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        return self._value(self._broker.inspect(self._backup_root, kind="snapshot-directory", component=component, snapshot_id=snapshot_id, directory=directory, password=c["password"], password_file=c["password_file"], limit=limit, offset=offset))

    def snapshot_manifest(self, component: str, snapshot_id: str, credentials: CredentialDescriptor | None = None) -> Any:
        return self._metadata(component, snapshot_id, "manifest.json", credentials, dict)

    def snapshot_packages(self, snapshot_id: str, credentials: CredentialDescriptor | None = None) -> Any:
        return self._metadata("packages", snapshot_id, "packages.json", credentials, list)

    def _metadata(self, component, snapshot_id, filename, credentials, expected_type):
        # List metadata can be arbitrarily large on real systems. Never move an
        # entire package/config inventory through one privileged response; page
        # it deterministically and assemble only in the unprivileged GUI.
        offset = 0
        combined: list[Any] = []
        while True:
            payload = {
                "kind": "metadata", "component": component, "snapshot_id": snapshot_id,
                "filename": filename, "limit": 500, "offset": offset,
            }
            if self._session is not None:
                response = self._session_request(INSPECT_OPERATION, payload, timeout=900.0)
            else:
                self._require_broker_fallback()
                c = self._credentials(credentials)
                response = self._broker.inspect(
                    self._backup_root, kind="metadata", component=component, snapshot_id=snapshot_id,
                    filename=filename, limit=500, offset=offset, password=c["password"],
                    password_file=c["password_file"],
                )
            envelope = self._value(response)
            if not isinstance(envelope, dict):
                raise TypeError("privileged inspect response is not an envelope")
            value = envelope.get("value")
            if expected_type is dict:
                if not isinstance(value, dict):
                    raise TypeError("privileged inspect response has an invalid value value")
                return value
            if not isinstance(value, list):
                raise TypeError("privileged inspect response has an invalid value value")
            combined.extend(value)
            next_offset = envelope.get("next_offset")
            if next_offset is None:
                return combined
            if isinstance(next_offset, bool) or not isinstance(next_offset, int) or next_offset <= offset:
                raise TypeError("privileged metadata pagination is invalid")
            offset = next_offset

    def repository_size(self, *, progress_cb=None) -> Any:
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, {"kind": "repository-size"}, timeout=1800.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        return self._value(self._broker.inspect(self._backup_root, kind="repository-size"))

    def delete_latest_snapshot(self, component: str, snapshot_id: str, *, progress_cb=None) -> Any:
        if self._session is None:
            self._require_broker_fallback()
            raise RuntimeError("Repository maintenance requires the authenticated startup session.")
        return self._session_request(
            MAINTENANCE_OPERATION,
            {"action": "delete-latest", "component": component, "snapshot_id": snapshot_id},
            timeout=3600.0,
            progress_cb=progress_cb,
        )

    def consolidate_history(self, component: str, snapshot_id: str, *, progress_cb=None) -> Any:
        if self._session is None:
            self._require_broker_fallback()
            raise RuntimeError("Repository maintenance requires the authenticated startup session.")
        return self._session_request(
            MAINTENANCE_OPERATION,
            {"action": "consolidate-history", "component": component, "snapshot_id": snapshot_id},
            timeout=3600.0,
            progress_cb=progress_cb,
        )

    def staging_children(self, staging_id: str, path: str = "", *, limit=500, offset=0) -> Any:
        if self._session is not None:
            return self._session_request(INSPECT_OPERATION, {"kind": "staging-children", "staging_id": staging_id, "path": path, "limit": limit, "offset": offset}, timeout=300.0)
        self._require_broker_fallback()
        return self._value(self._broker.inspect(self._backup_root, kind="staging-children", staging_id=staging_id, path=path, limit=limit, offset=offset))

    def backup(self, *, sources, source_exclusions, exclude_rules, packages, configs, components=None, credentials=None, progress_cb=None) -> Any:
        component_values = list(components or [])
        if len(component_values) != 1:
            raise ValueError("backup requires exactly one component repository")
        if self._session is not None:
            return self._session_request(BACKUP_OPERATION, {"sources": sources, "source_exclusions": source_exclusions, "exclude_rules": exclude_rules, "packages": packages, "configs": configs, "components": component_values, "dry_run": False}, timeout=3600.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        return self._value(self._broker.backup(self._backup_root, sources=sources, source_exclusions=source_exclusions, exclude_rules=exclude_rules, packages=packages, configs=configs, components=component_values, dry_run=False, password=c["password"], password_file=c["password_file"]))

    def dry_run(self, *, sources, source_exclusions, exclude_rules, packages, configs, components=None, credentials=None, progress_cb=None) -> Any:
        component_values = list(components or [])
        if len(component_values) != 1:
            raise ValueError("dry-run requires exactly one component repository")
        if self._session is not None:
            return self._session_request(BACKUP_OPERATION, {"sources": sources, "source_exclusions": source_exclusions, "exclude_rules": exclude_rules, "packages": packages, "configs": configs, "components": component_values, "dry_run": True}, timeout=3600.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        return self._value(self._broker.backup(self._backup_root, sources=sources, source_exclusions=source_exclusions, exclude_rules=exclude_rules, packages=packages, configs=configs, components=component_values, dry_run=True, password=c["password"], password_file=c["password_file"]))

    def restore_staging(self, component, snapshot_id, includes, credentials=None, *, progress_cb=None) -> Any:
        if self._session is not None:
            return self._session_request(RESTORE_STAGING_OPERATION, {"component": component, "snapshot_id": snapshot_id, "includes": includes}, timeout=1800.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        return self._value(self._broker.restore_staging(self._backup_root, component=component, snapshot_id=snapshot_id, includes=includes, password=c["password"], password_file=c["password_file"]))

    def restore_inplace(self, component, snapshot_id, includes, credentials=None, *, progress_cb=None) -> Any:
        if self._session is not None:
            return self._session_request(RESTORE_INPLACE_OPERATION, {"component": component, "snapshot_id": snapshot_id, "includes": includes}, timeout=1800.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        return self._value(self._broker.restore_inplace(self._backup_root, component=component, snapshot_id=snapshot_id, includes=includes, password=c["password"], password_file=c["password_file"]))

    def package_simulate(self, snapshot_id, packages, credentials=None, *, progress_cb=None) -> Any:
        return self._package_restore(snapshot_id, packages, True, credentials, progress_cb=progress_cb)

    def package_install(self, snapshot_id, packages, credentials=None, *, progress_cb=None) -> Any:
        return self._package_restore(snapshot_id, packages, False, credentials, progress_cb=progress_cb)

    # Compatibility aliases for callers/tests written before the multi-manager package model.
    apt_simulate = package_simulate
    apt_install = package_install

    def _package_restore(self, snapshot_id, packages, simulate, credentials, *, progress_cb=None):
        if self._session is not None:
            return self._session_request(PACKAGES_INSTALL_OPERATION, {"snapshot_id": snapshot_id, "packages": packages, "simulate": simulate}, timeout=1800.0, progress_cb=progress_cb)
        self._require_broker_fallback()
        c = self._credentials(credentials)
        return self._value(self._broker.packages_install(self._backup_root, snapshot_id=snapshot_id, packages=packages, simulate=simulate, password=c["password"], password_file=c["password_file"]))
