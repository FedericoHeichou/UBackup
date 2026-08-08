from __future__ import annotations

from dataclasses import dataclass, asdict
from fnmatch import fnmatchcase
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ExcludeRule:
    pattern: str
    category: str
    reason: str
    default_enabled: bool = True
    caution: str = ""

    def to_dict(self):
        return asdict(self)


# Conservative defaults. Steam save-bearing locations are deliberately retained.
DEFAULT_RULES: tuple[ExcludeRule, ...] = (
    ExcludeRule("*.tmp", "Temporary", "Temporary files"),
    ExcludeRule("/tmp/**", "System", "Temporary system files"),
    ExcludeRule("/var/tmp/**", "System", "Temporary system files"),
    ExcludeRule("/var/cache/apt/**", "APT", "APT caches are regenerable and package installation is reconstructed from the Packages snapshot"),
    ExcludeRule("/var/lib/apt/**", "APT", "APT package-manager state is reconstructed rather than copied onto a fresh installation"),
    ExcludeRule("/var/lib/dpkg/**", "APT/dpkg", "dpkg package-manager state must be rebuilt by package installation instead of restored as stale database files"),
    ExcludeRule("/snap/**", "Snap", "Mounted/installed Snap package payloads are managed by snapd; user data under ~/snap is retained"),
    ExcludeRule("/var/lib/snapd/snaps/**", "Snap", "Installed Snap package images are reinstallable from the Packages snapshot"),
    ExcludeRule("/var/lib/snapd/seed/snaps/**", "Snap", "Seed Snap images are package payloads managed by snapd"),
    ExcludeRule("/var/lib/snapd/cache/**", "Snap", "Snap download cache is regenerable"),
    ExcludeRule("/var/lib/flatpak/app/**", "Flatpak", "System Flatpak application deployments are reinstallable from the Packages snapshot"),
    ExcludeRule("/var/lib/flatpak/runtime/**", "Flatpak", "System Flatpak runtimes are dependency-managed and reinstallable"),
    ExcludeRule("/var/lib/flatpak/repo/**", "Flatpak", "System Flatpak OSTree objects are reinstallable"),
    ExcludeRule("**/.local/share/flatpak/app/**", "Flatpak", "Per-user Flatpak application deployments are reinstallable; ~/.var/app user data is retained"),
    ExcludeRule("**/.local/share/flatpak/runtime/**", "Flatpak", "Per-user Flatpak runtimes are dependency-managed and reinstallable"),
    ExcludeRule("**/.local/share/flatpak/repo/**", "Flatpak", "Per-user Flatpak repository objects are reinstallable"),
    ExcludeRule(
        "/etc/**",
        "Configuration",
        "The normal filesystem backup excludes /etc by default; use the /etc Configuration section to capture only audited non-default/customized configuration files",
        True,
        "Disable this rule only if you intentionally want the normal filesystem backup to include the entire /etc tree",
    ),
    ExcludeRule("/boot/**", "System", "Boot artifacts are normally reconstructable", True,
                "Disable this exclusion if you maintain custom boot files"),
    ExcludeRule("/boot/efi/**", "System", "EFI boot artifacts are normally reconstructable", True,
                "Disable this exclusion if you maintain custom EFI files"),
    ExcludeRule("**/.cache/**", "Cache", "Regenerable user cache"),
    ExcludeRule("**/__pycache__/**", "Python", "Regenerable Python bytecode"),
    ExcludeRule("**/.pytest_cache/**", "Python", "pytest cache"),
    ExcludeRule("**/.mypy_cache/**", "Python", "mypy cache"),
    ExcludeRule("**/.ruff_cache/**", "Python", "ruff cache"),
    ExcludeRule("**/.tox/**", "Python", "Recreatable tox environments"),
    ExcludeRule("**/.nox/**", "Python", "Recreatable nox environments"),
    ExcludeRule("**/.venv/**", "Python", "Virtual environment recreatable from project metadata", True,
                "Verify that pyproject.toml, requirements or a lock file exists"),
    ExcludeRule("**/venv/**", "Python", "Virtual environment recreatable from project metadata", True,
                "Verify that pyproject.toml, requirements or a lock file exists"),
    ExcludeRule("**/node_modules/**", "Node.js", "Dependencies reinstallable from package metadata/lock files"),
    ExcludeRule("**/.npm/_cacache/**", "Node.js", "npm download cache"),
    ExcludeRule("**/.pnpm-store/**", "Node.js", "Reconstructable pnpm store"),
    ExcludeRule("**/.yarn/cache/**", "Node.js", "Yarn cache"),
    ExcludeRule("**/target/**", "Rust", "Cargo build artifacts", False,
                "Generic directory name; enable only when target is a build directory"),
    ExcludeRule("**/.cargo/registry/cache/**", "Rust", "Downloaded crate cache"),
    ExcludeRule("**/.cargo/registry/src/**", "Rust", "Downloaded crate sources"),
    ExcludeRule("**/.gradle/caches/**", "JVM", "Gradle cache"),
    ExcludeRule("**/.m2/repository/**", "JVM", "Re-downloadable Maven repository"),
    ExcludeRule("**/.local/share/Trash/**", "Desktop", "Desktop trash"),
    ExcludeRule("**/.Trash-*/**", "Desktop", "Filesystem trash"),
    ExcludeRule("**/Cache/**", "Browser/App", "Generic cache directory", False,
                "Very generic name; disabled by default"),
    ExcludeRule("**/Code Cache/**", "Browser/App", "Chromium/Electron code cache"),
    ExcludeRule("**/GPUCache/**", "Browser/App", "Chromium/Electron GPU cache"),
    ExcludeRule("**/.local/share/Steam/steamapps/common/**", "Steam", "Installed Steam game data", False,
                "Some games may store local saves inside the installation directory"),
    ExcludeRule("**/.steam/steam/steamapps/common/**", "Steam", "Installed Steam game data", False,
                "Some games may store local saves inside the installation directory"),
    ExcludeRule("**/SteamLibrary/steamapps/common/**", "Steam", "Installed Steam game data", False,
                "Some games may store local saves inside the installation directory"),
    ExcludeRule("**/steamapps/shadercache/**", "Steam", "Steam shader cache"),
    ExcludeRule("**/steamapps/downloading/**", "Steam", "Temporary Steam downloads"),
    ExcludeRule("**/steamapps/temp/**", "Steam", "Steam temporary files"),
    ExcludeRule("**/steamapps/workshop/content/**", "Steam", "Re-downloadable Steam Workshop content", True,
                "Non-Workshop mods may live elsewhere and are not excluded"),
)

NEVER_DEFAULT_EXCLUDE_HINTS = (
    "**/Steam/userdata/**",
    "**/steamapps/compatdata/**",
    "**/.var/app/**",
    "**/snap/**",
)

# Hard exclusions are not user-overridable. /tmp, /etc and /boot are
# intentionally not here; they are preconfigured rules above and can be
# overridden by an explicit user inclusion.
SYSTEM_HARD_ROOTS = ("/proc", "/sys", "/dev", "/run")
SYSTEM_HARD_EXACT = ("/swapfile",)
# usrmerge compatibility aliases commonly present at the Ubuntu filesystem
# root. They are hard-excluded only when they really are symlinks so a custom
# installation containing a real directory at one of these paths is not
# silently discarded.
ROOT_COMPAT_SYMLINKS = ("/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")


def is_root_compat_symlink(path: str) -> bool:
    value = str(Path(path))
    for alias in ROOT_COMPAT_SYMLINKS:
        if value == alias or value.startswith(alias + "/"):
            return Path(alias).is_symlink()
    return False


def is_system_hard_path(path: str) -> bool:
    value = str(Path(path))
    if any(value == root or value.startswith(root + "/") for root in SYSTEM_HARD_ROOTS):
        return True
    if value in SYSTEM_HARD_EXACT:
        return True
    return is_root_compat_symlink(value)


def system_hard_exclude_patterns() -> list[str]:
    patterns = [root + "/**" for root in SYSTEM_HARD_ROOTS]
    patterns.extend(SYSTEM_HARD_EXACT)
    patterns.extend(path for path in ROOT_COMPAT_SYMLINKS if Path(path).is_symlink())
    return patterns


# Backward-compatible name used by older imports. This tuple intentionally
# contains only unconditional entries; callers that build a live Restic plan
# should use system_hard_exclude_patterns() so usrmerge aliases are conditional.
SYSTEM_EPHEMERAL_EXCLUDES = tuple(root + "/**" for root in SYSTEM_HARD_ROOTS) + SYSTEM_HARD_EXACT


def enabled_rules(selection_lookup) -> list[ExcludeRule]:
    return [r for r in DEFAULT_RULES if selection_lookup(r.pattern, r.default_enabled)]


def matches_resticish(path: str, pattern: str) -> bool:
    """UI-only approximation of restic glob matching; Restic remains authoritative."""
    negative = pattern.startswith("!")
    if negative:
        pattern = pattern[1:]
    norm = str(Path(path))
    if fnmatchcase(norm, pattern):
        return True
    if pattern.endswith("/**"):
        base = pattern[:-3]
        if base.startswith("**/"):
            needle = base[3:]
            return f"/{needle}/" in norm.rstrip("/") + "/" or norm.endswith("/" + needle)
        return norm == base or norm.startswith(base.rstrip("/") + "/")
    return fnmatchcase(norm, pattern)
