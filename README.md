# UBackup

UBackup is a curated backup/restore GUI for Ubuntu desktops. The PySide6 GUI always runs as the logged-in, unprivileged desktop user. Protected work is performed by a root-owned helper that is authorized once through Polkit when UBackup starts and remains attached to that GUI session through a private, typed IPC channel.

## Core behavior

- Incremental, encrypted Restic snapshots.
- Filesystem browser with cached sizes, explicit inclusion/exclusion policy, recursive inclusion and tri-state selection rendering.
- Hard system exclusions for pseudo/runtime filesystems and the backup repository itself.
- Preconfigured exclusions for reconstructible data such as caches, Python virtual environments, Node dependency trees and game download/shader caches.
- Conservative Steam policy: save-sensitive locations such as `Steam/userdata` and Proton `compatdata` are not excluded by default; `steamapps/common` rules are provided but disabled.
- Unified software inventory for APT manual packages, installed Snaps and Flatpak applications, with per-package restore policy and package-manager-aware restore.
- Curated `/etc` audit based on modified package configuration plus unmanaged files, shown as a virtual directory tree.
- Versioned `manifest.json`, package/configuration plans and system metadata inside the Restic snapshot they describe. Package snapshots store separate `packages-apt.json`, `packages-snap.json` and `packages-flatpak.json` files while the GUI presents one unified inventory.
- Selective file/configuration/package restore.
- Restic dry-run estimation and backup-filesystem capacity assessment.
- Background task monitor with throttled live progress/current-item information.
- Snapshot maintenance: only the latest snapshot can be deleted directly; deletion uses Restic `forget --prune`. A guarded `Consolidate history` action can keep the latest snapshot and remove compatible older history after coverage checks.

## Privilege model

The GUI must **not** be run with `sudo`, `sudo -E`, or `pkexec`.

Normal startup is:

```bash
ubackup
```

At startup the GUI launches one fixed root-owned startup helper through `pkexec`. Polkit may request administrator authentication at that point. After authorization, that helper remains alive for the lifetime of the GUI and services only a fixed allow-list of structured operations such as inspection, backup, restore and package installation.

The normal GUI path does not invoke `pkexec` again after startup. If the authenticated helper dies or the IPC session becomes invalid, the operation fails; UBackup does not silently launch another privileged helper and trigger another authentication prompt.

The helper is intentionally **not** a generic command runner. The GUI cannot supply an executable, shell fragment, arbitrary argv or arbitrary environment for root execution. Privileged requests are operation-specific and validated again inside the helper.

Standalone fixed helpers/policies remain installed for maintenance, compatibility and testing, but the production GUI uses the single startup-authorized session.

### Credentials

Polkit authentication and the Restic repository password are separate credentials.

- Polkit authentication is requested once when the privileged startup helper is launched.
- If a Restic password must be entered interactively, it is requested during startup and sent once to the authenticated helper.
- After the startup handshake succeeds, the GUI discards its plaintext Restic password value. The root helper retains the credential only for the lifetime of that application session and creates request-private password files with restrictive permissions when invoking Restic.
- `--password-file` may point to an existing external password file. UBackup does not modify it.

## Runtime write policy

During ordinary audit, browsing, dry-run and backup work, UBackup keeps its own writable state below the configured `--backup-root` (default `/backup`). Explicit restore operations are the expected exceptions because they intentionally modify the target filesystem or software package-manager state.

The default `/backup` may be created automatically by the authenticated root helper if it is genuinely absent. A custom `--backup-root` is not created arbitrarily by the helper; it must already satisfy the project's backup-root admission rules.

Typical layout:

```text
/backup/
├── repository/                  # root-controlled Restic repository
├── restores/                    # root-controlled staging restores
└── .ubackup/
    ├── cache/                   # privileged cache/runtime state
    ├── runtime/
    ├── plans/
    ├── state/current/           # helper-built snapshot metadata
    └── users/<uid>/             # private state for the unprivileged GUI
        ├── state/cache.sqlite3
        ├── cache/
        ├── runtime/
        └── logs/
```

The backup root and repository are hard exclusions from ordinary filesystem traversal, so selecting `/` cannot recursively back the repository into itself.

## Selection model

Filesystem policy is not a boolean. Persistent user policy distinguishes:

- `DEFAULT`: no explicit user decision;
- `INCLUDE`: explicitly include one non-directory path;
- `INCLUDE_RECURSIVE`: directory checkbox semantics; include current and future descendants unless a stronger exclusion applies;
- `EXCLUDE`: explicit persistent manual exclusion.

Rendered checkbox state is derived from effective descendant state and may be unchecked, checked or partially checked. `PartiallyChecked` is never persisted as user policy.

Unchecking a path that is currently selected, including a child selected through an ancestor's recursive inclusion, creates a persistent manual exclusion. Browsing/expanding alone never changes policy.

Effective precedence is intentionally centralized:

1. hard system / backup-root exclusion;
2. explicit manual exclusion;
3. exact explicit inclusion;
4. preconfigured exclusion;
5. inherited recursive inclusion;
6. default/unselected.

An explicit inclusion can therefore override a preconfigured convenience rule, while hard exclusions cannot be overridden.

New content is compared with the filesystem inventory associated with the last successful snapshot. A newly discovered path that is neither known to that snapshot nor automatically covered by recursive inclusion is shown as requiring review. That review state propagates upward in the visible tree.

## `/etc` strategy

UBackup deliberately does not back up all of `/etc` by default.

It builds a curated candidate set from:

- package configuration detected as modified by `debsums -ce`;
- files under `/etc` that are not present in dpkg package file lists.

The GUI renders those candidates as an expandable virtual `/etc` tree. Intermediate directories are aggregation nodes only: selecting `/etc/ssh` in that view means selecting the candidate leaves below it, not adding the real `/etc/ssh` directory wholesale to Restic.

Restores remain selective so old defaults are not blindly overlaid on a newer installation.

## Default filesystem exclusions

Hard, non-overridable system exclusions include at least:

```text
/proc
/sys
/dev
/run
<backup-root>
```

Preconfigured, user-overridable rules include `/tmp`, `/var/tmp`, `/boot`, `/boot/efi` and common reconstructible development/cache data. `/boot` and `/boot/efi` are not treated as pseudo-filesystems; a user may explicitly include them when custom boot data matters.

## Dependencies

Required Ubuntu-side tools:

```bash
sudo apt update
sudo apt install restic debsums python3-venv policykit-1
```

APT/dpkg utilities (`apt-mark`, `apt-get`, `dpkg-query`) are expected on Ubuntu. Snap and Flatpak are inventoried/restored when their commands are installed. `apt-clone` remains an optional APT compatibility/export utility; it is not treated as a separate package manager.

## Install the privileged backend

From a trusted checkout:

```bash
sudo ./scripts/install_system.sh
```

The installer copies only an explicit allow-list of privileged Python modules and fixed launchers into root-owned system locations, verifies ownership/modes, and installs Polkit policy only after the helper tree is in place. Standard `__pycache__` directories in the source tree are ignored and never installed; other unexpected privileged-source inputs remain fail-closed.

The GUI itself is not elevated by this installer.

The GUI starts maximized and remains an unprivileged desktop process; only the fixed helper session runs as root.

## Run from source

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
ubackup --backup-root /backup
```

Do not use `sudo -E` for the GUI.

## Portable build

The project can still be packaged as a standalone PySide6/Nuitka application for the GUI side. The installed privileged helper and Polkit policy remain system components and must be installed separately because privilege elevation cannot safely be implemented by unpacking arbitrary root code from an untrusted per-user bundle at runtime.

Build the standalone portable application with:

```bash
chmod +x scripts/build_portable.sh
./scripts/build_portable.sh
```
The standalone build is generated under `dist/`.

### Install the portable build

You can build UBackup locally as described above, or download the latest portable build from the [GitHub Releases](https://github.com/FedericoHeichou/UBackup/releases) page.

After extracting the release, install the executable system-wide:

```bash
sudo cp ubackup /usr/local/bin/ubackup
sudo chmod 755 /usr/local/bin/ubackup
sudo chown root:root /usr/local/bin/ubackup
```

Optionally, create a desktop launcher:

```bash
cat > ~/ubackup.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=UBackup
Comment=Backup and restore utility
Exec=/usr/local/bin/ubackup
Terminal=false
Categories=Utility;System;
EOF

mkdir -p ~/.local/share/applications
mv ~/ubackup.desktop ~/.local/share/applications/ubackup.desktop
chmod 644 ~/.local/share/applications/ubackup.desktop
```

UBackup will then be available from the desktop application launcher.

## Tests

Run the full test suite with the Qt offscreen backend:

```bash
python -m pip install -e . pytest
umask 0002
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

## Capacity estimates

The dashboard distinguishes logical selected data from the estimated Restic repository delta.

- For the first backup, logical selected size is a conservative capacity indicator until a Restic dry-run provides a better estimate.
- For incremental backups, UBackup uses the estimated new repository delta rather than the total logical selection.
- A safety margin is added before reporting the backup filesystem as sufficient.

Exact physical usage can still differ because Restic compression, deduplication, pack layout and filesystem overhead are data-dependent.


## Warning

UBackup is a fully vibe-coded project made to test some AI capabilities. I only tested it on Ubuntu 24.04 and I will try to use it on my PC. I am not responsible for any data loss or damage caused by using this software. Use it at your own risk. Always make sure to have a separate backup of your important data before using UBackup or any other backup software.
