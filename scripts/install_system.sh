#!/usr/bin/env bash
set -euo pipefail

# Install only the trusted privileged backend and Polkit actions. The GUI
# intentionally remains unprivileged and is not elevated by this script.
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '%s\n' 'install_system.sh must be run as root.' >&2
    exit 77
fi
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

SOURCE_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
INSTALL_ROOT="/usr/lib/ubackup"
LIBEXEC_ROOT="/usr/libexec"
POLICY_ROOT="/usr/share/polkit-1/actions"
HELPERS=(
    "ubackup-configure"
    "ubackup-startup"
    "ubackup-inspect"
    "ubackup-backup"
    "ubackup-restore-staging"
    "ubackup-restore-inplace"
    "ubackup-packages-install"
)
POLICIES=(
    "org.ubackup.configure.policy"
    "org.ubackup.startup.policy"
    "org.ubackup.inspect.policy"
    "org.ubackup.backup.policy"
    "org.ubackup.restore-staging.policy"
    "org.ubackup.restore-inplace.policy"
    "org.ubackup.packages-install.policy"
)

# This is an explicit manifest, not a recursive package copy.  It contains
# only the modules imported by the installed privileged helpers/session.
SOURCE_FILES=(
    "src/ubackup/__init__.py"
    "src/ubackup/cache.py"
    "src/ubackup/fs_scan.py"
    "src/ubackup/manifest.py"
    "src/ubackup/models.py"
    "src/ubackup/paths.py"
    "src/ubackup/profiles.py"
    "src/ubackup/restic_engine.py"
    "src/ubackup/restore_engine.py"
    "src/ubackup/system_scan.py"
    "src/ubackup/privileged/__init__.py"
    "src/ubackup/privileged/backup.py"
    "src/ubackup/privileged/inspect.py"
    "src/ubackup/privileged/maintenance.py"
    "src/ubackup/privileged/metadata.py"
    "src/ubackup/privileged/credentials.py"
    "src/ubackup/privileged/packages_install.py"
    "src/ubackup/privileged/protocol.py"
    "src/ubackup/privileged/restore.py"
    "src/ubackup/privileged/restore_inplace.py"
    "src/ubackup/privileged/restore_staging.py"
    "src/ubackup/privileged/configure.py"
    "src/ubackup/privileged/startup.py"
    "src/ubackup/privileged/filesystem_navigation.py"
    "src/ubackup/privileged/runtime.py"
    "src/ubackup/privileged/validation.py"
)

SOURCE_ASSETS=(
    "packaging/libexec/ubackup-configure"
    "packaging/libexec/ubackup-startup"
    "packaging/libexec/ubackup-inspect"
    "packaging/libexec/ubackup-backup"
    "packaging/libexec/ubackup-restore-staging"
    "packaging/libexec/ubackup-restore-inplace"
    "packaging/libexec/ubackup-packages-install"
    "packaging/polkit/org.ubackup.configure.policy"
    "packaging/polkit/org.ubackup.startup.policy"
    "packaging/polkit/org.ubackup.inspect.policy"
    "packaging/polkit/org.ubackup.backup.policy"
    "packaging/polkit/org.ubackup.restore-staging.policy"
    "packaging/polkit/org.ubackup.restore-inplace.policy"
    "packaging/polkit/org.ubackup.packages-install.policy"
)

die() {
    printf 'Installation refused: %s\n' "$1" >&2
    exit 65
}

mode_bits() {
    local mode
    mode="$(stat -c '%a' -- "$1")" || die "cannot stat $1"
    printf '%d\n' "$((8#$mode))"
}

verify_secure_path() {
    local path="$1" bits owner
    [[ ! -L "$path" ]] || die "symlink is not permitted: $path"
    [[ -e "$path" ]] || die "missing path: $path"
    owner="$(stat -c '%u' -- "$path")" || die "cannot stat owner: $path"
    [[ "$owner" == 0 ]] || die "path is not root-owned: $path"
    bits="$(mode_bits "$path")"
    (( (bits & 18) == 0 )) || die "path is group/world writable: $path"
}

verify_regular_source() {
    local path="$1"
    [[ ! -L "$path" ]] || die "source symlink is not permitted: $path"
    [[ -f "$path" ]] || die "source is not a regular file: $path"
    case "${path##*.}" in
        py|policy) ;;
        *)
            case "${path##*/}" in
                ubackup-configure|ubackup-startup|ubackup-inspect|ubackup-backup|ubackup-restore-staging|ubackup-restore-inplace|ubackup-packages-install) ;;
                *) die "unexpected source file type: $path" ;;
            esac
            ;;
    esac
    [[ "${path##*.}" != "pyc" && "${path##*.}" != "pyo" ]] \
        || die "bytecode input is not permitted: $path"
}

is_manifest_source() {
    local path="$1" relative
    for relative in "${SOURCE_FILES[@]}"; do
        [[ "$path" == "$SOURCE_ROOT/$relative" ]] && return 0
    done
    return 1
}

is_manifest_asset() {
    local path="$1" relative
    for relative in "${SOURCE_ASSETS[@]}"; do
        [[ "$path" == "$SOURCE_ROOT/$relative" ]] && return 0
    done
    return 1
}

for relative in "${SOURCE_FILES[@]}" "${SOURCE_ASSETS[@]}"; do
    verify_regular_source "$SOURCE_ROOT/$relative"
done

# Standard __pycache__ directories are ignored and never installed. Every
# other symlink or unlisted privileged input remains fail-closed.
[[ ! -L "$SOURCE_ROOT/src/ubackup/privileged" && -d "$SOURCE_ROOT/src/ubackup/privileged" ]] \
    || die "privileged source directory is unsafe"
while IFS= read -r -d '' input; do
    [[ ! -L "$input" ]] || die "source symlink is not permitted: $input"
    [[ -d "$input" ]] && continue
    is_manifest_source "$input" || die "unexpected privileged source input: $input"
    verify_regular_source "$input"
done < <(find -P "$SOURCE_ROOT/src/ubackup/privileged" \
    -type d -name '__pycache__' -prune -o -print0)

for asset_dir in "$SOURCE_ROOT/packaging/libexec" "$SOURCE_ROOT/packaging/polkit"; do
    [[ ! -L "$asset_dir" && -d "$asset_dir" ]] || die "packaging asset directory is unsafe: $asset_dir"
    while IFS= read -r -d '' input; do
        [[ ! -L "$input" ]] || die "packaging source symlink is not permitted: $input"
        [[ -d "$input" ]] && continue
        is_manifest_asset "$input" || die "unexpected packaging source input: $input"
        verify_regular_source "$input"
    done < <(find -P "$asset_dir" -print0)
done

# All installation parents must themselves be trusted before staging or
# replacement.  Staging under /usr/lib avoids user-writable temporary space.
for parent in /usr /usr/lib /usr/libexec /usr/share /usr/share/polkit-1 "$POLICY_ROOT"; do
    verify_secure_path "$parent"
    [[ -d "$parent" ]] || die "installation parent is not a directory: $parent"
done

for fixed in "$INSTALL_ROOT"; do
    [[ ! -L "$fixed" ]] || die "symlink installation destination: $fixed"
done
for helper in "${HELPERS[@]}"; do
    [[ ! -L "$LIBEXEC_ROOT/$helper" ]] || die "symlink installation destination: $LIBEXEC_ROOT/$helper"
done
for policy in "${POLICIES[@]}"; do
    [[ ! -L "$POLICY_ROOT/$policy" ]] || die "symlink installation destination: $POLICY_ROOT/$policy"
done
if [[ -e "$INSTALL_ROOT" ]]; then
    [[ -d "$INSTALL_ROOT" ]] || die "existing helper tree is not a directory"
    while IFS= read -r -d '' old; do
        verify_secure_path "$old"
    done < <(find -P "$INSTALL_ROOT" -print0)
fi

STAGE="$(mktemp -d /usr/lib/.ubackup-install.XXXXXX)"
trap 'rm -rf -- "$STAGE"' EXIT
install -d -o root -g root -m 0755 \
    "$STAGE/usr/lib/ubackup/ubackup/privileged" "$STAGE/usr/libexec" \
    "$STAGE/usr/share/polkit-1/actions"

for relative in "${SOURCE_FILES[@]}"; do
    installed="${relative#src/ubackup/}"
    install -D -o root -g root -m 0644 "$SOURCE_ROOT/$relative" \
        "$STAGE/usr/lib/ubackup/ubackup/$installed"
done
for helper in "${HELPERS[@]}"; do
    install -o root -g root -m 0755 "$SOURCE_ROOT/packaging/libexec/$helper" \
        "$STAGE/usr/libexec/$helper"
done
for policy in "${POLICIES[@]}"; do
    install -o root -g root -m 0644 "$SOURCE_ROOT/packaging/polkit/$policy" \
        "$STAGE/usr/share/polkit-1/actions/$policy"
done

# Verify the freshly built helper tree is exactly the manifest before any
# policy is installed.  This also makes replacement, rather than overlay,
# explicit: the old installed privileged helper tree is replaced below.
EXPECTED_TREE=(
    "$STAGE/usr/lib/ubackup"
    "$STAGE/usr/lib/ubackup/ubackup"
    "$STAGE/usr/lib/ubackup/ubackup/privileged"
    "$STAGE/usr/libexec"
    "$STAGE/usr/share"
    "$STAGE/usr/share/polkit-1"
    "$STAGE/usr/share/polkit-1/actions"
)
for relative in "${SOURCE_FILES[@]}"; do
    EXPECTED_TREE+=("$STAGE/usr/lib/ubackup/ubackup/${relative#src/ubackup/}")
done
for helper in "${HELPERS[@]}"; do EXPECTED_TREE+=("$STAGE/usr/libexec/$helper"); done
for policy in "${POLICIES[@]}"; do EXPECTED_TREE+=("$STAGE/usr/share/polkit-1/actions/$policy"); done
for expected in "${EXPECTED_TREE[@]}"; do
    verify_secure_path "$expected"
done
while IFS= read -r -d '' staged; do
    case " ${EXPECTED_TREE[*]} " in
        *" $staged "*) ;;
        *) die "unexpected staged installation input: $staged" ;;
    esac
done < <(find -P "$STAGE/usr/lib/ubackup" "$STAGE/usr/libexec" "$STAGE/usr/share" -print0)

rm -rf -- "$INSTALL_ROOT"
install -d -o root -g root -m 0755 "$INSTALL_ROOT"
for relative in "${SOURCE_FILES[@]}"; do
    install -D -o root -g root -m 0644 \
        "$STAGE/usr/lib/ubackup/ubackup/${relative#src/ubackup/}" \
        "$INSTALL_ROOT/ubackup/${relative#src/ubackup/}"
done
for helper in "${HELPERS[@]}"; do
    install -o root -g root -m 0755 "$STAGE/usr/libexec/$helper" "$LIBEXEC_ROOT/$helper"
done

# Policy installation is deliberately last: the code and fixed launcher have
# been replaced and their ownership/modes verified before authorization exists.
for installed in "$INSTALL_ROOT"; do
    verify_secure_path "$installed"
done
verify_secure_path "$INSTALL_ROOT/ubackup"
verify_secure_path "$INSTALL_ROOT/ubackup/privileged"
for relative in "${SOURCE_FILES[@]}"; do
    verify_secure_path "$INSTALL_ROOT/ubackup/${relative#src/ubackup/}"
done
for helper in "${HELPERS[@]}"; do verify_secure_path "$LIBEXEC_ROOT/$helper"; done
for policy in "${POLICIES[@]}"; do
    install -o root -g root -m 0644 "$STAGE/usr/share/polkit-1/actions/$policy" "$POLICY_ROOT/$policy"
    verify_secure_path "$POLICY_ROOT/$policy"
done

printf '%s\n' 'UBackup privileged helper installation complete.'
