#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ARCH="${UBACKUP_APPIMAGE_ARCH:-x86_64}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
APPIMAGE_OUTPUT="${UBACKUP_APPIMAGE_OUTPUT:-$ROOT/dist/UBackup-${ARCH}.AppImage}"
APPIMAGETOOL="${APPIMAGETOOL:-$ROOT/.venv-build/bin/appimagetool-${ARCH}.AppImage}"
APPIMAGETOOL_URL="${APPIMAGETOOL_URL:-https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage}"
APPDIR="$ROOT/build/UBackup.AppDir"
STANDALONE_DIR="$ROOT/dist/UBackup.dist"

requested_python="$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ -x .venv-build/bin/python ]]; then
  venv_python="$(.venv-build/bin/python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
else
  venv_python=""
fi
if [[ "$venv_python" != "$requested_python" ]]; then
  rm -rf .venv-build
  "$PYTHON_BIN" -m venv .venv-build
fi
source .venv-build/bin/activate
python -m pip install --upgrade pip
python -m pip install 'PySide6>=6.8,<7'
export PYTHONPATH="$ROOT/src"

# Build a relocatable Qt/Python directory first. Nuitka onefile is deliberately
# not used because it extracts to a temporary directory before UBackup can
# establish its controlled runtime/write locations. The standalone directory
# is then wrapped read-only into a single AppImage file.
pyside6-deploy "$ROOT/main.py" --name UBackup --force --init
python - <<'PY2'
from configparser import ConfigParser
from pathlib import Path

p = Path("pysidedeploy.spec")
c = ConfigParser(interpolation=None)
c.optionxform = str
c.read(p)
if not c.has_section("nuitka"):
    c.add_section("nuitka")
c.set("nuitka", "mode", "standalone")
if c.has_section("app"):
    c.set("app", "exec_directory", str(Path("dist").resolve()))
with p.open("w") as f:
    c.write(f)
PY2

rm -rf "$STANDALONE_DIR" "$APPDIR"
mkdir -p "$ROOT/dist"
pyside6-deploy -c "$ROOT/pysidedeploy.spec" --force

[[ -x "$STANDALONE_DIR/main.bin" ]] || {
  printf 'Expected standalone executable is missing: %s\n' "$STANDALONE_DIR/main.bin" >&2
  exit 1
}

mkdir -p \
  "$APPDIR/usr/lib/ubackup" \
  "$APPDIR/usr/share/applications" \
  "$APPDIR/usr/share/icons/hicolor/scalable/apps"
cp -a "$STANDALONE_DIR/." "$APPDIR/usr/lib/ubackup/"
cp "$ROOT/packaging/appimage/ubackup.desktop" "$APPDIR/usr/share/applications/ubackup.desktop"
cp "$ROOT/packaging/appimage/ubackup.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/ubackup.svg"
cp "$ROOT/packaging/appimage/ubackup.desktop" "$APPDIR/ubackup.desktop"
cp "$ROOT/packaging/appimage/ubackup.svg" "$APPDIR/ubackup.svg"
ln -s ubackup.svg "$APPDIR/.DirIcon"

cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
set -eu
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
exec "$HERE/usr/lib/ubackup/main.bin" "$@"
APPRUN
chmod 0755 "$APPDIR/AppRun"

if [[ ! -x "$APPIMAGETOOL" ]]; then
  command -v curl >/dev/null 2>&1 || {
    printf '%s\n' 'curl is required to download appimagetool.' >&2
    exit 1
  }
  mkdir -p "$(dirname "$APPIMAGETOOL")"
  printf 'Downloading appimagetool from %s\n' "$APPIMAGETOOL_URL"
  curl --fail --location --retry 3 --output "$APPIMAGETOOL" "$APPIMAGETOOL_URL"
  chmod 0755 "$APPIMAGETOOL"
fi

rm -f "$APPIMAGE_OUTPUT"
mkdir -p "$(dirname "$APPIMAGE_OUTPUT")"
ARCH="$ARCH" APPIMAGE_EXTRACT_AND_RUN=1 \
  "$APPIMAGETOOL" "$APPDIR" "$APPIMAGE_OUTPUT"
chmod 0755 "$APPIMAGE_OUTPUT"

printf '\nBuild complete. Single-file AppImage: %s\n' "$APPIMAGE_OUTPUT"
