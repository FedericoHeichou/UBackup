#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ ! -d .venv-build ]]; then
  python3 -m venv .venv-build
fi
source .venv-build/bin/activate
python -m pip install --upgrade pip
python -m pip install 'PySide6>=6.8,<7'
export PYTHONPATH="$ROOT/src"

# Generate the official Qt for Python deployment spec, then force standalone mode.
# Standalone is intentional: Nuitka onefile extracts itself to a temporary directory
# before Python can parse --backup-root, which would violate UBackup's runtime write policy.
pyside6-deploy "$ROOT/main.py" --name UBackup --force --init
python - <<'PY2'
from configparser import ConfigParser
from pathlib import Path
p=Path('pysidedeploy.spec')
c=ConfigParser(interpolation=None)
c.optionxform=str
c.read(p)
if not c.has_section('nuitka'):
    c.add_section('nuitka')
c.set('nuitka','mode','standalone')
if c.has_section('app'):
    c.set('app','exec_directory', str(Path('dist').resolve()))
with p.open('w') as f:
    c.write(f)
PY2
mkdir -p dist
pyside6-deploy -c "$ROOT/pysidedeploy.spec" --force
printf '\nBuild complete. Portable standalone output is under %s/dist.\n' "$ROOT"
