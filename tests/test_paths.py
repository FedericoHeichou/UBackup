from dataclasses import fields
from pathlib import Path

from ubackup.paths import AppPaths, GuiPaths


def test_paths_are_below_root(tmp_path):
    p = AppPaths.create(tmp_path / "backup")
    for field in fields(AppPaths):
        value = getattr(p, field.name)
        if isinstance(value, Path):
            assert p.root == value or p.root in value.parents


def test_gui_environment_retains_inherited_runtime_dir(tmp_path):
    paths = GuiPaths.for_user(tmp_path / "backup", 1000)

    env = paths.prepare_environment({"XDG_RUNTIME_DIR": "/run/user/1000"})

    assert env["XDG_RUNTIME_DIR"] == "/run/user/1000"


def test_gui_environment_uses_private_runtime_dir_when_absent(tmp_path):
    paths = GuiPaths.for_user(tmp_path / "backup", 1000)

    env = paths.prepare_environment({})

    assert env["XDG_RUNTIME_DIR"] == str(paths.runtime)


def test_backup_domains_have_independent_repositories_and_state(tmp_path):
    from ubackup.paths import PrivilegedPaths

    base = PrivilegedPaths.for_root(tmp_path / "backup")
    domains = {name: base.for_component(name) for name in ("filesystem", "configs", "packages")}
    assert len({paths.repository for paths in domains.values()}) == 3
    assert domains["filesystem"].repository == base.root / "repositories" / "filesystem"
    assert domains["configs"].repository == base.root / "repositories" / "configs"
    assert domains["packages"].repository == base.root / "repositories" / "packages"
    assert domains["configs"].manifest_file == base.root / ".ubackup" / "state" / "configs" / "current" / "manifest.json"
    assert len({paths.lock_file for paths in domains.values()}) == 3
