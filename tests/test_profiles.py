from pathlib import Path

from ubackup.profiles import DEFAULT_RULES, matches_resticish


def test_steam_saves_not_default_excluded():
    enabled = [r.pattern for r in DEFAULT_RULES if r.default_enabled]
    assert not any("userdata" in x for x in enabled)
    assert not any("compatdata" in x for x in enabled)


def test_steam_common_matches():
    p = "/home/u/.local/share/Steam/steamapps/common/Game/foo.bin"
    rule = next(r for r in DEFAULT_RULES if ".local/share/Steam/steamapps/common" in r.pattern)
    assert matches_resticish(p, rule.pattern)


def test_etc_is_a_default_preconfigured_exclusion():
    from ubackup.profiles import DEFAULT_RULES
    rule = next(rule for rule in DEFAULT_RULES if rule.pattern == "/etc/**")
    assert rule.default_enabled is True
    assert "/etc Configuration" in rule.reason
    assert "non-default/customized" in rule.reason


def test_swapfile_is_a_hard_system_exclusion():
    from ubackup.profiles import is_system_hard_path, system_hard_exclude_patterns
    assert is_system_hard_path("/swapfile")
    assert "/swapfile" in system_hard_exclude_patterns()


def test_usrmerge_alias_is_hard_excluded_only_when_it_is_a_symlink(monkeypatch):
    from ubackup import profiles

    original = Path.is_symlink

    def fake_is_symlink(path):
        value = str(path)
        if value == "/bin":
            return True
        if value == "/lib32":
            return False
        return original(path)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
    assert profiles.is_system_hard_path("/bin")
    assert profiles.is_system_hard_path("/bin/tool")
    assert not profiles.is_system_hard_path("/lib32")
    assert "/bin" in profiles.system_hard_exclude_patterns()
    assert "/lib32" not in profiles.system_hard_exclude_patterns()


def test_tmp_files_are_default_preconfigured_exclusions():
    rule = next(rule for rule in DEFAULT_RULES if rule.pattern == "*.tmp")
    assert rule.default_enabled is True
    assert matches_resticish("/home/user/download.part.tmp", rule.pattern)
    assert matches_resticish("/var/lib/app/cache.tmp", rule.pattern)
    assert not matches_resticish("/home/user/tmp.txt", rule.pattern)
