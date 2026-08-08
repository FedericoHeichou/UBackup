from __future__ import annotations

import sqlite3
from pathlib import Path

from ubackup.cache import CacheDB
from ubackup.models import BackupState, ExclusionOrigin, SelectionPolicy
from ubackup.profiles import ExcludeRule
from ubackup.selection import SelectionResolver


def resolver(tmp_path: Path, policies: dict[str, SelectionPolicy], *, known=(), previous=True, rules=()):
    return SelectionResolver(
        backup_root=str(tmp_path / "backup"),
        policy_lookup=lambda path: policies.get(path, SelectionPolicy.DEFAULT),
        enabled_rules=rules,
        is_known=lambda path: path in set(known),
        has_previous_snapshot=previous,
        previous_sources=["/home"],
    )


def test_policy_precedence_and_recursive_discovery(tmp_path):
    rules = [ExcludeRule("**/node_modules/**", "Node.js", "reinstallable")]
    policies = {"/home/u/Projects": SelectionPolicy.INCLUDE_RECURSIVE}
    r = resolver(tmp_path, policies, known={"/home/u/Projects"}, rules=rules)

    new_project = r.resolve("/home/u/Projects/new")
    assert new_project.selected and new_project.backup_state is BackupState.PENDING

    cache = r.resolve("/home/u/Projects/new/node_modules")
    assert not cache.selected
    assert cache.exclusion_origin is ExclusionOrigin.PRECONFIGURED

    policies["/home/u/Projects/new/node_modules"] = SelectionPolicy.INCLUDE_RECURSIVE
    overridden = r.resolve("/home/u/Projects/new/node_modules/pkg")
    assert overridden.selected
    assert overridden.exclusion_origin is ExclusionOrigin.NONE


def test_manual_and_hard_exclusions_win(tmp_path):
    policies = {
        "/home": SelectionPolicy.INCLUDE_RECURSIVE,
        "/home/u/private": SelectionPolicy.EXCLUDE,
        "/home/u/private/keep": SelectionPolicy.INCLUDE_RECURSIVE,
        "/proc": SelectionPolicy.INCLUDE_RECURSIVE,
    }
    r = resolver(tmp_path, policies, known={"/home", "/home/u/private", "/home/u/private/keep"}, rules=())
    assert r.resolve("/home/u/private/keep/file").backup_state is BackupState.MANUALLY_EXCLUDED
    assert r.resolve("/proc/cpuinfo").backup_state is BackupState.SYSTEM_EXCLUDED
    assert r.resolve(str(tmp_path / "backup" / "repository")).backup_state is BackupState.SYSTEM_EXCLUDED


def test_new_unselected_content_is_review_required(tmp_path):
    r = resolver(tmp_path, {}, known={"/home/u/old"}, previous=True, rules=())
    assert r.resolve("/home/u/new").backup_state is BackupState.REVIEW_REQUIRED
    assert r.resolve("/home/u/new").selected is False


def test_default_tmp_rule_excludes_tmp_file_inside_recursive_selection(tmp_path):
    from ubackup.profiles import DEFAULT_RULES

    policies = {"/home": SelectionPolicy.INCLUDE_RECURSIVE}
    r = resolver(tmp_path, policies, previous=False, rules=DEFAULT_RULES)
    result = r.resolve("/home/user/archive.tmp", is_dir=False)

    assert result.selected is False
    assert result.exclusion_origin is ExclusionOrigin.PRECONFIGURED
    assert result.backup_state is BackupState.PRECONFIGURED_EXCLUDED


def test_preconfigured_rule_can_be_disabled_or_explicitly_overridden(tmp_path):
    rule = ExcludeRule("/tmp/**", "System", "temporary")
    excluded = resolver(tmp_path, {}, previous=False, rules=[rule]).resolve("/tmp")
    assert excluded.backup_state is BackupState.PRECONFIGURED_EXCLUDED

    no_rule = resolver(tmp_path, {}, previous=False, rules=[]).resolve("/tmp")
    assert no_rule.backup_state is BackupState.NOT_SELECTED

    included = resolver(tmp_path, {"/tmp": SelectionPolicy.INCLUDE_RECURSIVE}, previous=False, rules=[rule]).resolve("/tmp/a")
    assert included.selected


def test_legacy_boolean_source_selections_migrate_deterministically(tmp_path):
    db_path = tmp_path / "cache.sqlite3"
    con = sqlite3.connect(db_path)
    con.execute("CREATE TABLE selections(kind TEXT NOT NULL, key TEXT NOT NULL, selected INTEGER NOT NULL, PRIMARY KEY(kind,key))")
    con.execute("INSERT INTO selections(kind,key,selected) VALUES('source','/home',1)")
    con.execute("INSERT INTO selections(kind,key,selected) VALUES('source','/home/u/skip',0)")
    con.commit(); con.close()

    cache = CacheDB(db_path)
    try:
        assert cache.get_path_policy("/home") is SelectionPolicy.INCLUDE_RECURSIVE
        assert cache.get_path_policy("/home/u/skip") is SelectionPolicy.EXCLUDE
        cache.set_path_policy("/home/u/missing", SelectionPolicy.EXCLUDE)
        assert cache.get_path_policy("/home/u/missing") is SelectionPolicy.EXCLUDE
    finally:
        cache.close()


def test_recursive_rule_override_preserves_later_nested_exclusion():
    from ubackup.profiles import ExcludeRule
    from ubackup.selection import apply_recursive_rule_overrides

    rules = [
        ExcludeRule("/boot/**", "System", "boot"),
        ExcludeRule("/boot/efi/**", "System", "efi"),
    ]
    effective = apply_recursive_rule_overrides(rules, ["/boot"])
    assert [rule.pattern for rule in effective] == [
        "/boot/**",
        "!/boot/**",
        "/boot/efi/**",
    ]


def test_known_path_can_be_scoped_to_last_snapshot(tmp_path):
    from ubackup.cache import CacheDB

    cache = CacheDB(tmp_path / "cache.sqlite3")
    try:
        cache.mark_paths_known(["/home/user/old"], "snapshot-a")
        assert cache.is_known_path("/home/user/old", "snapshot-a")
        assert not cache.is_known_path("/home/user/old", "snapshot-b")
        cache.mark_paths_known(["/home/user/old"], "snapshot-b")
        assert cache.is_known_path("/home/user/old", "snapshot-b")
    finally:
        cache.close()


def test_exact_file_include_overrides_preconfigured_rule_without_reincluding_subtree():
    from ubackup.selection import apply_rule_overrides

    rules = [
        ExcludeRule("**/node_modules/**", "Node.js", "dependencies"),
        ExcludeRule("**/node_modules/cache/**", "Node.js", "nested cache"),
    ]
    effective = apply_rule_overrides(
        rules, [], ["/home/u/p/node_modules/keep.txt"]
    )
    assert [rule.pattern for rule in effective] == [
        "**/node_modules/**",
        "!/home/u/p/node_modules/keep.txt",
        "**/node_modules/cache/**",
    ]


def test_review_frontier_scans_selected_island_ancestors_without_recursive_crawl(tmp_path):
    from ubackup.selection import review_ancestor_paths, review_watch_directories

    policies = [
        ("/home/u/Projects", SelectionPolicy.INCLUDE_RECURSIVE),
        ("/home/u/Documents/keep.txt", SelectionPolicy.INCLUDE),
        ("/home/u/Projects/private", SelectionPolicy.EXCLUDE),
    ]
    watched = review_watch_directories(policies, backup_root=str(tmp_path / "backup"))
    assert "/" in watched
    assert "/home" in watched
    assert "/home/u" in watched
    assert "/home/u/Documents" in watched
    assert "/home/u/Projects" not in watched

    propagated = review_ancestor_paths(["/home/u/Documents/new.txt"])
    assert {"/", "/home", "/home/u", "/home/u/Documents", "/home/u/Documents/new.txt"} <= propagated


def test_recursive_folder_selection_adopts_future_descendants(tmp_path):
    policies = {"/home/u/Projects": SelectionPolicy.INCLUDE_RECURSIVE}
    r = SelectionResolver(
        backup_root=str(tmp_path / "backup"),
        policy_lookup=lambda path: policies.get(path, SelectionPolicy.DEFAULT),
        enabled_rules=(),
        is_known=lambda _path: False,
        has_previous_snapshot=True,
        previous_sources=["/home/u/Projects"],
    )
    new = r.resolve("/home/u/Projects/new.txt")
    assert new.selected
    assert new.backup_state is BackupState.PENDING


def test_fixed_selection_cache_migrates_folder_to_recursive_policy(tmp_path):
    db = tmp_path / "cache.sqlite3"
    cache = CacheDB(db)
    cache.set_path_policy("/home/u/Projects", SelectionPolicy.INCLUDE)
    cache.replace_fixed_selection(
        "/home/u/Projects",
        [("/home/u/Projects", True), ("/home/u/Projects/file.txt", False)],
    )
    cache.close()

    reopened = CacheDB(db)
    try:
        assert reopened.get_path_policy("/home/u/Projects") is SelectionPolicy.INCLUDE_RECURSIVE
        assert not reopened.has_fixed_selection("/home/u/Projects")
    finally:
        reopened.close()


def test_recursive_folder_override_of_broad_rule_keeps_nested_rules(tmp_path):
    policies = {"/etc": SelectionPolicy.INCLUDE_RECURSIVE}
    rules = [
        ExcludeRule("/etc/**", "Configuration", "use curated configs"),
        ExcludeRule("/etc/private/**", "Test", "nested rule"),
    ]
    r = SelectionResolver(
        backup_root=str(tmp_path / "backup"),
        policy_lookup=lambda path: policies.get(path, SelectionPolicy.DEFAULT),
        enabled_rules=rules,
        is_known=lambda _path: False,
        has_previous_snapshot=False,
    )
    assert r.resolve("/etc/ssh/sshd_config").selected
    assert r.resolve("/etc/later.conf").selected
    assert not r.resolve("/etc/private/secret").selected


def test_filesystem_order_prioritizes_pending_then_size_then_name():
    from ubackup.selection import filesystem_order_key

    rows = [
        (BackupState.BACKED_UP, 999, "zeta"),
        (BackupState.PENDING, 10, "beta"),
        (BackupState.PENDING, 100, "zeta"),
        (BackupState.PENDING, 100, "alpha"),
        (BackupState.NOT_SELECTED, 10000, "huge"),
    ]
    ordered = sorted(rows, key=lambda row: filesystem_order_key(*row))
    assert ordered[:3] == [
        (BackupState.PENDING, 100, "alpha"),
        (BackupState.PENDING, 100, "zeta"),
        (BackupState.PENDING, 10, "beta"),
    ]
    assert ordered[3][0] is BackupState.BACKED_UP


def test_cache_close_is_idempotent(tmp_path):
    from ubackup.cache import CacheDB

    cache = CacheDB(tmp_path / "close.sqlite3")
    cache.close()
    cache.close()


def test_unchecking_effectively_selected_item_creates_manual_exclusion():
    from ubackup.selection import checkbox_selection_policy

    assert checkbox_selection_policy(checked=False, is_dir=True, was_selected=True) is SelectionPolicy.EXCLUDE
    assert checkbox_selection_policy(checked=False, is_dir=False, was_selected=True) is SelectionPolicy.EXCLUDE
    assert checkbox_selection_policy(checked=False, is_dir=True, was_selected=False) is SelectionPolicy.DEFAULT
    assert checkbox_selection_policy(
        checked=False, is_dir=True, was_selected=False, subtree_selected=True
    ) is SelectionPolicy.EXCLUDE
    assert checkbox_selection_policy(checked=True, is_dir=True, was_selected=False) is SelectionPolicy.INCLUDE_RECURSIVE
    assert checkbox_selection_policy(checked=True, is_dir=False, was_selected=False) is SelectionPolicy.INCLUDE


def test_existing_manual_exclusion_survives_repeated_unchecked_refresh():
    from ubackup.selection import checkbox_selection_policy

    assert checkbox_selection_policy(
        checked=False,
        is_dir=True,
        was_selected=False,
        subtree_selected=False,
        existing_policy=SelectionPolicy.EXCLUDE,
    ) is SelectionPolicy.EXCLUDE


def test_managed_children_promote_default_directory_status():
    from ubackup.selection import aggregate_directory_backup_state

    assert aggregate_directory_backup_state(
        BackupState.NOT_SELECTED,
        [BackupState.MANUALLY_EXCLUDED, BackupState.PENDING],
    ) is BackupState.PENDING
    assert aggregate_directory_backup_state(
        BackupState.NOT_SELECTED,
        [BackupState.MANUALLY_EXCLUDED, BackupState.BACKED_UP],
    ) is BackupState.BACKED_UP
    assert aggregate_directory_backup_state(
        BackupState.NOT_SELECTED,
        [BackupState.MANUALLY_EXCLUDED, BackupState.NOT_SELECTED],
    ) is BackupState.NOT_SELECTED
    assert aggregate_directory_backup_state(
        BackupState.MANUALLY_EXCLUDED,
        [BackupState.PENDING],
    ) is BackupState.MANUALLY_EXCLUDED


def test_complete_directory_size_requires_all_children_and_sums_exact_values():
    from ubackup.selection import complete_directory_size

    assert complete_directory_size([120, 0, 80]) == 200
    assert complete_directory_size([]) == 0
    assert complete_directory_size([120, None, 80]) is None


def test_known_paths_for_returns_only_requested_snapshot_rows(tmp_path):
    cache = CacheDB(tmp_path / "known-paths.sqlite3")
    try:
        cache.mark_paths_known((f"/data/{index}" for index in range(900)), "snap-a")
        cache.mark_paths_known(["/data/899"], "snap-b")

        requested = [f"/data/{index}" for index in range(0, 900, 2)]
        known = cache.known_paths_for(requested, "snap-a")

        assert "/data/0" in known
        assert "/data/898" in known
        assert "/data/899" not in known
        assert len(known) == 450
        assert cache.known_paths_for(requested, "snap-b") == set()
    finally:
        cache.close()


def test_manual_exclusion_survives_cache_close_and_reopen_under_recursive_home(tmp_path):
    """A user EXCLUDE is durable policy, not transient tree presentation state."""
    db = tmp_path / "persistent-manual-exclude.sqlite3"
    cache = CacheDB(db)
    cache.set_path_policy("/home", SelectionPolicy.INCLUDE_RECURSIVE)
    cache.set_path_policy("/home/federico/.steam", SelectionPolicy.EXCLUDE)
    cache.close()

    reopened = CacheDB(db)
    try:
        assert reopened.get_path_policy("/home") is SelectionPolicy.INCLUDE_RECURSIVE
        assert reopened.get_path_policy("/home/federico/.steam") is SelectionPolicy.EXCLUDE
        policies = dict(reopened.path_policy_rows())
        resolver_after_restart = SelectionResolver(
            backup_root=str(tmp_path / "backup"),
            policy_lookup=lambda path: policies.get(str(Path(path)), SelectionPolicy.DEFAULT),
            enabled_rules=(),
            is_known=lambda _path: False,
            has_previous_snapshot=False,
        )
        decision = resolver_after_restart.resolve("/home/federico/.steam", is_dir=True)
        assert decision.selected is False
        assert decision.backup_state is BackupState.MANUALLY_EXCLUDED
    finally:
        reopened.close()
