from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .models import BackupState, DiscoveryState, ExclusionOrigin, SelectionPolicy
from .profiles import (
    ExcludeRule, SYSTEM_HARD_ROOTS,
    is_system_hard_path, matches_resticish,
)


HARD_SYSTEM_ROOTS = SYSTEM_HARD_ROOTS
DEFAULT_PRECONFIGURED_PATHS = ("/tmp", "/var/tmp", "/etc", "/boot", "/boot/efi")


FILESYSTEM_STATUS_PRIORITY = {
    BackupState.PENDING: 0,
    BackupState.REVIEW_REQUIRED: 1,
    BackupState.BACKED_UP_NOW: 2,
    BackupState.BACKED_UP: 3,
    BackupState.NOT_SELECTED: 4,
    BackupState.PRECONFIGURED_EXCLUDED: 5,
    BackupState.MANUALLY_EXCLUDED: 6,
    BackupState.SYSTEM_EXCLUDED: 7,
    BackupState.EXCLUDED: 8,
}


def filesystem_order_key(state: BackupState, size: int | None, name: str) -> tuple[int, int, str]:
    """Stable ncdu-like ordering: status, descending size, alphabetic name."""
    numeric_size = int(size) if size is not None else -1
    return (FILESYSTEM_STATUS_PRIORITY.get(state, 99), -numeric_size, str(name).casefold())


def _contains(root: str, path: str) -> bool:
    root = root.rstrip("/") or "/"
    if root == "/":
        return path.startswith("/")
    return path == root or path.startswith(root + "/")


def _ancestors(path: str) -> list[str]:
    current = Path(path)
    result = [str(current)]
    result.extend(str(parent) for parent in current.parents)
    return result


@dataclass(frozen=True, slots=True)
class EffectiveDecision:
    path: str
    explicit_policy: SelectionPolicy
    selected: bool
    recursive: bool
    exclusion_origin: ExclusionOrigin
    backup_state: BackupState
    discovery_state: DiscoveryState
    reason: str = ""


def apply_rule_overrides(
    rules: Iterable[ExcludeRule],
    recursive_roots: Iterable[str],
    exact_paths: Iterable[str] = (),
) -> list[ExcludeRule]:
    """Return Restic rules with explicit user overrides in safe order.

    Restic negative exclude patterns use last-match-wins semantics. An override
    is emitted immediately after the rule it cancels so a later, more-specific
    exclusion still wins. Recursive directory policy re-includes the subtree;
    exact policy re-includes only that path.
    """
    recursive = tuple(dict.fromkeys(str(Path(root)) for root in recursive_roots))
    exact = tuple(dict.fromkeys(str(Path(path)) for path in exact_paths))
    output: list[ExcludeRule] = []
    for rule in rules:
        output.append(rule)
        for root in recursive:
            if matches_resticish(root, rule.pattern):
                output.append(
                    ExcludeRule(
                        "!" + root.rstrip("/") + "/**",
                        "User override",
                        f"Explicit recursive inclusion overrides {rule.pattern}",
                        True,
                    )
                )
        for path in exact:
            if matches_resticish(path, rule.pattern):
                output.append(
                    ExcludeRule(
                        "!" + path,
                        "User override",
                        f"Explicit inclusion overrides {rule.pattern}",
                        True,
                    )
                )
    return output


def apply_recursive_rule_overrides(
    rules: Iterable[ExcludeRule], recursive_roots: Iterable[str]
) -> list[ExcludeRule]:
    """Backward-compatible wrapper for callers that only have recursive roots."""
    return apply_rule_overrides(rules, recursive_roots)


def review_watch_directories(
    policies: Iterable[tuple[str, SelectionPolicy]], *, backup_root: str
) -> list[str]:
    """Return the minimal ancestor frontier for new-unselected detection.

    Explicitly selected paths create selected islands inside otherwise default
    ancestors.  Only those ancestors need one-level directory inspection to
    discover new siblings that require review; recursively walking selected
    subtrees would be wasted work because future descendants are included
    automatically.
    """
    backup = str(Path(backup_root))
    watched: set[str] = set()
    for path, policy in policies:
        if policy not in {SelectionPolicy.INCLUDE, SelectionPolicy.INCLUDE_RECURSIVE}:
            continue
        for parent in Path(path).parents:
            value = str(parent)
            if _contains(backup, value) or any(_contains(root, value) for root in HARD_SYSTEM_ROOTS):
                continue
            watched.add(value)
    return sorted(watched, key=lambda value: (len(Path(value).parts), value))


def checkbox_selection_policy(
    *, checked: bool, is_dir: bool, was_selected: bool, subtree_selected: bool = False,
    existing_policy: SelectionPolicy = SelectionPolicy.DEFAULT,
) -> SelectionPolicy:
    """Translate an explicit checkbox action into persistent path policy.

    A directory check is recursive by design. Unchecking something that was
    effectively selected is a durable manual exclusion, including when the
    selection was inherited from an ancestor. A partially checked directory
    can itself resolve as unselected while containing explicitly selected
    descendants; unchecking that subtree is also an explicit exclusion.
    """
    if checked:
        return SelectionPolicy.INCLUDE_RECURSIVE if is_dir else SelectionPolicy.INCLUDE
    # Once the user has explicitly bookmarked a manual exclusion, an
    # unchecked presentation event must never erase it.  It changes only on
    # an explicit include/check or ``Clear policy`` action.  This also makes
    # the model robust against harmless programmatic checkbox refreshes
    # emitted while a parent is being browsed/recalculated.
    if existing_policy is SelectionPolicy.EXCLUDE:
        return SelectionPolicy.EXCLUDE
    return SelectionPolicy.EXCLUDE if was_selected or subtree_selected else SelectionPolicy.DEFAULT


def complete_directory_size(child_sizes: Iterable[int | None]) -> int | None:
    """Return a parent Size only when every direct child contribution is exact.

    ``None`` is a deliberate "not enough information" result.  Callers can
    therefore avoid both recursive rescans and arithmetic guesses: once every
    expanded child has an exact Cached/Calculated contribution, the parent is
    simply their sum.
    """
    total = 0
    for size in child_sizes:
        if size is None:
            return None
        total += max(0, int(size))
    return total


def aggregate_directory_backup_state(
    own_state: BackupState, child_states: Iterable[BackupState],
) -> BackupState:
    """Summarize a fully visible directory without changing its policy.

    A default/unselected directory can still be a useful aggregate container
    for explicitly managed descendants.  If every visible child is managed,
    surface the strongest actionable descendant state instead of the
    misleading ``Not selected`` label.  Any unmanaged child keeps the parent
    ``Not selected``; review always propagates.  Explicit/effective state on
    the directory itself remains authoritative.
    """
    states = tuple(child_states)
    if BackupState.REVIEW_REQUIRED in states:
        return BackupState.REVIEW_REQUIRED
    if own_state is not BackupState.NOT_SELECTED or not states:
        return own_state
    if BackupState.NOT_SELECTED in states:
        return own_state

    priority = (
        BackupState.PENDING,
        BackupState.BACKED_UP_NOW,
        BackupState.BACKED_UP,
        BackupState.PRECONFIGURED_EXCLUDED,
        BackupState.MANUALLY_EXCLUDED,
        BackupState.SYSTEM_EXCLUDED,
        BackupState.EXCLUDED,
    )
    for candidate in priority:
        if candidate in states:
            return candidate
    return own_state


def review_ancestor_paths(new_paths: Iterable[str]) -> set[str]:
    """Propagate concrete review candidates to their visible ancestors."""
    result: set[str] = set()
    for path in new_paths:
        value = str(Path(path))
        result.add(value)
        result.update(str(parent) for parent in Path(value).parents)
    return result


class SelectionResolver:
    """Central policy resolver shared by tree rendering and Restic planning."""

    def __init__(
        self,
        *,
        backup_root: str,
        policy_lookup: Callable[[str], SelectionPolicy],
        enabled_rules: Iterable[ExcludeRule],
        is_known: Callable[[str], bool],
        has_previous_snapshot: bool,
        previous_sources: Iterable[str] = (),
    ) -> None:
        self.backup_root = str(Path(backup_root))
        self.policy_lookup = policy_lookup
        self.rules = tuple(enabled_rules)
        self.is_known = is_known
        self.has_previous_snapshot = has_previous_snapshot
        self.previous_sources = tuple(previous_sources)

    def _hard_origin(self, path: str) -> ExclusionOrigin:
        if _contains(self.backup_root, path):
            return ExclusionOrigin.BACKUP_ROOT
        if is_system_hard_path(path):
            return ExclusionOrigin.SYSTEM
        return ExclusionOrigin.NONE

    def _manual_exclusion(self, path: str) -> str | None:
        for candidate in _ancestors(path):
            if self.policy_lookup(candidate) is SelectionPolicy.EXCLUDE:
                return candidate
        return None

    def _recursive_inclusion(self, path: str) -> str | None:
        for candidate in _ancestors(path):
            if self.policy_lookup(candidate) is SelectionPolicy.INCLUDE_RECURSIVE:
                return candidate
        return None

    def _preconfigured_reason(self, path: str, *, override_root: str | None = None) -> str | None:
        # A recursive inclusion explicitly placed on a path that is itself
        # preconfigured-excluded overrides that *same* rule for its subtree.
        # It does not suppress unrelated nested rules (for example /boot may
        # be included while a nested node_modules remains excluded).
        for rule in self.rules:
            if not matches_resticish(path, rule.pattern):
                continue
            if override_root and matches_resticish(override_root, rule.pattern):
                continue
            return rule.reason
        return None

    def resolve(self, path: str, *, is_dir: bool = False) -> EffectiveDecision:
        path = str(Path(path))
        explicit = self.policy_lookup(path)
        hard = self._hard_origin(path)
        if hard is not ExclusionOrigin.NONE:
            state = BackupState.SYSTEM_EXCLUDED
            return EffectiveDecision(path, explicit, False, False, hard, state, DiscoveryState.KNOWN, "Hard system exclusion")

        manual = self._manual_exclusion(path)
        if manual is not None:
            return EffectiveDecision(
                path, explicit, False, False, ExclusionOrigin.MANUAL,
                BackupState.MANUALLY_EXCLUDED, DiscoveryState.KNOWN,
                f"Excluded by explicit policy on {manual}",
            )

        # Exact inclusion defeats a preconfigured rule for that exact source.
        # Explicit recursive inclusion also overrides the rule that matched
        # the recursively included root, while unrelated nested exclusions
        # still apply.  Manual/hard exclusions above remain stronger.
        exact_included = explicit in {SelectionPolicy.INCLUDE, SelectionPolicy.INCLUDE_RECURSIVE}
        recursive_from = self._recursive_inclusion(path)
        override_root = recursive_from if recursive_from and self._preconfigured_reason(recursive_from) else None
        preconfigured = None if exact_included else self._preconfigured_reason(path, override_root=override_root)
        if preconfigured is not None:
            return EffectiveDecision(
                path, explicit, False, False, ExclusionOrigin.PRECONFIGURED,
                BackupState.PRECONFIGURED_EXCLUDED, DiscoveryState.KNOWN, preconfigured,
            )

        known = self.is_known(path)
        selected = exact_included or recursive_from is not None
        recursive = explicit is SelectionPolicy.INCLUDE_RECURSIVE or (
            recursive_from is not None and recursive_from != path
        )
        discovery = DiscoveryState.KNOWN
        if self.has_previous_snapshot and not known and not selected:
            discovery = DiscoveryState.NEW_UNSELECTED
        if discovery is DiscoveryState.NEW_UNSELECTED:
            state = BackupState.REVIEW_REQUIRED
        elif selected:
            if self.has_previous_snapshot and not known:
                state = BackupState.PENDING
            elif any(_contains(source, path) for source in self.previous_sources):
                state = BackupState.BACKED_UP
            else:
                state = BackupState.PENDING
        else:
            state = BackupState.NOT_SELECTED
        return EffectiveDecision(path, explicit, selected, recursive, ExclusionOrigin.NONE, state, discovery)

    def is_hard_excluded(self, path: str) -> bool:
        return self._hard_origin(str(Path(path))) is not ExclusionOrigin.NONE
