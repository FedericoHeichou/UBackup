# AGENTS.md — UBackup engineering guide

This document is for AI coding agents and maintainers working on UBackup. It describes the project's stable architecture, security boundaries, behavioral contracts and testing expectations without depending on fragile line numbers or exact implementation details.

## 1. Product intent

UBackup is a curated Ubuntu desktop backup and restore application built around Restic. It is not a block-level imaging tool and should not become a blind root-filesystem mirror.

The application optimizes for reconstructibility:

- preserve user data that is hard or impossible to recreate;
- exclude generated/reinstallable data by default;
- record software/package state so software can be reinstalled normally;
- preserve selected system configuration rather than copying all defaults;
- version the restore plan in the same Restic snapshot as the corresponding data;
- make backup and restore policy visible and user-controlled.

The key product principle is: **back up irreplaceable state; describe reconstructible state; never silently overwrite a new OS installation with broad old defaults.**

## 2. Non-negotiable security architecture

### 2.1 The GUI is never root

The PySide6 process must run as the logged-in desktop user and should actively reject effective UID 0. Do not reintroduce a `sudo`/`sudo -E` GUI launch path.

Reasons include both security and desktop correctness: Wayland, DBus, portals, themes, clipboard, notifications, keyrings and XDG state all belong to the user session.

### 2.2 One Polkit authorization at startup

The production GUI starts one fixed root-owned helper through Polkit/`pkexec` during application startup. Polkit authentication may be shown at that point.

After authorization, that same helper process remains alive for the GUI session and accepts a bounded, typed request protocol over inherited private pipes. Normal GUI operations must reuse that session. Do not invoke `pkexec` again for ordinary browse, inspect, backup, restore or package-manager operations.

If the privileged session dies, fail the operation and surface the error. Do not silently fall back to a fresh privileged launch because that both changes the security model and creates repeated password prompts.

Standalone operation-specific helpers may remain available for maintenance/tests, but they are not the normal GUI route.

### 2.3 The privileged helper is not a root shell

Never add an RPC such as `run_command`, `run_argv`, `execute`, or any equivalent that lets the GUI choose an executable or shell fragment.

The root boundary exposes only purpose-specific operations, conceptually:

- protected inspection;
- backup;
- staging restore;
- in-place restore;
- package restore/install.

Every request must be parsed as strict structured data and validated again in the privileged process. Security-sensitive values include backup roots, filesystem paths, snapshot IDs, package names, include lists, configuration paths and credentials.

Do not trust input merely because it originated from UBackup's own GUI.

### 2.4 Installed privileged code is trusted code

Privileged Python modules and libexec launchers are installed root-owned in system locations. The installer intentionally uses an explicit source manifest instead of recursively copying the application tree.

Maintain these properties:

- installed code and parent directories must not be user/group/world writable;
- reject source symlinks and unexpected privileged inputs;
- standard Python `__pycache__` directories may be ignored, but bytecode must never be installed as privileged source;
- install/verify code before enabling the corresponding Polkit policy;
- fixed libexec launchers must reject arguments unless their protocol explicitly requires otherwise;
- privileged Python should run isolated (`-I`) with bytecode disabled (`-B`) where applicable;
- keep the privileged dependency surface as small as practical.

Do not solve installation problems with permissive modes such as `chmod 777`.

## 3. Credential model

Polkit authentication and the Restic repository password are different credentials.

### Polkit

Polkit authenticates the user once to start the root helper. The authorized helper remains alive, so later privileged requests do not need another Polkit transaction.

### Restic password

The Restic password is supplied once during startup, either interactively or via an existing `--password-file`.

For an interactive secret:

- transmit it only over the private startup session;
- validate/bind it inside the helper;
- after successful startup, discard the GUI's plaintext copy;
- keep it in the helper only for that application session;
- materialize request-private password files only when required by Restic;
- create them with restrictive permissions and remove them after the request.

Never pass passwords in command-line arguments, logs, exception text, world-readable files or arbitrary temporary locations.

## 4. Write-location invariant

During normal browsing, audit, dry-run and backup, UBackup's own writes must stay under the configured backup root. The default is `/backup`.

The root helper owns protected repository/runtime state. The GUI receives a private per-UID leaf under the backup root for its cache, logs and XDG/runtime state.

Explicit in-place restore and package-manager restore are expected exceptions because their purpose is to modify the operating system.

Do not silently write application state to `/tmp`, `/root`, the user's real home directory, or unrelated XDG locations. Libraries/subprocesses that need writable HOME/XDG/temp/cache paths must receive controlled environment values derived from the backup-root path policy.

The fixed default `/backup` may be created automatically by the authenticated helper if absent. Custom backup-root paths must not become a generic root directory-creation primitive; require them to satisfy the project's admission/approval rules.

## 5. Backup-root admission and path security

Treat backup-root admission as a security boundary, not convenience validation.

When operating as root:

- reject unsafe symlinked components according to the admission contract;
- verify owner/mode expectations;
- revalidate before sensitive operations where TOCTOU matters;
- use real path/component-aware logic rather than naive string-prefix checks;
- prevent the repository and helper runtime from becoming selectable backup sources;
- validate restore destinations separately because in-place restore intentionally crosses the backup-root boundary.

Hard system exclusions and backup-root protection are not user-overridable.

## 6. Core data/state model

Do not collapse user policy, effective state and UI rendering into one boolean or one human-readable string.

### 6.1 Persistent selection policy

Filesystem path policy has four semantic values:

- `DEFAULT`: no explicit user decision;
- `INCLUDE`: explicitly include one non-directory path;
- `INCLUDE_RECURSIVE`: directory checkbox semantics; include present and future descendants, subject to stronger exclusions;
- `EXCLUDE`: explicit persistent manual exclusion.

A checked filesystem directory must persist `INCLUDE_RECURSIVE`; there is no frozen-membership capture step. New non-excluded descendants become pending automatically. `INCLUDE` is retained for exact/non-directory selections and serialization compatibility.

A manual exclusion is a bookmark-like user decision. Browsing or expanding a node must never create one. Explicitly unchecking a path that is currently effectively selected, including selection inherited from an ancestor, is itself a deliberate exclusion action and must persist `EXCLUDE`, exactly like the Manual exclude control.

### 6.2 Exclusion origin

Keep exclusion provenance distinct from effective backup state. Important origins include:

- none;
- system/hard;
- preconfigured;
- manual;
- backup-root.

### 6.3 Effective backup state

The effective state is derived from policy, exclusion rules, previous snapshot knowledge and current Restic activity. Examples include:

- not selected;
- system excluded;
- preconfigured excluded;
- manually excluded;
- pending backup;
- backed up;
- backed up in the current operation;
- review required.

### 6.4 Discovery/newness

A path is "new unselected" when it is present in the current scan, absent from the inventory associated with the last successful snapshot, and is not automatically covered by effective recursive inclusion.

This is separate from checkbox state. In the UI it is represented as `Review required` and should propagate to visible ancestors. Detect this proactively with a targeted one-level scan of the ancestor frontier created by explicit inclusions; do not recursively crawl subtrees that are already covered by recursive inclusion merely to discover review state. Paths observed by this frontier belong to the current discovery generation and should be associated with the next successful snapshot.

### 6.5 Checkbox state

Unchecked/checked/partially checked is derived presentation state. Never persist `PARTIALLY_CHECKED` as user policy.

A closed parent should still render partially checked when persistent descendant policies already prove the subtree is mixed, even before the descendant nodes are loaded.

## 7. Selection precedence

Keep policy resolution centralized. The intended precedence is:

1. hard system / backup-root exclusion;
2. explicit manual exclusion (including inherited parent exclusion);
3. exact explicit inclusion;
4. preconfigured exclusion;
5. inherited recursive inclusion;
6. default/unselected.

This has important consequences:

- an explicit include can override a convenience/preconfigured exclusion;
- a manual parent exclusion remains stronger than a descendant include;
- hard exclusions can never be overridden;
- recursive inclusion automatically covers future children;
- nested, more-specific preconfigured rules must remain effective unless explicitly overridden according to the same resolver.

Restic source/exclude generation must consume the resolved domain policy, not widget checkbox values.

## 8. Restic exclude ordering

Restic pattern ordering matters. Negative patterns used to cancel a preconfigured exclusion must be emitted near the rule they override, not blindly appended at the end, because a late broad negation could accidentally defeat a more-specific nested exclusion.

Any change to exclusion generation needs tests for nested rules and explicit overrides.

## 9. Hard and preconfigured filesystem exclusions

Hard, non-traversable roots include at least:

- `/proc`;
- `/sys`;
- `/dev`;
- `/run`;
- the configured backup root and descendants.

They should not be scanned recursively and should render as system exclusions.

Do not classify `/tmp`, `/var/tmp`, `/boot` or `/boot/efi` as pseudo-filesystems. They are preconfigured exclusions and may be overridden by explicit user inclusion. `/boot` can contain custom state.

Development/cache profiles may include Node dependency trees, virtual environments, language build caches, browser caches and similar reconstructible content.

Steam exclusions must be conservative. Shader/download/temp caches are reasonable defaults. Do not automatically exclude `Steam/userdata`, Proton `compatdata`, or all of `steamapps/common`: local saves can exist there.

## 10. `/etc` audit model

Do not add all of `/etc` as a Restic source.

The system audit identifies candidate files from modified package configuration and unmanaged `/etc` files. The GUI builds a virtual expandable `/etc` tree from only those candidate leaves.

Intermediate directories are aggregation nodes. Selecting a virtual `/etc/ssh` node means changing the selection of candidate leaves beneath it; it must never turn the real `/etc/ssh` directory into a broad Restic source.

Configuration candidate type and user selection should be semantic enum/domain values, not rendered strings.

## 11. Package model

The Packages domain is a unified inventory of APT manually marked packages, installed Snaps, and installed Flatpak applications. Dependency payloads themselves are not backed up. Each package record carries a `PackageManager` enum and a stable manager/scope/name policy key. Flatpak records also preserve installation scope, origin, ref, and remote URL when available.

The packages Restic repository is one history, but each snapshot stores manager-specific metadata files (`packages-apt.json`, `packages-snap.json`, `packages-flatpak.json`). The GUI combines them into one table with a Package manager column. `apt-clone` is compatibility/export tooling, not another manager.

Package restore must validate every requested manager/scope/name selector against metadata stored in the chosen snapshot before invoking any package manager. APT restore uses `apt-get`; Snap uses `snap`; Flatpak uses `flatpak`. Per-user Flatpak commands must run as the recorded desktop user rather than root, while system/custom installations remain privileged. Never construct shell strings; use explicit argv and validated metadata.

Dry-run package restore must be non-mutating. APT may use its simulation mode, Snap may use read-only package information checks, and Flatpak may use configured-remote inspection or report that a recorded remote would need to be recreated.

## 12. Snapshot-consistent metadata

Package/config/source policy and system inventory describe a specific backup generation. Keep them versioned inside the same Restic snapshot as the data.

The local SQLite database is operational cache/policy state, not the historical source of truth for old snapshots.

Snapshot metadata should remain simple, versioned and forward-compatible. Restore views should read the metadata from the selected snapshot, not from current machine state.

## 13. Cache behavior

Expensive filesystem and system scans should be cached whenever correctness permits.
Filesystem size scans must report global cumulative bytes/items for the requested root and throttle progress transport; subtree-local counters must never be presented as task-level progress. Directory expansion should list/render children before an expensive recursive size scan begins, and a fresh exclusion-profile-aware size cache must suppress redundant scans.


Cache and persistent user policy are different layers:

- a refreshed inventory must not resurrect stale checkbox values;
- path policies survive temporary disappearance of the path;
- a reappearing path is evaluated against the last successful snapshot's inventory for discovery/newness;
- cache invalidation should be targeted instead of forcing full rescans on every navigation.

Filesystem size caching may use stable metadata such as inode/device/mtime as a pragmatic invalidation signal. The cache is an optimization; Restic remains authoritative for snapshot contents.

## 14. Background execution and progress

Never block the Qt event loop with filesystem scans, Restic, package inspection or restore work.

Use the project's worker/task abstraction. Tasks should expose, where meaningful:

- semantic task state;
- start/elapsed time;
- current item or operation;
- items processed;
- bytes processed;
- percentage only when it is genuinely measurable;
- errors/warnings.

The privileged session supports progress frames on the same authenticated IPC request. Use those for protected `/etc` scans, filesystem size scans, Restic backup/restore and other long root operations.

Do not repaint the GUI for every file. Task state may update frequently internally, but UI refresh should be throttled. Restic per-file events may still be used to update already-visible path states where useful.

Design new long-running operations so cancellation can be added without inventing a second IPC protocol.

## 15. IPC invariants

The startup/helper protocol is length-framed strict JSON with bounded request/response sizes and request/session identifiers.

Maintain these properties:

- reject duplicate JSON keys and non-finite values;
- bound frame sizes before allocation/processing;
- validate session ID, request ID and operation on every response/event;
- serialize privileged requests; one root operation runs at a time;
- progress frames and the final response for a request share the same identity;
- on framing timeout/desynchronization, close the session rather than attempting to reuse an ambiguous byte stream;
- closing the GUI/control pipe must be observable by long-running privileged work so child processes can be cancelled/reaped;
- never multiplex arbitrary executable selection into this channel.

Be careful with file-descriptor blocking modes. Temporary nonblocking monitoring must restore the original mode before the descriptor returns to request/response framing.

## 16. Restic integration

Restic is the authoritative storage engine. UBackup should orchestrate, not reimplement, encryption/deduplication/snapshot storage.

Important practices:

- use explicit source lists (`--files-from-verbatim`) and exclude files;
- exclude caches via Restic's cache-marker behavior where appropriate;
- keep the repository itself outside ordinary traversal;
- preserve structured JSON progress;
- allow Restic's partial-snapshot result to be surfaced distinctly;
- distinguish logical processed bytes from repository data added/packed;
- validate snapshot IDs before passing them to Restic;
- keep restore includes explicit and bounded;
- locate UBackup snapshot metadata from Restic snapshot source metadata before considering a recursive snapshot walk; new snapshots use the stable `.ubackup/state/current` metadata path;
- treat snapshot deletion as a privileged destructive operation and re-check that the requested snapshot is still the latest immediately before `forget`;
- remember that Restic has no merge-to-parent operation. `Consolidate history` means keeping the latest complete/covering snapshot and forgetting/pruning compatible older history; refuse partial histories that the latest snapshot does not cover.

The dry-run estimate is useful but not an exact physical-space promise.

## 17. Capacity dashboard

Show real mounted filesystem capacity while filtering pseudo/runtime mounts.

The backup-root filesystem deserves a separate capacity section with:

- total/used/available space;
- current repository size;
- logical selected data size;
- estimated next repository delta;
- safety margin and capacity assessment.

For a first backup, logical selected size is a conservative indicator until a Restic dry-run exists. For incrementals, do not use the full logical selection as the predicted growth; use the delta estimate.

## 18. Semantic enums and UI labels

Machine/domain state should use string-backed enums or equivalent stable semantic values. Human-facing English labels are a separate presentation mapping.

Do not write business logic such as:

```python
if status == "Manually excluded":
    ...
```

Compare domain values instead.

Likewise keep centralized semantic style metadata. Use green for positive/included/installed/backed-up states, amber for pending/warnings, purple for review-required, blue for running, neutral gray for unselected/system-neutral states, and red/pink for explicit exclusion/failure/missing states. Text/icons must accompany color for accessibility.

All current user-facing strings are English. Do not use rendered English labels as persistence identifiers.

## 19. Qt tree behavior

Filesystem and configuration trees are lazy where practical.

Filesystem browsing must not mutate persistent policy. Expanding a path can trigger cached/privileged discovery and size calculation, but must not create a manual exclusion. Checkbox interaction is different: unchecking an effectively selected path persists a manual exclusion.

Provide explicit actions for recursive inclusion, manual exclusion and clearing an explicit policy.

Long/elided values should expose their full original text via tooltips. Do not rely on literal `...` being present in the stored string; Qt can visually elide text during layout.

The `/etc` tree uses virtual intermediate directories. Filesystem tree nodes represent real paths.

## 20. Restore safety

Restore is intentionally selective.

Staging restore writes into the controlled backup-root restore area. In-place restore may write to `/` but must require explicit includes and reject dangerous broad requests such as restoring all of `/etc` as one operation.

Package restore must be constrained to packages recorded in the chosen snapshot.

Destructive actions need clear GUI confirmation and structured error reporting.

## 21. Subprocess rules

Use explicit argv arrays and controlled environments. Avoid `shell=True` and string interpolation for commands.

Privileged subprocesses should inherit only the environment required by the operation. Do not trust user-supplied `PATH`, `PYTHONPATH`, `PYTHONHOME`, loader variables or similar execution-affecting variables across the root boundary.

Long subprocesses must support timeout/cancellation and process-group cleanup. Do not leave detached Restic/APT children after the GUI closes or a request times out.

## 22. Testing expectations

Security and state-resolution behavior needs tests, not only GUI smoke testing.

At minimum preserve coverage for:

- GUI rejects root and can start as non-root;
- privileged helper rejects an unexpected unprivileged context;
- exactly one production startup `pkexec` session is used;
- later client operations use the attached session and never silently fall back;
- session request/response/progress framing and identity validation;
- control-channel cancellation and child cleanup;
- backup-root admission/default `/backup` creation rules;
- hard exclusion attempted override;
- recursive include + new child;
- recursive include + preconfigured excluded child;
- recursive include + manually excluded child;
- preconfigured exclusion + exact explicit include;
- manual parent exclusion + descendant include;
- new unselected propagation;
- derived partial checkbox behavior;
- persistent policy for disappearing/reappearing paths;
- nested Restic exclude override ordering;
- package/config payload validation;
- restore include/path validation;
- credential lifecycle and request-private cleanup.

Use fake helpers/backends for most automated tests so the suite does not require a real Polkit authentication or root session.

Very short process-start timing tests can be flaky under loaded CI/container environments. Do not weaken production cancellation/deadline semantics merely to hide an environment-dependent startup race; distinguish a real regression from a baseline timing failure.

## 23. Development workflow for agents

Before changing code:

1. identify whether the change crosses the GUI/root boundary;
2. identify whether it changes persistent policy or only presentation;
3. identify cache invalidation implications;
4. identify Restic source/exclude consequences;
5. identify backward compatibility of serialized/cache state.

During implementation:

- change the domain model/resolver before patching multiple widgets independently;
- keep privileged APIs narrow;
- add focused tests as behavior changes;
- run syntax checks and the relevant test subset early;
- run the full suite before delivery;
- inspect the repository for stale root-GUI assumptions (`sudo -E`, root-only GUI wording, direct later `pkexec` calls);
- do not include generated `__pycache__`, `.pyc`, `.pytest_cache`, build output or local secrets in patch archives.

## 24. Things an agent should not do

Do not:

- run the Qt GUI as root;
- add repeated Polkit prompts for ordinary operations;
- add a generic root command executor;
- trust GUI-supplied paths without privileged validation;
- make `/backup` world-writable;
- treat `/tmp` or `/boot` as hard pseudo-filesystem exclusions;
- back up all of `/etc` because a virtual tree directory was checked;
- store partial checkbox state as persistent policy;
- infer manual exclusion from browsing/unchecking alone;
- silently discard policies when paths disappear;
- exclude Steam save-sensitive trees indiscriminately;
- use UI labels as domain/persistence values;
- block the Qt event loop for scans or Restic;
- promise exact physical backup growth from logical selected size;
- include repository/cache/runtime contents recursively in snapshots.

## 25. Definition of done for architecture-sensitive changes

A privilege-related change is complete only when:

- the GUI process remains non-root;
- one startup Polkit authorization creates the persistent helper session;
- later production GUI operations reuse it;
- helper death causes a clear failure rather than a new authentication prompt;
- the helper API remains typed/allow-listed;
- credentials remain bounded to the intended session/request lifecycle;
- subprocesses are cancellable/reaped;
- documentation and tests describe the same architecture.

A selection-model change is complete only when persistent policy, effective resolution, Restic planning and rendered checkbox/status behavior agree.
