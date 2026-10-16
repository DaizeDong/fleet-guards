# Source-owned storage contracts

`tools/storage_contract.py` is the canonical implementation of storage contract
validation and path matching. A consumer's root
`storage.contract.json` supplies policy. Smith's inventory and retirement CLI
imports these primitives; it owns inventory, size reporting and reviewed removal.
Do not copy the contract engine into consumers.

## Version 1 declarations

A contract has `schema_version: 1`, a nonempty `tool`, and a nonempty audited
`artifacts` list. Each artifact requires nonempty `artifact_id`, `path_pattern`,
`purpose`, `schema`, `producer`, `consumer_or_final_deliverable`, and
`rebuild_or_restore` strings. `retention_rule` has a `class` of `core`,
`rebuildable`, or `retired` and a nonempty concrete `rule`. Root and artifact
`max_bytes` values, when present, are positive integers. The contract references
domain schemas; validation does not check payload contents or enforce size budgets.

Paths are portable POSIX paths relative to the exact companion root. Traversal,
Windows device names, alternate streams, repository metadata and unrestricted
root catch-alls are refused. `*` stays within one segment; `**` spans zero or more
segments. A writable path must have exactly one artifact owner. `protected_paths`
contains optional relative patterns for the retirement workflow.
Patterns made entirely of wildcard segments, including equivalent root catch-all
spellings such as `**/**`, must name a bounded artifact namespace instead.
Windows matching folds case so different-case declarations cannot hide multiple
owners of one physical file. Existing Windows path components must use their
canonical filesystem spelling; NTFS short names cannot address a different
artifact or Git metadata through an otherwise valid declaration. Reserved device
names include console aliases and the Windows superscript COM/LPT forms.

The default `layout` is `separate_companion`: source and companion cannot be the
same directory or contain one another. An explicit `combined_private_repo`
layout requires the same PRIVATE source/companion root and nonempty, nonoverlapping
`data_roots`. These roots are exact relative paths without globs; every artifact
pattern and admitted path must stay within them.

`persistence` is optional. Omission means `versioned`, including for rebuildable
artifacts. Versioned artifacts should not be ignored by effective Git rules,
because ignored files never reach the companion's history. The caller's normal
backup workflow is responsible for adding, committing and publishing data to the
private companion.

An artifact can explicitly declare `persistence: transient` and a nonempty
`transient_reason` explaining its temporary lifecycle and recovery dependency.
Only this source-owned declaration permits an ignored destination. Persistence
and retention are independent: an active SQLite WAL can be transient while its
retention is core until checkpoint. Transient persistence does not authorize
cleanup while a writer or recovery obligation remains active. Retired artifacts
cannot receive new writes, regardless of persistence. There is no caller flag
that grants an ignored-path exception.

## Write time

There is no runtime write admission. A writer resolves its companion with the
shared resolver, keeps its outputs to its declared artifacts inside that companion
and never writes inside the public source tree. Companions are not wired to
fleet-guards and nothing checks their visibility; `data_boundary` keeps DATA out
of public trees, and `publication_guard` calls `prove_private_companion` only on
the opted-in repository being committed to, to select structural-only scope.

The reusable validation/matching primitives retain Smith's existing names:
`CONTRACT`, `FIELDS`, `CLASSES`, `SEPARATE`, `COMBINED`, `relative_path`,
`validate_contract(repo)`, `in_data_scope`, `matches`, `no_links`, `owners`, and
`canonical_hash`. Validation propagates filesystem failures; a missing or
unreadable contract is not an empty policy. Consumers load the module through
`fleet_guards.runtime.storage_contract()`.
