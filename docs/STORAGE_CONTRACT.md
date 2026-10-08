# Source-owned storage and write admission

`tools/storage_contract.py` is the canonical implementation of storage contract
validation, path matching, and artifact write admission. A consumer's root
`storage.contract.json` supplies policy. Smith's inventory and retirement CLI
imports these primitives; it owns inventory, size reporting and reviewed removal.
Do not copy the contract engine into consumers.

## Version 1 declarations

A contract has `schema_version: 1`, a nonempty `tool`, and a nonempty audited
`artifacts` list. Each artifact requires nonempty `artifact_id`, `path_pattern`,
`purpose`, `schema`, `producer`, `consumer_or_final_deliverable`, and
`rebuild_or_restore` strings. `retention_rule` has a `class` of `core`,
`rebuildable`, or `retired` and a nonempty concrete `rule`. Root and artifact
`max_bytes` values, when present, are positive integers. Admission references
domain schemas; it does not validate payload contents or enforce size budgets.

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
artifacts. Versioned destinations must not be ignored by effective Git rules,
even when an ignored file is already force-tracked. A new file can be admitted
before it exists: the repository must have a valid HEAD and the new path must be
versionable. The caller's normal backup workflow remains responsible for adding,
committing and publishing authorized data to the private companion.

An artifact can explicitly declare `persistence: transient` and a nonempty
`transient_reason` explaining its temporary lifecycle and recovery dependency.
Only this source-owned declaration permits an ignored destination. Persistence
and retention are independent: an active SQLite WAL can be transient while its
retention is core until checkpoint. Transient persistence does not authorize
cleanup while a writer or recovery obligation remains active. Retired artifacts
cannot receive new writes, regardless of persistence. There is no caller flag
that grants an ignored-path exception.

## Runtime API

Load this module by its path in the pinned Guards checkout, then call:

```python
admission = storage.authorize_artifact_write(
    source_root, companion_root, "data/runs/run-001/result.json",
    artifact_id="run-result",
    visibility_map=None,
)
destination = admission.path
```

The immutable result also has `artifact_id`, `contract_sha256`, and `proof`.
`proof` is a `PrivateCompanionProof`; its private process context must not be
serialized. The optional expected `artifact_id` lets each producer restrict its
output to its own source declaration. The existing `producer` field is descriptive
text, not an executable identity check.

The explicit `companion_root` must equal the root returned by the PRIVATE proof.
All physical and effective fetch/push destinations must have current PRIVATE
receipts. Missing metadata, Git errors, PUBLIC or UNKNOWN destinations, nested
repositories, symlinks, junctions, hardlinked leaves, and unsupported file types
refuse admission. A legitimate linked-worktree `.git` file at the companion root
is supported. This API loads the boundary implementation beside itself; it does
not fall back to an ambient or copied checker.

Git supplies `GIT_EXEC_PATH` to hooks even when no custom helper path was selected.
For SSH and HTTPS, admission accepts it only when an independent local probe of
the selected Git executable, with that override absent, returns the same existing
canonical helper directory. Unverified paths, aliases and probe failures remain
UNKNOWN. This check preserves the caller's environment and does not relax other
transport or trust overrides. It assumes the selected Git executable is trusted;
path matching does not authenticate an arbitrary executable supplied through PATH.

The function is read-only and works with absent target paths. It neither discovers
a companion nor creates data directories. Call the existing shared resolver to
select a companion, preserve its documented precedence, and pass the exact root
explicitly. Bind a tool's selected DATA subdirectory to its declared artifact
layout before invoking a producer; absence of `data/` does not justify rewriting
the output path to the companion root.

Call admission immediately before each write and let failure stop the write.
It rechecks the contract, destination topology, publication state and ignore rules
before returning. It is a snapshot, not a filesystem lock. The caller owns
concurrency control, atomic replacement, and authorization for every temporary
artifact created by that replacement protocol.

For a directory artifact, `directory=True` preserves directory-only ignore rules
even before the directory exists. That directory must itself have one owner;
admitting it does not authorize arbitrary future descendants. Structural parents
need no separate artifact declaration: first admit the concrete leaf, then
prepare its inspected parent directories as part of the adjacent write. Admit
each produced leaf independently. Atomic temporary files need their own bounded
source declaration when they do not match the final artifact's pattern.

The reusable validation/matching primitives retain Smith's existing names:
`CONTRACT`, `FIELDS`, `CLASSES`, `SEPARATE`, `COMBINED`, `relative_path`,
`validate_contract(repo)`, `in_data_scope`, `matches`, `no_links`, `owners`, and
`canonical_hash`. Validation and admission propagate filesystem failures; a
missing or unreadable contract is not an empty policy. The Guards `tools/` API is
consumed through the pinned checkout. Python package 0.2.1 also exposes admission
through `fleet_guards.runtime`; its wheel maps this same source implementation
and its PRIVATE proof dependencies, without maintaining a second policy engine.
