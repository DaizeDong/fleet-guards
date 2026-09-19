# Shared Python API

The stdlib-only `fleet_guards` package can be consumed from a checkout or a
version-pinned wheel. The Git hooks keep their existing entrypoints. Deployment
must pair the wheel and submodule with the same accepted source revision; the
controller records that revision in its deployment lock.

## Credential detection

```python
from fleet_guards.secrets import scan

result = scan(serialized_document, policy="credential-shapes-v1")
if result["state"] != "clean":
    # The caller must stop publication, including when the scan failed.
    raise RuntimeError("document_not_cleared")
```

The result contains `state` (`clean`, `findings`, or `scan_failed`),
`policy_version`, and `findings`. Each finding contains `rule_id`, a half-open
character `span`, `severity="block"`, and numeric `confidence`. Failed scans also
carry an `error_code`; their empty findings list does not imply clearance. Unknown
policies have a null `policy_version`. No value, password hash, or exception text
is included. A private caller that needs correlation can derive its own keyed
fingerprint from the original text and span.

| Policy | Behavior |
| --- | --- |
| `credential-shapes-v1` | Union of provider keys, access tokens, webhooks, private-key headers, credential URIs, assignments, query parameters, CLI arguments and bearer tokens. Complete explicit templates are exempt. |
| `support-egress-v1` | The same shapes, plus the existing uppercase canary and entropy checks. Template-shaped credentials retain the strict support behavior. |

The support policy covers direct credential scanning. Existing support layers for
PII, encoded output, injection detection and transport authorization must remain
in the consumer. This API does not replace them.

Shape detection does not require high entropy. Generic assignments require at
least eight value characters; URI passwords, CLI/query arguments and bearer
values can be short. Complete environment references and explicit placeholder
syntax can be exempted by the default policy; a placeholder prefix with an
attached value cannot. Detection of short values in structured secret fields
remains the caller's parsing policy.

The input is limited to 1,000,000 characters and results to 1,000 findings. A
one-second budget is checked between regex operations; it is not a preemptive
regex timeout. Exceeding any bound returns `scan_failed`. Scan the final
serialization, including generated CLI argument arrays, before publication.
JSON/TOML editing, omission recovery manifests and vault routing belong to callers.

`python -m fleet_guards scan [--policy POLICY]` reads bounded UTF-8 from stdin and
writes metadata JSON. Exit codes are 0 for clean, 1 for findings and 2 for scan
failure. It never prints the submitted text.

## Filesystem primitives

`fleet_guards.filesystem` exports:

| API | Contract |
| --- | --- |
| `validate_path(path, *, root=None) -> Path` | Absolute lexical path, optional root containment, no traversal, reserved device names, alternate streams, symlinks or reparse components. |
| `read_bounded(path, limit) -> bytes` | Regular files only, at most the requested bytes, explicit failure for oversize files or observed changes. |
| `atomic_replace(path, data, mode=0o600) -> None` | Same-directory staging, UTF-8 for strings, flush and file fsync before replacement. |
| `create_no_replace(path, data, mode=0o600) -> bool` | Publish only when absent; return False on a regular-file collision. Concurrent creators are arbitrated by the OS. |

Writers create missing parents. They accept strings or bytes and reject unsafe
paths before publication. I/O errors propagate. No-replace uses Windows rename
or POSIX hard-link creation; unsupported filesystems fail instead of using a
racy fallback. Temporary files are cleaned on failure.

Permissions default to 0600, matching the existing atomic writer. Windows chmod
does not establish a private ACL: directories must already have appropriate ACLs.
Unlike a writer that suppresses chmod errors, these primitives report them. A
consumer adapting an older API must preserve its return type and deliberately
account for this stricter error handling.

POSIX directory fsync errors propagate. Windows lacks a portable directory fsync
in this implementation, so directory-entry survival across power loss is not
promised. Errors after publication may indicate that bytes were published but
durability or cleanup failed. Callers own recovery, resource locks and multi-file
transactions. Path checks detect observed links and changes; they do not isolate
a directory from a hostile concurrent process swapping its ancestors, and
replacement is not an atomic compare-and-swap.

## Companion resolution

`fleet_guards.datadir` exports `resolve_data_dir`, `resolve_companion_root`,
`data_path` and `assert_outside_own_repo`. All require an existing absolute
`consumer_root` keyword argument. They never infer a consumer from site-packages
or the current working directory. Exceptions remain `DataDirNotInitialized`,
`DataDirInsideOwnRepo` and `CompanionUnproven`.

`tools/datadir.py` remains the standalone implementation and keeps its existing
signatures with optional `consumer_root=` added. Its CLI also accepts
`--consumer-root`. The build includes this exact source in the wheel as
`fleet_guards._datadir`; the checkout facade loads the same source locally.
No second maintained resolver or business package is bundled.

The resolver APIs also accept `env=` (a complete caller environment snapshot)
and `cwd=` for relative pointers. Neither changes process-wide state. An explicit
context without a home does not use the ambient user's home. These arguments let
concurrent model calls resolve their own private outputs through this same API.

The strict scanner accepts `entropy_threshold=` for legacy caller compatibility;
invalid thresholds fail closed. Default policy behavior is unchanged.

The existing first-existing-candidate order is retained: explicit data directory,
configuration pointers, proven sibling companion, then home dotfiles. An explicit
pointer to a missing directory does not override a later existing candidate.
Submodules resolve against their superproject; linked worktrees retain their own
root. Linked companion remotes are read from Git's common config. Sibling identity
proof remains required and does not itself establish remote visibility.

`data_path` rejects absolute paths, traversal and resolved paths inside the tool
repository. This closes a previous escape through the relative-path argument.
Visibility checks remain with the existing data-boundary guard.
