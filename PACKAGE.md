# Shared Python API

Version 0.2.0 packages the credential scanner and filesystem primitives used by
Python consumers. Install a wheel built from an accepted source revision and
record both the revision and wheel hash in the deployment lock.

This release has a narrower module surface than the earlier 0.1.0 package:
`fleet_guards.datadir` and `_datadir` are not shipped. The standalone
`tools/datadir.py` resolver remains part of the Git guard kit. Its current
signature does not implement the earlier package facade's explicit consumer
context, so this build does not expose that facade or bundle a second resolver.
Callers that need it must keep their existing accepted release until that API has
a separate compatibility migration. Importing the package or its CLI does not
load the resolver. Git hooks and publication policy retain their existing paths.

## Credential scanning

```python
from fleet_guards.secrets import scan

result = scan(document, policy="credential-shapes-v1")
if result["state"] != "clean":
    raise RuntimeError("document_not_cleared")
```

Results contain `state` (`clean`, `findings`, or `scan_failed`), `policy_version`
and `findings`. Findings contain only `rule_id`, a half-open character `span`,
`severity` and `confidence`. Failures include an `error_code`; an empty findings
list on a failed scan does not establish clearance. Input values, exception text
and password hashes are never included in results.

`credential-shapes-v1` checks provider keys, access tokens, webhooks, private-key
headers, credential URIs, assignments, query parameters, CLI arguments and bearer
tokens. Complete explicit templates are exempt. `support-egress-v1` adds canary
and entropy checks and retains strict handling of template-shaped credentials.
These policies do not replace a consumer's PII, encoding, injection, transport or
publication checks.

Defaults are 1,000,000 characters, 1,000 findings and one second. Per-call
`max_text_chars` and `seconds` can raise the bounds to 16 Mi characters and 30
seconds. Bounds are checked without truncating input. The time budget is checked
between regex operations and is not a preemptive regex timeout. Byte limits and
structured-field policy belong to the caller. Scan the final serialized output.

`python -m fleet_guards scan [--policy POLICY]` reads bounded UTF-8 from stdin and
prints metadata JSON. Exit codes are 0 for clean, 1 for findings and 2 for failure.

## Filesystem operations

| API | Contract |
| --- | --- |
| `validate_path(path, *, root=None)` | Validate lexical paths, optional containment, and observed symlink/reparse components. |
| `read_bounded(path, limit)` | Read regular files within a byte limit; reject observed identity or content changes. |
| `atomic_replace(path, data, mode=0o600)` | Stage on the destination volume, flush, fsync and replace a regular file. |
| `create_no_replace(path, data, mode=0o600)` | Publish only when absent; return `False` on a regular-file collision. |
| `create_no_replace_with_identity(...)` | Return the staging object's device/inode identity, or `None` on collision. |
| `identity(path)` / `sync_directory(path)` | Read regular-file identity / apply the supported directory durability operation. |
| `detach_if_matches(...)` | On Windows, retain a matching object using handle-based exclusion; conflicts return `False`. |
| `exclude_file_writes(paths)` | Hold Windows write/delete exclusion while the caller operates; unsupported platforms raise. |
| `delete_if_identity_matches(...)` | Delete only the matching opened Windows object; conflicts or unsupported platforms return `False`. |
| `link_no_replace(source, destination)` | Create a no-replace link in a trusted directory; collisions return `False`. |
| `assert_same_volume(source, destination)` | Refuse a known or unprovable cross-volume operation. |

Writers accept strings or bytes and create missing parents. Filesystem failures
propagate; an error after publication can mean bytes were published but durability
or cleanup failed. Callers own transaction journals, resource locks and recovery.
Windows chmod is not an ACL privacy guarantee, and this implementation makes no
portable promise of directory-entry survival across Windows power loss.

These primitives operate in trusted, cooperative directories. They do not isolate
ancestor paths from a hostile concurrent process, implement atomic compare-and-swap,
or prove PRIVATE repository visibility. Consumers must establish their own storage
and publication authority before writing.
