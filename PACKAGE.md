# Shared Python API

Version 0.3.0 packages the credential scanner, filesystem primitives and runtime access to the
canonical tools used by Python consumers. Install it editable from the machine's checkout:

    pip install -e "$(git config --get fleet.guards)"

`fleet_guards.runtime` loads `tools/datadir.py` and `tools/storage_contract.py`, packaged as
`fleet_guards._tools`. The editable install maps that package to the checkout's `tools/`, so there
is one implementation; a built wheel (the runtime generation) carries a copy of the same files. If they are missing, the import
fails with `ModuleNotFoundError`. Importing the package does
not load the resolver. Git hooks run from the same checkout through each consumer's `.githooks/`
shims.

## Companion discovery

```python
from fleet_guards.runtime import companion_resolver

resolver = companion_resolver(source_root=absolute_consumer_root)
companion = resolver.resolve_companion_root("example-tool")
data = resolver.resolve_data_dir("example-tool")
```

The bound root controls sibling discovery and own-source exclusion. It must be absolute, and each
resolver retains its own immutable binding. Every resolver entry point requires `source_root`;
nothing is inferred from where the kit is installed. Discovery identifies a location; it does not
establish artifact ownership. There is no runtime PRIVATE proof or write admission. Companions are
not wired to fleet-guards and nothing checks their visibility; `data_boundary` keeps DATA out of
public trees.

## Storage contracts

```python
from fleet_guards.runtime import storage_contract

contract = storage_contract()
policy = contract.validate_contract(absolute_companion_root)
```

`storage_contract()` returns the canonical `tools/storage_contract.py` module; see
[docs/STORAGE_CONTRACT.md](docs/STORAGE_CONTRACT.md).

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
tokens. Complete explicit templates are exempt.
This policy does not replace a consumer's PII, encoding, injection, transport or
publication checks.

Defaults are 1,000,000 characters, 1,000 findings and one second. Per-call
`max_text_chars` and `seconds` can raise the bounds to 16 Mi characters and 30
seconds. Bounds are checked without truncating input. The time budget is checked
between regex operations and is not a preemptive regex timeout. Byte limits and
structured-field policy belong to the caller. Scan the final serialized output.

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
| `link_no_replace(source, destination)` | Create a no-replace link in a trusted directory; collisions return `False`. |

Writers accept strings or bytes and create missing parents. Filesystem failures
propagate; an error after publication can mean bytes were published but durability
or cleanup failed. Callers own transaction journals, resource locks and recovery.
Windows chmod is not an ACL privacy guarantee, and this implementation makes no
portable promise of directory-entry survival across Windows power loss.

These primitives operate in trusted, cooperative directories. They do not isolate
ancestor paths from a hostile concurrent process, implement atomic compare-and-swap,
or prove PRIVATE repository visibility. Consumers resolve their companion before
writing; nothing checks a companion's visibility.
