# Publication policy

Run `python guards/tools/publication_guard.py ci` from a consumer root to apply the same visibility policy as its normal hooks and CI. Direct scanner commands remain public-policy diagnostics.

## Visibility and normal entrypoints

The normal hooks and composite CI action use `publication_guard.py`. A fresh proof must identify
every stored and effective fetch/push destination as PRIVATE before private content is permitted.
An explicit push URL must also belong to the proven configured push routes. Local hooks use the
installed visibility receipt; GitHub Actions obtains current repository metadata from the canonical
GitHub API using its job token. Missing evidence retains the full public checks.
The metadata client rejects custom CA, proxy and TLS key-log environment settings before any
credential-bearing request. It verifies TLS with default trust, forbids redirects, and requires
the response URL and repository identity to match the requested canonical API endpoint.

For verified PRIVATE repositories, declared DATA and private references are permitted. Manifest,
path, schema, fixture, run-shape and sealed-path checks still run, and the pre-commit identity
assertion remains mandatory. The output names the proven repositories and states that public-content
scanning is out of scope. Public and unknown repositories receive the full PII and data-boundary
checks. Explicit `pii_guard.py --tree --history` and `data_boundary.py` invocations remain public-policy
diagnostics regardless of visibility; private-only content can produce findings in those diagnostics.

## Public source boundary

The public TOOL check rejects declared DATA and sealed paths that physically exist, including ignored
files and empty declared directories. Keep public tool DATA in a separate private companion repository.

## Scan coverage and failure states

Staged and range scans compare decoded Git blobs, so UTF-16 editor files receive the same
addition-only checks as UTF-8. Unchanged and removed lines stay outside those incremental scans;
merge additions must be new against every parent. Range scans also check newly introduced paths,
including rename destinations and gitlinks. Tree scans exclude indexed submodules from their parent;
scan each child repository separately to check its content.
All Git discovery and object reads use original objects, including commit and tag metadata.
Replacement objects cannot conceal reachable history. Hook repository selectors and the selected
index remain in effect for scans of the repository being checked.

## Private token policies and companion identity

Format-2 private token policies require an integer `count` matching all loaded entries, including the canary. Legacy policies remain readable and report that completeness is unattested. The DATA resolver follows the physical installation when imported through a directory alias and refuses authorization if filesystem resolution fails. Visibility remains a separate companion audit.

Eligible historical blobs above the 8 MiB scan limit make the history scan incomplete. The API raises `ScanIncompleteError`; the CLI prints `SCAN INCOMPLETE` and exits 2, which blocks publication. A size limit cannot establish that the skipped content is safe. Existing exclusions for known binary extensions remain separate.

When another owner's private repository has exactly this repository's name or a documented companion name, the cross-repository policy retains that foreign `owner/name` as a qualified token. Bare own-companion names and explicit own-owner references do not identify the foreign repository. Explicit foreign references retain their original severity, unrelated private names retain bare-name enforcement, and independent secret denylist entries still apply.

See [COMPANION.md](../COMPANION.md#verifying-a-companion) for destination proof and [STORAGE_CONTRACT.md](STORAGE_CONTRACT.md) for artifact write admission.
