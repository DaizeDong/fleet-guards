# fleet-guards

The guard kit for this fleet, in one place, consumed as a git submodule: nine detection rules, a data boundary, and hooks that refuse to run when they are not there.

Python consumers can build the [shared filesystem, credential and runtime package](PACKAGE.md).
Its versioned API and wheel are separate from the Git hook entrypoints.

[![Guard Kit](https://img.shields.io/badge/Guard%20Kit-Git%20Submodule-orange?style=flat)](#install)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Detection Rules](https://img.shields.io/badge/Detection%20Rules-9-green?style=flat)](#what-is-in-here)
[![Languages](https://img.shields.io/badge/Languages-EN%20%2F%20CN-blue?style=flat)](#languages)
[![Roadmap](https://img.shields.io/badge/Roadmap-v0.1.0-purple?style=flat)](ROADMAP.md)

[English](README.md) | [中文版](README_CN.md)

---

## ⭐ Read this first, the design philosophy

Three commitments shape everything here, and they matter more than the rule list.

**A sieve at the exit cannot catch a pipe pointed at it.** `pii_guard` reads what is about to be
published and flags what smells private. That is the backstop, not the primary control. The 2026-07
audit found public repositories holding real-run output that the skills themselves had written
there, every run, by design: a verdict ledger, a purchase record, an activity log. A ticker with an
entry price carries no address and no phone number, so a content scanner has nothing to smell. The
primary control is therefore structural: every path belongs to exactly one class declared in
`.dataclass.json`, and anything a real run produced lives in a private companion repository that is
physically absent from the public one.

**An allowlist, because a denylist is written by whoever leaks.** A hand listed set of forbidden
terms only ever blocks what its author already thought of, and a file full of real identifiers is
itself the document you were trying not to publish. So the scanner flags every real world shaped
identifier that is not from the declared synthetic namespace, including vendors nobody anticipated.
It contains no private data and is safe to publish. The private term list stays on one machine and
never enters a repository.

**Absent is a failure, not a reason to skip.** Every state where a check could be missing is a
blocking state: an empty submodule directory, a scanner file that is not there, a `.dataclass.json`
that was never written, a Git command that failed instead of listing nothing. A step wrapped in
`if [ -f ... ]` disappears from the report when its file goes missing, and a report with one line
missing reads exactly like a report where everything passed. Clean and never checked have to be two
different outputs.

## What it is (and isn't)

It is the fleet's security kit: the scanner, the data boundary, the companion resolver, their tests,
two Git hooks, and a composite CI action, consumed by other repositories as a submodule at `guards/`.

Nine detection rules, implemented as 38 regexes across five tools. What they actually block:

| Rule | Plain words |
|---|---|
| PERSONAL-MAILBOX | a real personal mailbox in something about to be public |
| EMAIL | any address outside the declared synthetic namespace |
| PHONE | a NANP phone number |
| ZIP | a postal code near shipping or address words |
| USER-PATH | a machine path carrying an operator username |
| PRIVATE-PATH | a path that exists only on a maintainer machine |
| AUTHOR-EMAIL | the identity a commit is about to be signed with |
| CROSS-REPO | one repo naming another repo's private companion |
| DENYLIST | hand-listed private terms no structural rule can infer |

Plus 13 filename patterns that recognise real-run output, four false-positive suppressors, and
twelve pure text helpers that carry no security role at all.

It is **not** a Claude Code skill or plugin, and it ships no `SKILL.md`: nothing here is invoked by
an agent. It is **not** the style kit. The two gates that were purely style and architecture,
`dash_guard` and `load_budget`, live in `fleet-style`: they were 17.5% of this repository and none
of it was about keeping an identifier out of a public history. It is **not** a private repository
and must never become one: a private submodule breaks CI in every public consumer.

Before this repository existed, the kit was copied by hand into every consumer: 17 files, 7,643
lines, times 22 repos, about 191,000 lines on disk. The copies were byte identical and one installer
could resync them all, so duplication was not the cost. The cost was that the installer worked from
a hand written list, and a repository missing from that list got, in the installer's own words, "the
appearance of a gate and none of the maintenance". Two public repositories sat on a fail open
pre-push hook for exactly that reason, found on 2026-08-31. A submodule replaces the list with a
pointer that lives in the consuming repository itself.

## Install

    git submodule add -b main https://github.com/DaizeDong/fleet-guards.git guards
    git config core.hooksPath .githooks

Commit fail-closed `.githooks/pre-commit` and `.githooks/pre-push` forwarding shims as part of
installation. A shim must stop if `guards/hooks/<hook>` is missing, then execute that hook. Pointing
Git directly at an empty submodule disables the gate silently; the committed shims are what detect
an incomplete clone.

To preserve an optional machine-level commit-message rule, also commit the following as
`.githooks/commit-msg` and mark it executable with `git add --chmod=+x .githooks/commit-msg`.
Keep `core.hooksPath` set to `.githooks`. Adjust `guards` if the kit has a different submodule path.
The kit forwarder asks Git for the global hook directory and propagates that rule's exit status.

<!-- optional-commit-msg-shim -->
```sh
#!/bin/sh
ROOT=$(git rev-parse --show-toplevel) || exit 1
HOOK="$ROOT/guards/hooks/commit-msg"
if [ ! -f "$HOOK" ]; then
  echo "commit-msg: the configured guard forwarder is missing" >&2
  exit 1
fi
exec sh "$HOOK" "$@"
```

Companion auditing uses the target's registered fleet-guards submodule, including a custom
submodule path. A missing checkout or resolver blocks the audit. For a standalone deployment,
run that repository's own `tools/data_boundary.py`; an external checker will not import a loose
consumer copy. `--companion-dir` remains available when explicitly selecting the DATA store.

USE THE HTTPS URL, not an ssh host alias. `.gitmodules` is committed and shared, so the url has to
resolve for everyone who clones, including a CI runner. The first migration used a local ssh alias
and all three workflows failed immediately with "Could not read from remote repository".

Clone with `--recursive`, or run `git submodule update --init` afterwards. CI must set
`submodules: true` on `actions/checkout`.

## Quick start

A consumer's whole workflow is a checkout, a Python, and one line:

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # the history scan is the point; a shallow clone would see nothing
          submodules: true
      - uses: actions/setup-python@v5
      - uses: ./guards/ci/pii-guard
```

Run the publication policy and contract by hand from a consumer's root:

```bash
python guards/tools/publication_guard.py ci
python guards/tools/test_companion_contract.py
```

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

The public TOOL check rejects declared DATA and sealed paths that physically exist, including ignored
files and empty declared directories. Keep public tool DATA in a separate private companion repository.

Staged and range scans compare decoded Git blobs, so UTF-16 editor files receive the same
addition-only checks as UTF-8. Unchanged and removed lines stay outside those incremental scans;
merge additions must be new against every parent. Range scans also check newly introduced paths,
including rename destinations and gitlinks. Tree scans exclude indexed submodules from their parent;
scan each child repository separately to check its content.
All Git discovery and object reads use original objects, including commit and tag metadata.
Replacement objects cannot conceal reachable history. Hook repository selectors and the selected
index remain in effect for scans of the repository being checked.

Format-2 private token policies require an integer `count` matching all loaded entries, including the canary. Legacy policies remain readable and report that completeness is unattested. The DATA resolver follows the physical installation when imported through a directory alias and refuses authorization if filesystem resolution fails. Visibility remains a separate companion audit.

Eligible historical blobs above the 8 MiB scan limit make the history scan incomplete. The API raises `ScanIncompleteError`; the CLI prints `SCAN INCOMPLETE` and exits 2, which blocks publication. A size limit cannot establish that the skipped content is safe. Existing exclusions for known binary extensions remain separate.

When another owner's private repository has exactly this repository's name or a documented companion name, the cross-repository policy retains that foreign `owner/name` as a qualified token. Bare own-companion names and explicit own-owner references do not identify the foreign repository. Explicit foreign references retain their original severity, unrelated private names retain bare-name enforcement, and independent secret denylist entries still apply.

Audit that companion with:

```bash
python guards/tools/data_boundary.py --companion-dir ../example-skill-config --visibility-map /path/to/visibility.json
```

The receipt uses the same `owner/repository` to `PUBLIC`/`PRIVATE`/`UNKNOWN` mapping and `_refreshed` timestamp as `pii_guard`. Its age must be known and no more than 30 days. Every effective fetch and push URL across all configured remotes must resolve to a repository marked `PRIVATE`; Git URL rewrites and additional push URLs are checked. The audit prints the verified repository names and allows versioned DATA there. SSH aliases require an explicit `HostName github.com` in every plausible configuration chain. Missing or stale evidence, public destinations, unrecognized clients, and unproved routing or trust settings block admission. See [the transport contract](COMPANION.md#verifying-a-companion) for the supported SSH and HTTPS configurations. This check uses the local receipt and does not make network calls.

Companion discovery starts at the physical DATA destination, independently of the invoking hook's
repository and index. Its stored repository configuration and its effective process configuration
must both identify only PRIVATE destinations. A temporary URL rewrite cannot turn a PUBLIC store
into an authorized companion. Linked worktrees remain supported.

## What is in here

| Path | What it is |
| --- | --- |
| `tools/pii_guard.py` | The scanner. Allowlist based, structural, runs over the working tree and the full history. |
| `tools/data_boundary.py` | The primary control. Asks whether this repository is an uninitialized tool or somebody's life. |
| `tools/publication_guard.py` | Applies proven repository visibility to normal hook and CI policy. |
| `tools/datadir.py` | The resolver. Decides where real-run output goes, which is always outside the repository. |
| `tools/fleet_sync.py` | Dispatches verified upstream updates and advances consumer gitlinks. |
| `tools/test_*.py` | The kit's own suite, including the policy layer whose private half never exists on a runner. |
| `hooks/` | `pre-commit` and `pre-push`, the bodies the consumer's shims forward into. |
| `ci/pii-guard/action.yml` | The composite action every consumer references by local path. |
| `templates/fleet-sync.yml` | The one workflow a consumer copies to enroll in automatic synchronization. |
| `COMPANION.md` | The contract between a public repository and its private companion, checked against the resolver by a test. |
| `docs/AUTOMATIC_SYNC.md` | How a consumer enrolls, and why the dispatch path is what it is. |

## How to update a consumer

    git submodule update --remote guards
    git add guards && git commit -m "guards: bump"

A submodule pins one commit. Consumers update manually with the commands above, or enroll in
[automatic synchronization](docs/AUTOMATIC_SYNC.md). Once enrolled, a successful upstream check
sends a dispatch event and the consumer records a normal gitlink update commit on its default
branch. Its commit gates and CI still run.

## Example output

```
$ python tools/pii_guard.py --tree
pii_guard: clean (tree)  [28 file(s) scanned, 0 skipped]

$ python tools/data_boundary.py
data_boundary: clean (0 DATA + 0 sealed paths not tracked, 0 FIXTUREs generator-reproducible,
28 tracked files carry no real-run shape)
```

Both print a count, and the count is the point. "Clean" with nothing scanned is the failure this kit
spends most of its lines preventing.

## The failure mode to know about

A plain `git clone` without `--recursive` leaves `guards/` EMPTY. So does a CI checkout without
`submodules: true`. The hooks fail closed on a missing scanner, so that state blocks a commit loudly
rather than passing in silence, which is the only reason this arrangement is safe. If the guards
directory is ever empty, the answer is `git submodule update --init`, never `--no-verify`.

## Starting processes on Windows

Every process the kit starts goes through `_no_window()`, and `tools/test_no_console_window.py`
fails on any `subprocess` call, `os.system`, `os.popen` or process pool that does not. The reason is
measured, not theoretical: a console program started by a process with no console of its own
(`pythonw`, a scheduled task, a service) gets a new console, and Windows shows it as a window. A
daemon that proved its private companion on every log line ran about 19 git commands per proof and
opened roughly 9,000 terminal windows in eight hours.

The helper adds `CREATE_NO_WINDOW` only when the calling process has no console. With a console, the
children share it, nothing opens, and the flag would instead move their unredirected output and
terminal prompts into a hidden console where a hook's findings could not be read. It refuses
`DETACHED_PROCESS`, because Windows ignores `CREATE_NO_WINDOW` alongside it and the console-less
child's own children open windows again, and `CREATE_NEW_CONSOLE`, which is a window by definition.
Each tool file carries its own copy, because consumers load these files one at a time by path; the
same test holds every copy identical.

## Limitations

**Four things behave differently in a repository that carries this submodule.** Measured on a real
consumer, not reasoned about, and only one of them will actually stop you.

The pre-commit framework refuses to install: `pre-commit install` prints "Cowardly refusing to
install hooks with `core.hooksPath` set" and hints that you unset it. Following that hint leaves a
working formatter and no gate. The stub in `.githooks/` calls `pre-commit run` itself when a config
and the binary are both present, so both run and the guard stays last: a formatter that rewrites
files cannot slip the change past the scan.

A linter walks in here. This kit is clean under ruff's default rules. Under an opinionated set it is
not, and cannot be: 155 of the findings at that level are "rewrite %-formatting as f-strings" across
a scanner where that churn buys no correctness. Exclude the submodules with
`extend-exclude = ["guards", "style"]`.

A module of yours with the same name as one here wins. With the repository's own directory first on
`sys.path`, `import datadir` resolves to the repository's, not the kit's. A root `conftest.py` also
wins over the one here. The reverse only happens if you put the kit's path first, which is a choice.

Everything else was checked and is a non-event: a new top-level package and its tests are collected
normally, `find_packages()` returns nothing from the submodules, `pytest` at the root does not pick
up the kit's suite (`pytest guards/tools/` still does, deliberately), a `pytest.ini` with `testpaths`
changes nothing, and the submodules never show as dirty after a test run.

**What the kit cannot close.** The boundary stops an agent from copying a real file, because no real
file is within reach. The structural rules recognise shapes and the private list recognises names.
None of the three recognises prose that leaks a private fact without naming an identifier. That one
has no mechanism behind it, only the rule never to use a real example.

## Languages

English (`README.md`) · 中文 (`README_CN.md`)

## Roadmap · Contributing · License

See [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) · [COMPANION.md](COMPANION.md).

The deviations from the house repository spec, and the reasons for each, are recorded in
[docs/2026-09-22-spec-adaptation.md](docs/2026-09-22-spec-adaptation.md).
