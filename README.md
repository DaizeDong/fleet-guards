# fleet-guards

Shared publication guards for Git repositories: nine detection rules, a data boundary, and hooks that block when required checks are unavailable. Consumers pin the kit as a Git submodule.

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

The kit combines structural storage rules, identifier scanning and explicit failure reporting.

**Keep real output outside public source.** The 2026-07 audit found that repository-relative output paths placed real run records in public repositories. Records can contain private facts without an email address or phone number, so content scanning alone cannot enforce this boundary. Every path is classified in `.dataclass.json`; real output belongs in a separate PRIVATE companion.

**Allow declared synthetic identifiers.** Structural rules flag identifiers outside the synthetic namespace. A private term list supplements those rules for names they cannot infer. The public scanner contains no private identifiers; the private list stays outside public repositories.

**Report incomplete checks as failures.** Missing scanners, empty submodules, absent declarations and failed Git reads must block the affected check. Reports distinguish a completed scan with no findings from a scan that never ran.

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

This repository is a Git/CI toolkit without a Claude Code skill or plugin entrypoint. Style and loading-budget checks belong to `fleet-style`; the original `dash_guard` and `load_budget` split moved 17.5% of this kit into that separate scope. Keep this submodule public so public consumers can fetch it in CI.

The earlier deployment copied 17 files and 7,643 lines per kit across 22 consumers; the historical inventory reported about 191,000 lines on disk. Its installer depended on a manually maintained consumer list. The 2026-08-31 audit found two omitted public repositories with fail-open pre-push hooks. Each consumer now records its dependency as a submodule pointer, making that dependency part of its own source history.

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

Use the HTTPS URL in `.gitmodules` so other machines and CI can resolve it. A local SSH host alias caused all three workflows in the first migration to fail with "Could not read from remote repository".

Clone with `--recursive`, or run `git submodule update --init` afterwards. CI must set
`submodules: true` on `actions/checkout`.

## Quick start

Add the composite action after checkout and Python setup:

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

Normal hooks and CI apply the [publication policy](docs/PUBLICATION_POLICY.md). Current evidence must prove every stored and effective fetch/push destination PRIVATE before private content is admitted. Missing evidence retains full public checks. Manifest, schema, fixture, path and identity requirements still apply to PRIVATE repositories.

Direct `pii_guard.py --tree --history` and `data_boundary.py` commands always use public policy. For companion admission, including receipt freshness and supported transports, follow [COMPANION.md](COMPANION.md#verifying-a-companion).

## What is in here

| Path | What it is |
| --- | --- |
| `tools/pii_guard.py` | The scanner. Allowlist based, structural, runs over the working tree and the full history. |
| `tools/data_boundary.py` | Checks declared classes, fixtures and real-output boundaries. |
| `tools/publication_guard.py` | Applies proven repository visibility to normal hook and CI policy. |
| `tools/datadir.py` | The resolver. Decides where real-run output goes, which is always outside the repository. |
| `tools/fleet_sync.py` | Dispatches verified upstream updates and advances consumer gitlinks. |
| `tools/test_*.py` | The kit's own suite, including the policy layer whose private half never exists on a runner. |
| `hooks/` | `pre-commit` and `pre-push`, the bodies the consumer's shims forward into. |
| `ci/pii-guard/action.yml` | The composite action every consumer references by local path. |
| `templates/fleet-sync.yml` | The one workflow a consumer copies to enroll in automatic synchronization. |
| `templates/upstream-notify.yml` | The workflow a custom or private upstream copies to notify its own consumers. |
| `COMPANION.md` | The contract between a public repository and its private companion, checked against the resolver by a test. |
| `docs/AUTOMATIC_SYNC.md` | How a consumer enrolls, and why the dispatch path is what it is. |

## How to update a consumer

    git submodule update --remote guards
    git add guards && git commit -m "guards: bump"

A submodule pins one commit. Consumers update manually with the commands above, or enroll in
[automatic synchronization](docs/AUTOMATIC_SYNC.md). Once enrolled, a successful upstream check
sends a dispatch event and the consumer records a normal gitlink update commit on its default
branch. Its commit gates and CI still run. The same path can follow other repositories, private
ones included, on a declared branch and gate workflow; see
[Private or custom upstreams](docs/AUTOMATIC_SYNC.md#private-or-custom-upstreams).

## Example output

```
$ python tools/pii_guard.py --tree
pii_guard: clean (tree)  [28 file(s) scanned, 0 skipped]

$ python tools/data_boundary.py
data_boundary: clean (0 DATA + 0 sealed paths not tracked, 0 FIXTUREs generator-reproducible,
28 tracked files carry no real-run shape)
```

Reports include examined and excluded counts so readers can distinguish coverage from an empty or incomplete scan.

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

The following compatibility observations came from a consumer checkout. They describe that validation scope, not every possible consumer configuration.

The pre-commit framework refuses to install: `pre-commit install` prints "Cowardly refusing to
install hooks with `core.hooksPath` set" and hints that you unset it. Following that hint leaves a
working formatter and no gate. The stub in `.githooks/` calls `pre-commit run` itself when a config
and the binary are both present, so both run and the guard stays last: a formatter that rewrites
files cannot slip the change past the scan.

The kit passed ruff's default rules in that check. A stricter configuration reported 155 requests to replace %-formatting with f-strings. Consumers applying their own lint policy can exclude submodules with `extend-exclude = ["guards", "style"]`.

A module of yours with the same name as one here wins. With the repository's own directory first on
`sys.path`, `import datadir` resolves to the repository's, not the kit's. A root `conftest.py` also
wins over the one here. The reverse only happens if you put the kit's path first, which is a choice.

In that consumer check, new top-level packages and tests were collected normally, `find_packages()` excluded the submodules, and root `pytest` excluded the kit suite while explicit `pytest guards/tools/` collected it. A `pytest.ini` with `testpaths` did not change those results, and tests left the submodules clean.

**Private facts in prose remain a gap.** Keeping DATA outside public source prevents accidental inclusion of those files. Structural rules recognize identifiers and the private list recognizes configured names, but neither establishes that prose contains no private facts. Public examples must use synthetic data.

## Languages

English (`README.md`) · 中文 (`README_CN.md`)

## Roadmap · Contributing · License

See [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) · [COMPANION.md](COMPANION.md).

The deviations from the house repository spec, and the reasons for each, are recorded in
[docs/2026-09-22-spec-adaptation.md](docs/2026-09-22-spec-adaptation.md).
