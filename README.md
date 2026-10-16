# fleet-guards

Shared publication guards for Git repositories: nine detection rules, a data boundary, and hooks that block when required checks are unavailable. The kit runs from one local checkout per machine; consumers opt in with two small hook shims.

Python consumers use the [installed runtime package](PACKAGE.md) for companion discovery and storage contracts.

[![Guard Kit](https://img.shields.io/badge/Guard%20Kit-Local%20Checkout-orange?style=flat)](#install)
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

**Report incomplete checks as failures.** A missing kit checkout, an unset `fleet.guards`, absent declarations and failed Git reads must block the affected check. Reports distinguish a completed scan with no findings from a scan that never ran.

## What it is (and isn't)

It is the fleet's security kit: the scanner, the data boundary, the companion resolver and the Git
hooks. It lives in one checkout per machine, named by the global git config key `fleet.guards`.
Only repositories that opt in with the `.githooks/` shims are checked; there is no machine-wide hook
and no CI step.

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

This repository is a Git hook toolkit without a Claude Code skill or plugin entrypoint. Style and loading-budget scripts belong to `fleet-style`.

## Install

Once per machine:

    git clone https://github.com/DaizeDong/fleet-guards.git <path>
    git config --global fleet.guards <path>        # forward slashes, e.g. C:/src/fleet-guards
    pip install -e "$(git config --get fleet.guards)"

The checkout stays on `main`. Edits to the kit happen in a `git worktree` of it, so the checkout the
hooks run from is never half-edited. To try a worktree's hooks before merging, override the key for
one command: `git -c fleet.guards=<worktree> commit ...`.

## Opting a repository in

Commit two shims and point the repository's hooks at them:

    git config core.hooksPath .githooks
    git update-index --chmod=+x .githooks/pre-commit .githooks/pre-push

`.githooks/pre-commit`:

```sh
#!/bin/sh
# Privacy checks run from the local fleet-guards checkout named by git config fleet.guards.
G=$(git config --get fleet.guards)
if [ -z "$G" ] || [ ! -s "$G/hooks/pre-commit" ]; then
  echo "BLOCKED: git config fleet.guards is unset or has no hooks/pre-commit; nothing was checked." >&2
  exit 1
fi
exec sh "$G/hooks/pre-commit" "$@"
```

`.githooks/pre-push` is the same with `hooks/pre-push` in both places. A repository that also uses
the `fleet-style` dash check adds that block before the `exec` (see the fleet-style README).

The shims read `fleet.guards` with plain `git config --get`, so `git -c fleet.guards=...` overrides
it. An unset key or a checkout without the hook blocks; there is no fallback location.

A repository that uses Git LFS must call LFS's own hooks from its `.githooks/` shims
(`git lfs pre-push "$@"` before the `exec` in pre-push, and the matching post-checkout,
post-commit and post-merge shims), because `core.hooksPath=.githooks` replaces the directory
where `git lfs install` put them.

Each repository keeps its own `.pii-allow` and `.dataclass.json`: which findings are exempt and
which paths are TOOL, FIXTURE or DATA are facts about that repository.

## What runs

`hooks/pre-commit` holds the logic for both phases; `hooks/pre-push` re-executes it with
`--phase pre-push`.

- **Commit:** the identity assertion against `~/.pii-guard/identities.conf`, then
  `publication_guard.py pre-commit`, which runs `pii_guard.py --staged` (only what is being
  committed) and `data_boundary.py`.
- **Push:** `publication_guard.py pre-push`, which runs `pii_guard.py --tree --history` and
  `data_boundary.py`. A push that only deletes refs publishes nothing and is skipped.

Both call `python` directly; a missing or broken interpreter returns nonzero and blocks.

The [publication policy](docs/PUBLICATION_POLICY.md) decides scope. Current evidence must prove every stored and effective fetch/push destination PRIVATE before private content is admitted. Missing evidence retains full public checks. Manifest, schema, fixture, path and identity requirements still apply to PRIVATE repositories.

Direct `pii_guard.py --tree --history` and `data_boundary.py` commands always use public policy. For companion admission, including receipt freshness and supported transports, follow [COMPANION.md](COMPANION.md#verifying-a-companion).

## What is in here

| Path | What it is |
| --- | --- |
| `tools/pii_guard.py` | The scanner. Allowlist based, structural, runs over staged changes, the working tree or the full history. |
| `tools/data_boundary.py` | Checks declared classes, fixtures and real-output boundaries. |
| `tools/publication_guard.py` | Applies proven repository visibility to the commit and push policy. |
| `tools/datadir.py` | The resolver. Decides where real-run output goes, which is always outside the repository. |
| `tools/storage_contract.py` | Validates a companion's `storage.contract.json` and path ownership. |
| `fleet_guards/` | The installed package; `fleet_guards.runtime` exposes the resolver and storage contract. |
| `hooks/` | `pre-commit` (both phases) and `pre-push` (re-executes it), the bodies the consumer's shims forward into. |
| `.githooks/` | This repository's own opt-in shims. |
| `COMPANION.md` | The contract between a public repository and its private companion. |

## Example output

```
$ python tools/pii_guard.py --tree
pii_guard: clean (tree)  [28 file(s) scanned, 0 skipped]

$ python tools/data_boundary.py
data_boundary: clean (0 DATA + 0 sealed paths not tracked, 0 FIXTUREs generator-reproducible,
28 tracked files carry no real-run shape)
```

Reports include examined and excluded counts so readers can distinguish coverage from an empty or incomplete scan.

## Starting processes on Windows

Every process the kit starts goes through `_no_window()`. A console program started by a process
with no console of its own (`pythonw`, a scheduled task, a service) otherwise gets a visible window.
The helper adds `CREATE_NO_WINDOW` only when the calling process has no console, so a hook's
unredirected output is never hidden, and it refuses `DETACHED_PROCESS` and `CREATE_NEW_CONSOLE`.
Each tool file carries its own copy, because the tools are loaded one at a time by path.

## Limitations

The pre-commit framework refuses to install: `pre-commit install` prints "Cowardly refusing to
install hooks with `core.hooksPath` set" and hints that you unset it. Following that hint leaves a
working formatter and no gate. Call `pre-commit run` from the `.githooks/pre-commit` shim before the
`exec` instead, so a formatter that rewrites files cannot slip the change past the scan.

**Private facts in prose remain a gap.** Keeping DATA outside public source prevents accidental inclusion of those files. Structural rules recognize identifiers and the private list recognizes configured names, but neither establishes that prose contains no private facts. Public examples must use synthetic data.

## Languages

English (`README.md`) · 中文 (`README_CN.md`)

## Roadmap · Contributing · License

See [ROADMAP.md](ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md) · [COMPANION.md](COMPANION.md).
