# Rules for public repositories

What an author of an opted-in public repository must do so that real data never reaches it. The
companion interface is [COMPANION.md](../COMPANION.md); commit and push scope is
[PUBLICATION_POLICY.md](PUBLICATION_POLICY.md).

## A public repository is an uninitialized tool

It ships complete code, schemas and synthetic examples, imports and runs, and knows nothing about
anyone. Every real record lives in a PRIVATE companion. The point is not that data is hidden but that
an agent writing the public repository has no real file at hand to copy an example from. A scanner
reads what is about to be published and looks for things that smell private; a run ledger of
tickers, entry dates and prices smells of nothing. Storage separation is the primary control and
`pii_guard` is the backstop.

## The data boundary

Every path is TOOL, FIXTURE or DATA, declared in `.dataclass.json` (see COMPANION.md).

1. **The test is public versus private, not tracked versus untracked.** DATA lives in its PRIVATE
   companion and is committed there; a companion is the right home for real history. A loose
   directory under the home folder is not: it is the one copy of the run history with no history, no
   diff and no backup. DATA never appears in a public repository.
2. **No in-repository fallback.** "If the private directory is missing, use the copy in the
   repository" is the leak itself. A missing companion raises with initialization instructions.
3. **Reads degrade, writes fail.** A reader with no ledger reports an uninitialized tool and exits
   0. A writer that cannot reach its companion fails hard; the only alternatives are dropping a real
   observation or writing into the repository, and both are bugs.
4. **Fixtures come from the generator.** `tools/make_fixtures.py` is the only producer and
   `data_boundary.py` checks byte equality. A real record cannot be reproduced by the generator, so
   pasting one into a golden fails at commit time. To change a fixture, change the generator's case
   table and rerun it.
5. **Documentation never points at an in-repository DATA path.** Documents name the companion,
   resolved through `fleet_guards.runtime.companion_resolver(source_root=...)`, and writers apply the
   resolver's path check before writing; a successful resolve alone is not write permission.
6. **Dead paths are sealed.** A path that once held real data and must not come back is declared
   `data_sealed`: never tracked, no schema required. `.gitignore` is advice that `git add -f` walks
   past; the declaration is enforced.
7. **Run-shaped files fail regardless of declarations.** `data_boundary.py` reads the tracked file
   list and rejects anything shaped like real output: jsonl ledgers under `metrics/`, anything under
   `runs/`, dated files in output directories, known live ledger file names, database files. A
   hand-written file that has to look like a ledger is listed in the `tool` allowlist with its
   reason, where the diff shows it.
8. **An empty `data` list is an audited conclusion, not a default.** Ask whether shipped code or
   shipped documents can put real output at a repository-relative path, through any flag, variable
   or working-directory default, not merely whether something writes to a tracked file today.
9. **A missing gate is a failure.** The shims block when `fleet.guards` is unset or the hook is
   absent; nothing skips a check because its file is not there.

Each repository carries:

```
.githooks/pre-commit, .githooks/pre-push   forwarding shims (README, "Opting a repository in")
.dataclass.json                            data / data_sealed / fixture classes and the tool allowlist
.pii-allow                                 this repository's exemptions, one line each with a reason
tools/make_fixtures.py                     only when the repository has FIXTUREs
<data path>.example                        the schema of each DATA path, never its content
```

## Identifiers and history

1. **Allowlist, not denylist.** Public text uses only the declared synthetic namespace:
   `user1@example.com`, `example-employer.com`, `(555) 867-5309`, ZIP `10001`, `AcmeCorp`. Anything
   shaped like a real identifier outside it fails. A list of real identifiers is itself a private
   document, so the optional term list (`~/.pii-denylist.json`) stays outside every public
   repository.
2. **History is part of the product.** Once private data is in a commit, editing the file does not
   fix it: rewrite the commit (`git filter-repo`), force-push every branch and every tag (a tag pins
   the old commit), then verify from a fresh clone of the remote. Check the working tree,
   `git log --all -p`, commit messages, and author and committer identities.
3. **Commit identity is a GitHub noreply address** (`<id>+<handle>@users.noreply.github.com`). A real
   address on an author or committer line fails; no file scan can see it.
4. **Exceptions are argued in the diff.** A third-party business address or phone number that a
   parser must match literally goes into `.pii-allow` with a reason. The operator's own data never
   goes there.
5. **Never bypass the hooks.** No `--no-verify`, and no `git commit` or `git push` piped into a
   command that truncates output: a broken pipe kills the hook and its exit code means nothing.

## What it cannot close

Prose. An agent that has read the operator's mail can type a real employer, a rate or a quoted
conversation into a CHANGELOG from memory without naming anyone. No file boundary and no pattern
catches it. The only control is the author's rule: every example is invented.
