# fleet-guards

The guard kit for this fleet, in one place, consumed as a git submodule.

## What is in here

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
twelve pure text helpers that carry no security role at all. The two gates that were purely
style and architecture, dash_guard and load_budget, now live in fleet-style: they were 17.5% of
this repo and none of it was about keeping an identifier out of a public history.

## Why this repo exists

Before this, the kit was copied by hand into every consuming repo: 17 files, 7,643 lines, times 22
repos, about 191,000 lines on disk. The copies were byte identical and a single installer could
resync them all, so duplication was not the real cost. The real cost was that the installer worked
from a hand written list of repositories, and a repo missing from that list got, in the installer's
own words, "the appearance of a gate and none of the maintenance". That is not hypothetical: two
PUBLIC repos sat on a fail-open pre-push hook for exactly this reason, found on 2026-08-31.

A submodule replaces the list with a pointer that lives in the consuming repo itself.

## How to consume it

    git submodule add -b main https://github.com/DaizeDong/fleet-guards.git guards
    git config core.hooksPath guards/hooks

USE THE HTTPS URL, not an ssh host alias. `.gitmodules` is committed and shared, so the url has to
resolve for everyone who clones, including a CI runner. The first migration used a local ssh alias
and all three workflows failed immediately with "Could not read from remote repository". This is
also why this repo must stay public: a private submodule breaks CI in every public consumer.

Clone with `--recursive`, or run `git submodule update --init` afterwards. CI must set
`submodules: true` on actions/checkout.

## How to update a consumer

    git submodule update --remote guards
    git add guards && git commit -m "guards: bump"

A submodule pins one commit and does not follow the source on its own. That is deliberate: the
consuming repo decides when to take a new version, and the version it is on is recorded in its own
history.

## THE FAILURE MODE TO KNOW ABOUT

A plain `git clone` without `--recursive` leaves `guards/` EMPTY. So does a CI checkout without
`submodules: true`. The hooks are written to fail closed on a missing scanner, so that state blocks
a commit loudly rather than passing in silence, which is the only reason this arrangement is safe.
If you ever see the guards directory empty, the answer is `git submodule update --init`, never
`--no-verify`.

## Adding things to a repo that consumes this

Measured on a real consumer, not reasoned about. Four things behave differently once a submodule
is in the tree, and only one of them will actually stop you.

**The pre-commit framework will refuse to install.** `pre-commit install` prints "Cowardly refusing
to install hooks with `core.hooksPath` set" and hints that you unset it. Following that hint leaves
you with a working formatter and no gate. The stub in `.githooks/` calls `pre-commit run` itself
when a config and the binary are both present, so both run and the guard stays last: a formatter
that rewrites files cannot slip the change past the scan. Nothing to configure.

**A linter walks in here.** This kit is clean under ruff's default rules, so `ruff check .` in a
consumer reports nothing from it. Under an opinionated set it is not, and cannot be: 155 of the
findings at that level are "rewrite %-formatting as f-strings" across a scanner where that churn
buys no correctness. If you turn those on, exclude the submodules:

    [tool.ruff]
    extend-exclude = ["guards", "style"]

**A module of yours with the same name as one here wins.** Verified: with the repo's own directory
first on `sys.path`, `import datadir` resolves to the repo's, not the kit's. A `conftest.py` at the
repo root also wins over the one here. The reverse only happens if you put the kit's path first,
which is a choice, not a default.

**Everything else was checked and is a non-event.** A new top-level package and its tests are
collected normally; `find_packages()` returns nothing from the submodules; `pytest` at the root
does not pick up the kit's suite (`pytest guards/tools/` still does, deliberately); a `pytest.ini`
with `testpaths` changes nothing here; and the submodules never show as dirty after a test run.
