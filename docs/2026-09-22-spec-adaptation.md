# 2026-09-22: applying the house repository spec to the guard kit itself

This repository was brought in line with Skill Repo Spec v1, which was written for Claude Code skill
repositories. This one is the kit that enforces several of that spec's own chapters. Most of the
eleven chapters apply as written, a few need adapting, and a handful of individual requirements are
refused outright because meeting them would mean claiming something untrue.

This file is the record of those decisions, so the next person auditing this repository against the
spec finds a reasoned position rather than silence, and can argue with it. It is dated evidence, not
a rule: the rules live in the tools, and the version history in `CHANGELOG.md`.

The self consumption point is worth stating once. Chapters 8 and 9 are implemented here, which makes
"does this repository install the gate" a different question than it is for a consumer: there is no
`guards/` submodule to install, because this is what would be installed. The gate runs against this
repository through `.github/workflows/pii-guard.yml`, which calls the shipped action by local path,
so a failure here is a failure every consumer would have seen.

## Refused, because meeting them would be a false claim

**No `.claude-plugin/plugin.json`.** Chapter 1 makes it mandatory so that a repository stays
installable with `/plugin install`. There is nothing here for that command to install: no
`SKILL.md`, no skill entrypoint, no agent behaviour at all. This repository is consumed by
`git submodule add`, and a manifest would be advertising rather than metadata.

**No "Claude Code Skill" badge.** Chapter 3 fixes the first badge as `Claude Code Skill` linking to
the Claude Code docs. The slot is kept, because a reader should learn from the first line of badges
what kind of thing this is, but its content is `Guard Kit / Git Submodule` linking to the install
section, which is both true and the thing a visitor needs to know first.

**No `claude-code`, `claude-plugin`, `claude-skill`, `claude` or `skill` topic.** Chapter 6 calls
these part of a nine topic identity fingerprint every repository carries. Five of the nine are false
here. This is a Git hook and CI kit written in Python; it contains no Claude integration, and
`skill` on GitHub reads as "Agent Skill", which this is not. Putting them on would pollute the
search results for the repositories where they are true. Of the remaining four, `ai`, `ai-agent` and
`agent` are honest and are carried, because the failure this kit exists to prevent is specifically
an agent authoring a public repository while looking at real private data. `llm` is not: nothing
here makes a model call or holds a prompt. So the base nine is read here as a base three, and the
domain topics carry the rest.

**No `SKILL.md`, and no L0 or L1 layer.** Chapter 11's first two layers are the frontmatter
description and the per invocation preamble, both of which exist because a skill pays for them on
every turn. This kit is executed by a hook or a CI step, never loaded into a context window, so
there is nothing to pay and nothing to budget. L2 through L5 apply unchanged: each tool's module
docstring is the home for its own reasoning, the two READMEs are the tour, and `ROADMAP.md` plus
`CHANGELOG.md` are the only places a version number appears in prose.

**No `.pii-allow`.** Chapter 8 lists it as a required file. It is a list of real third party
identifiers a repository is allowed to contain, each with an argued reason. This repository contains
none, and an empty allowlist asserts nothing. It is created when there is a first exemption to argue
for, and not before.

**The license, resolved the same day.** Chapter 3 makes `License: MIT` mandatory, linking to
`LICENSE`, and no such file existed here. None was invented: a badge asserting MIT over an
unlicensed repository is a false claim about what anyone may do with it, and it is exactly the kind
of false claim a reader acts on, which for a submodule other repositories pin is worse than for most.
The license question was then decided rather than deferred. `LICENSE` is MIT, identical to the rest
of the fleet, and the badge went in with it.

## Adapted, because the intent survives and the letter does not

**No dash-guard workflow.** Requirement 4 of the standardisation asks for
`.github/workflows/dash-guard.yml` when a repository carries a `style/` submodule with
`style/ci/dash-guard`. This repository has no `.gitmodules` at all and therefore no `style/`, which
is deliberate rather than an omission: the style kit was split out of here precisely so that the
security suite and the style suite answer separately whether every public repository must carry
them. Wiring up a workflow that points at a directory that is not here would be the fail open shape
this kit spends most of its lines refusing, so none was added.

**Version, set at 0.1.0 with the gap stated.** Chapter 7 asks for four copies of the version kept in
step: a manifest, two README badges, the ROADMAP heading and the CHANGELOG entry. This repository
declares no version anywhere. There is no `plugin.json`, no `pyproject.toml`, no `__version__`, and
a grep for one across the tree returns only unrelated matches. Per the standardisation instruction,
the floor is set at 0.1.0 in the badges, `ROADMAP.md` and `CHANGELOG.md`. Three prose copies with no
literal behind them are held in step by attention, which is the weak form, so `ROADMAP.md` carries
it as planned work rather than pretending the rule is met.

**The green feature badge counts rules, not scope.** Chapter 3 allows up to two quantified selling
point badges. One is carried, `Detection Rules 9`, because the number is checkable against the table
directly below it. A consumer count was considered and rejected: it changes whenever a repository
enrolls or leaves, and a badge that drifts away from the truth on its own is worse than no badge.

**The data-boundary toolchain is this repository.** Chapter 9 requires `tools/datadir.py`,
`tools/test_datadir.py`, `tools/data_boundary.py` and `tools/make_fixtures.py` in every repository.
The first three are here as the originals rather than as copies. `make_fixtures.py` is absent
because this repository declares no FIXTUREs: a generator with nothing to generate would print a
green line forever, and the chapter's point is that a fixture must be reproducible, not that a
generator must exist. `.dataclass.json` argues both the empty DATA list and the empty FIXTURE list
rather than defaulting to them, and it names where the one write in shipped code actually lands,
which is outside every work tree.

## What was measured, and where

| Claim | How it was checked |
| --- | --- |
| The kit's own suite passes | `python -m pytest tools/ -q` at the repository root: 330 passed, 1 skipped |
| The scanner is armed, not merely present | `python tools/pii_guard.py --tree` prints `clean (tree) [28 file(s) scanned, 0 skipped]`; the file count is the part that distinguishes clean from never checked |
| The boundary is armed | `python tools/data_boundary.py` prints clean over 28 tracked files with 0 DATA and 0 FIXTURE paths, which is the conclusion `.dataclass.json` argues |
| The companion document still matches the resolver | `python tools/test_companion_contract.py` passes all four of its sections, including the refusal to resolve a data directory inside the repository |
| No style submodule exists to wire | No `.gitmodules` in the tree, and no `style/` directory |
| The repository declares no version | A tree wide grep for `version`, `VERSION` and `__version__` outside `__pycache__` returns only Python version pins in workflows, a GitHub API header and prose inside comments |
