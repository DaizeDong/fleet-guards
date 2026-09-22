# Changelog

All notable changes to this project are documented here (Keep a Changelog style).

## [Unreleased]

### Changed

- **docs: unify repo structure (Skill Repo Spec v1).** The README keeps its substance and takes the
  spec's section order, philosophy first, with an honest badge row. `README_CN.md` was added as a
  section for section counterpart, and the mandatory `ROADMAP.md` and `CHANGELOG.md` alongside it.
  Nothing about the kit's behaviour changed, so no functional version was bumped.

  Six requirements of that spec are deliberately not met, each because meeting it would claim
  something untrue of a guard kit rather than a skill, and all six are argued in
  `docs/2026-09-22-spec-adaptation.md` rather than left as a silent gap: no
  `.claude-plugin/plugin.json`, no `SKILL.md` and therefore no L0 or L1 documentation layer, no
  license badge until a `LICENSE` file exists, no `.pii-allow` until there is an exemption to argue
  for, no dash-guard workflow because this repository carries no `style/` submodule, and five of the
  nine fingerprint topics refused. The base nine is read here as a base three: `ai`, `ai-agent` and
  `agent` are carried; `claude-code`, `claude-plugin`, `claude-skill`, `claude` and `skill` are not,
  and `llm` is judged against because nothing here makes a model call.

### Added

- **A declared version, at 0.1.0.** This repository declares no version in code, in packaging
  metadata or in any manifest, so the spec's four way version agreement had nothing to agree with.
  The floor is set here and in `ROADMAP.md`, and the gap is recorded rather than papered over: with
  no literal to read, the three prose copies are held in step by attention, which `ROADMAP.md` lists
  as planned work rather than as a solved problem.

## [0.1.0] - 2026-09-22

### Added

- The guard kit as a git submodule: the allowlist scanner, the data boundary, the companion
  resolver, their tests, the commit and push hooks, and the composite CI action every consumer
  references by local path.
- Automatic submodule synchronization, dispatching verified upstream updates to enrolled consumers.

### Changed

- **The kit stopped being copied into every consumer.** Seventeen files and 7,643 lines, times 22
  repositories, were resynced by an installer that worked from a hand written list. A repository
  missing from that list received the appearance of a gate and none of the maintenance, which is
  how two public repositories came to sit on a fail open pre-push hook, found on 2026-08-31. The
  list is replaced by a pointer that lives in the consuming repository.
- **The kit's own workflow runs the shipped action rather than a second copy of it.** Two copies of
  the same argument, one shipped and one proving the source repository green, is how a shipped path
  breaks while its origin keeps passing.
- **The style gates moved out.** `dash_guard` and `load_budget` were 17.5% of this repository and
  neither was about keeping an identifier out of a public history. They live in `fleet-style`, which
  answers a different question about which repositories must carry it.

### Fixed

- **Steps that skipped themselves when their file was absent.** Gate steps wrapped in `if [ -f ... ]`
  went green in a repository whose copy had gone missing. Absent is now a failure, verified on
  2026-07-31 by deleting each file and watching the step exit non-zero.
- **A contract that ran nowhere.** `test_companion_contract.py` is a script rather than a pytest
  module, so every job that looked like it covered the kit collected nothing from it. It was failing
  when it was found on 2026-09-04, because a resolver change had made the document stale, which is
  exactly the drift it exists to catch.
