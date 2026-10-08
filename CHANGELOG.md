# Changelog

All notable changes to this project are documented here (Keep a Changelog style).

## [Unreleased]

### Changed

- **PRIVATE companion proofs respect explicit proxy bypass rules.** When a
  supported proxy is bypassed for every GitHub transport route, the proof
  validates that effective route instead of rejecting the unused proxy.
  Ambiguous or unproved overrides remain refused; synthetic fixtures cover
  both the permitted bypass and blocked transport cases.

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

- **Source-owned artifact write admission.** `tools/storage_contract.py` holds
  the validation and matching primitives shared with Smith and a read-only
  `authorize_artifact_write` API. It requires a unique declared owner, an exact
  PRIVATE versioned companion root, safe path topology, and effective ignore
  checks before a write. Explicit source `persistence: transient` with a concrete
  reason permits ignored temporary artifacts; rebuildable retention alone does
  not. Publication routes and source policy are rechecked before returning.
  Equivalent unrestricted root-glob spellings are rejected by the shared validator.
  Windows case aliases, NTFS short names, and reserved console/device names cannot
  bypass declaration ownership or address Git metadata.
  The synthetic admission suite runs in the shared CI action. See
  `docs/STORAGE_CONTRACT.md` for the API and its concurrency boundary.

- **Claude Code transcript shapes in `data_boundary.py`.** Check 4 did not recognise a session
  transcript, so a real conversation committed into a public repository passed. Four shapes now
  cover it: a `<uuid>.jsonl` or `.jsonl.gz` session file (and the `.fork-<uuid>.tmp` staging copy),
  a `subagents/**/agent-<id>.jsonl` subagent transcript or its `.meta.json`, a `<uuid>/` directory
  holding `subagents/`, `tool-results/` or `workflows/`, and anything under an encoded project
  directory (`C--Users-<x>-<y>/`, `-home-<x>-<y>/`) or `.claude/projects/`. Each needs something no
  hand-written file carries, so a bare `*.jsonl` fixture does not match. Before promotion the list
  was scored against every tracked file of every local repository: no consumer gains a finding, and
  the only new hits across 240 repositories are genuine session-tree files in a private one. Negative controls and over-rejection controls are in `tools/test_data_boundary.py`; a
  transcript-shaped fixture stays possible through `fixture` plus a generator, as for any other.

- **Runner choice for the shared sync workflow.** `sync-consumer.yml` takes an optional `runs-on`
  input, a JSON string of one label or a label array, read with `fromJSON`. The default is
  `"ubuntu-latest"`, so consumers that pass nothing run exactly as before. It exists for private
  consumers whose GitHub-hosted jobs no longer start and must sync on a self-hosted runner.

- **A declared version, at 0.1.0.** This repository declares no version in code, in packaging
  metadata or in any manifest, so the spec's four way version agreement had nothing to agree with.
  The floor is set here and in `ROADMAP.md`, and the gap is recorded rather than papered over: with
  no literal to read, the three prose copies are held in step by attention, which `ROADMAP.md` lists
  as planned work rather than as a solved problem.

### Fixed

- **No process the kit starts can open a console window.** A daemon running under `pythonw` proved
  its private companion on every log line. Each proof ran about 19 git commands through
  `data_boundary.py`, none of them asked for a hidden console, and a process with no console hands
  every console child a new one, which Windows shows as a window: roughly 9,000 terminal windows in
  eight hours. Every spawn in `tools/` now passes through `_no_window()`, which adds
  `CREATE_NO_WINDOW` when the caller has no console and changes nothing when it has one, because a
  shared console never opens a window and hiding it would swallow a hook's unredirected findings
  (measured: an unredirected child's output is lost under the flag). `DETACHED_PROCESS` and
  `CREATE_NEW_CONSOLE` are refused. `tools/test_no_console_window.py` checks every copy of the
  helper, scans every Python file in the kit for a spawn that bypasses it with thirteen planted
  bypasses as negative controls, and runs the companion proof, its read-only queries, the resolver
  lookup, the fixture check and the scanners' git runners with `Popen` recorded. On Windows it also
  runs the incident's own shape for real: `pythonw` calling `data_boundary._run`, whose child must
  have a console and no visible window.

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
