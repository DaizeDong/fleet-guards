# Roadmap

Current: **v0.1.0**

Shared Python package: **v0.3.0**, including consumer-bound companion discovery
and the storage contract accessor. See [PACKAGE.md](PACKAGE.md).

## v0.1.0 (current)

Feature names only. Why each one behaves the way it does lives in the tool that implements it,
which is the single home for that reasoning, and what changed lives in `CHANGELOG.md`.

- The scanner: nine detection rules across 38 regexes, allowlist based, over staged changes, the
  working tree and the full history (`tools/pii_guard.py`).
- The policy layer: a private term list that stays on one machine, with a load proof so a list that
  failed to load is refused rather than treated as empty.
- The data boundary: every path declared TOOL, FIXTURE or DATA in `.dataclass.json`, with fixtures
  required to be generator reproducible (`tools/data_boundary.py`).
- The companion resolver: documented probe locations in a fixed order, a proof requirement, and a refusal
  to resolve a data directory that sits inside the skill's own repository (`tools/datadir.py`).
- The companion contract (`COMPANION.md`).
- Source-owned storage contract validation and path matching
  (`tools/storage_contract.py`, `docs/STORAGE_CONTRACT.md`).
- Per-repo commit and push gates with one implementation, run from one local checkout named by
  `git config fleet.guards` through each consumer's `.githooks/` shims, blocking on an unset key, a
  missing kit, a failing interpreter and a comparison that cannot prove it runs (`hooks/pre-commit`,
  `hooks/pre-push`).
- Window-less process spawning: every process the kit starts goes through one helper that gives a
  console-less caller's children a hidden console.

## Planned

- **A control for prose that leaks without naming an identifier.** The boundary removes the real
  file, the structural rules recognise shapes and the private list recognises names. A sentence that
  describes a private fact in general words passes all three. This is the single largest gap, and
  nothing here closes it.
- **A measured false-negative rate for the denylist layer.** The structural rules have negative
  controls. The private layer's recall is asserted by argument rather than by a scored corpus.
- **A run-shape check that is calibrated against real output.** The shape list recognises jsonl
  ledgers, dated files under output directories, database files and, since 2026-09-27, Claude Code
  session transcripts. Formats outside that list, an image among them, pass a repository whose only
  real output is that format.
- **One version literal.** The toolkit version in the badge, this heading and the
  changelog is maintained separately from the Python package version in
  `pyproject.toml`.
