# The companion repository contract

This public repository is an **uninitialized tool**. Everything a real run produces lives somewhere
else, in a private repository beside this one, and this file is the contract between the two.

It exists so that a companion built by anyone, on any machine, plugs in without reading this
skill's source. If you are restoring a machine, or wiring up a companion that somebody else made,
this file is the whole interface.

## Why the output lives outside

Real run records may contain private facts without recognizable identifiers. Repository-relative output defaults caused the 2026-07 leakage audit findings, so storage separation is the primary control and content scanning is a supplement. The [design rationale](README.md) explains the boundary.

Every source path has one class in `.dataclass.json`:

| Class | Contents | Location |
|---|---|---|
| TOOL | Code, documentation and metrics about the tool | Public source |
| FIXTURE | Tests, goldens and examples | Public source; synthetic and generator-produced |
| DATA | Real run output | PRIVATE companion; physically absent from public source |

## How the companion is found

`tools/datadir.py` probes these locations in order and takes the FIRST ONE THAT EXISTS as a
directory. Discovery proves the companion identity described below; PRIVATE publication is enforced at commit time, not at discovery or write time. `<SKILL>` is this repository's name uppercased with hyphens turned into underscores, so
`small-cap-deepdive` becomes `SMALL_CAP_DEEPDIVE`.

| Order | Location | Notes |
|---|---|---|
| 1 | `$<SKILL>_DATA_DIR` | the data directory itself, not a repo root |
| 2 | `$<SKILL>_CONFIG/data`, then `$<SKILL>_CONFIG` | also `$<SKILL>_CONFIG_DIR` |
| 3 | `<sibling>/data`, then `<sibling>` | **the convention**: a directory named `<skill>-config` beside this repository |

There is no home-directory location. `~/.<skill>-config` and `~/.<skill>-data` were probed until
2026-10-12 and are not any more: a directory in the home folder is not a repository, so nothing
versioned, backed up or pushed what a skill wrote there. A machine with neither a variable nor a
sibling companion is uninitialized; readers report that, and writers raise `DataDirNotInitialized`
with how to create the companion.

Two properties of this list are load bearing and were each added after a measured failure.

**The sibling convention is probed at all.** Discovery once depended entirely on an environment
variable, so the answer to "where is this skill's data" depended on whether somebody had remembered
to export something on that particular machine. Measured across eight skills with real data: three
resolved to the companion because their variable happened to be set, three fell through to a home
dotfile while the companion repository sat right beside them, and three answered "uninitialized"
while one of those had 153 tracked files in its companion. Those three were invisible to the
boundary tooling and every report about them was green.

**Both the `data/` subdirectory and the root are probed.** Two shapes exist in this fleet and both
are legitimate. Most companions keep output under `data/`. Some file it directly at the root. A
resolver that knew only one shape reported "no data" for a repository whose files were in plain
sight.

If nothing is found, `resolve_data_dir` returns `None` and the skill must degrade to uninitialized
rather than inventing a path. A resolved directory that turns out to be inside this repository is a
hard error, `DataDirInsideOwnRepo`, never a silent fallback: a fallback into the repository is
precisely the leak this whole boundary exists to prevent.

## The minimum a companion has to be

```
<skill>-config/
  .gitignore        REQUIRED
  README.md         REQUIRED
  data/             where real-run output goes
```

- It is a **git repository with a PRIVATE remote**. Private is the point, not un-versioned: the
  companion is exactly where a person's real output legitimately lives, with a history, a diff and
  a backup. The rule is "DATA never in a PUBLIC repo", not "DATA never in git", and conflating the
  two has already produced one wrong verdict in this fleet.
- The normal layout is **beside this repository**, named `<skill>-config`. The discovery table also supports explicit environment variables; there is no home-directory location, and no location inside public source is permitted.
- It must **prove it is the companion**, and a directory that merely sits at the right path does
  not qualify. `is_dir()` was the whole test once, so anything created at a candidate path won:
  a scratch directory made during unrelated work, an empty folder left by a failed run, a
  same-named directory belonging to something else. The resolver would hand it back and a skill
  would write real output into it. Either proof is sufficient and most companions already have the
  first without doing anything:

  - **a git remote whose URL ends in `<skill>-config`.** A real companion has one; a stray
    directory has no remote at all.
  - **a `.companion` file whose first line is the skill's name.** For a companion that is not a
    git repository, or whose remote is named differently for a reason.

  With neither identity proof, the resolver raises `CompanionUnproven`. A marker can establish discovery identity for a non-Git directory, but DATA still belongs in a versioned PRIVATE Git repository.
- Real output is **tracked or ignored, never loose**. Output that is neither is in a limbo where
  nothing backs it up and where `git status` is buried under so much noise that a genuinely new
  file cannot be seen. Measured on one companion: 35 loose run trees, 1640 files, 1.5 GB, against
  40 tracked files.

Anything else a companion contains is that skill's own business. Several in this fleet carry
`registry.json`, `runbooks/`, `scripts/` or `secrets/`, and those are conventions of one skill
rather than part of this contract. Do not add them to satisfy a checker; nothing checks for them.

## What this repository promises in return

- It **reads** the companion. It does not write this repository's own tree, and no default here
  points inward.
- It **works uninitialized**. With no companion present the skill still loads, still explains
  itself, and reports that it has no data rather than failing.
- It ships **only the schema**. Every declared DATA path has a `<path>.example` beside it here, so
  the shape is public and the content is not.

## Verifying a companion

A companion is verified when it commits or pushes: its own hooks and CI run
`publication_guard.py`, which calls `prove_private_companion` against the visibility receipt
`~/.pii-guard/visibility.json`.

The receipt uses the same `owner/repository` to `PUBLIC`/`PRIVATE`/`UNKNOWN` mapping and `_refreshed` timestamp as `pii_guard`. Its age must be known and no more than 30 days. Every effective fetch and push URL across all configured remotes must resolve to a repository marked `PRIVATE`; Git URL rewrites and additional push URLs are checked. The guard prints the verified repository names and allows versioned DATA there. SSH aliases require an explicit `HostName github.com` in every plausible configuration chain. Missing or stale evidence, public destinations, unrecognized clients, and unproved routing or trust settings block admission. See [the transport contract](COMPANION.md#verifying-a-companion) for the supported SSH and HTTPS configurations. This check uses the local receipt and does not make network calls.

Companion discovery starts at the physical DATA destination, independently of the invoking hook's
repository and index. Its stored repository configuration and its effective process configuration
must both identify only PRIVATE destinations. A temporary URL rewrite cannot turn a PUBLIC store
into an authorized companion. Linked worktrees remain supported.

### SSH transport

Visibility evidence must be fresh and PRIVATE for every effective fetch and push URL, including Git URL rewrites. Canonical HTTPS URLs are supported. Canonical SSH URLs and SSH aliases require a recognized system or Git-bundled OpenSSH client and statically verifiable default configurations. Each distinct SSH host is checked; an alias additionally needs an explicit `HostName github.com` in every plausible user/system configuration chain. On Windows, a selected Git installation's bundled SSH takes precedence over the SSH executable found on Python's PATH.

The SSH policy permits client identity and authentication settings, and explicit `HostName github.com`, `User git`, and `Port 22`. Server authentication must use the default known-hosts files, with `StrictHostKeyChecking` absent or set to `yes` or `ask`. Disabling verification, automatically accepting new keys, or overriding either known-hosts file produces UNKNOWN; the static check cannot prove a custom trust file. Custom Git SSH commands or variants, `GIT_EXEC_PATH` overrides, remote helpers, remapped hosts, proxies, `Include`, `Match`, embedded NUL bytes, and other unsupported active syntax produce UNKNOWN. Configuration commands and `ssh -G` are never executed during this check. Use canonical HTTPS when an SSH configuration cannot be proven by this policy.

### HTTPS transport

The HTTPS policy checks both physical and effective Git configuration before granting PRIVATE admission. Default routing and certificate trust are supported, as is an explicitly enabled `http.sslVerify`. OpenSSL and Windows Schannel backend selections are supported. Git for Windows may explicitly name its own packaged CA bundle through an absolute path belonging to the selected installation; the certificate path must pass regular-file and filesystem-alias checks. This recognizes packaged trust without reading certificate contents. Custom CA files, unknown backends, disabled verification or Schannel revocation checks, and Schannel custom-CA enablement produce UNKNOWN.

HTTP version, connection counts, buffering, low-speed limits, and keepalive tuning remain supported. Apart from the authentication headers below, other HTTP options, including URL-scoped settings, remote proxies, resolver entries, redirects, and headers require transport proof that this static check does not provide, so they produce UNKNOWN. Every configuration occurrence is checked, including an unsafe override followed by a default or empty value.

HTTPS authentication may use a single-line Basic or Bearer Authorization header through `http.extraHeader`
or the canonical `http.https://github.com/.extraHeader` key. Each occurrence is checked independently.
Other header names, foreign URL scopes, leading whitespace, tabs, embedded line breaks and NUL bytes
remain unproved. This supports the credential header written by `actions/checkout` without authorizing
a different destination or trust configuration.

Certificate, TLS-backend, Git-helper and HTTP request environment overrides produce UNKNOWN unless explicitly supported by the policy. Environment proxies are permitted only when every present spelling of `NO_PROXY`/`no_proxy` provably bypasses `github.com`: either the whole value `*`, or an exact comma-separated `github.com` or `.github.com` entry. Trust overrides are checked separately; an unproved bypass still fails. Git low-speed environment settings do not alter admission. The check never executes an override or prints its value. Restore supported HTTPS settings or use the separately verified SSH policy before retrying; a fresh visibility receipt alone cannot establish a modified connection's destination.

### Proof API

`prove_private_companion(destination, visibility_map=None)` in `tools/data_boundary.py` is the
proof the commit-time publication guard and fleet_sync use. It returns an immutable proof
with `root`, sorted `repositories`, and an opaque `signature` binding the canonical repository
administration and physical/effective Git configuration snapshots. It is not a write-time API:
consumers do not call it before writing DATA. PRIVATE publication is enforced by the hooks and CI.

Git's default injected `GIT_EXEC_PATH` is normalized
only by the normal hook entrypoint after resolving the same Git executable and checking its default;
the executable, default helper directory and all ancestors must be free of filesystem aliases,
and the supplied helper path must use the normalized default spelling.
The companion proof API continues to reject an unproved helper-path environment override.
Git for Windows discovery recognizes its `cmd`, `bin`, architecture `bin`, and architecture
`libexec/git-core` launchers. The latter is prepended to PATH by native Git hooks. Each layout
resolves the same packaged SSH configuration and CA bundle; unknown layouts remain unproved.

Explicit `remote.pushDefault` and `branch.*.remote` or `branch.*.pushRemote` values must name a configured remote, preserving the remote name's case. Local `.` selectors, missing remotes and direct URL/path selectors are unproved and fail admission. No particular remote name, including `origin`, is required.

```
python tools/data_boundary.py                 # this repo holds no run output
python tools/data_boundary.py --explain <name> ...   # would a given output name be recognised
```

`--explain` is the one to reach for when wiring up a companion somebody else built. Feed it the
filenames that companion actually holds. Names it does not recognise are not necessarily wrong, but
they are names this repository's boundary check would not notice if they ever appeared on this side.

`.dataclass.json` carries `_run_shape_probes`, the schematic filenames a real run of this skill
produces. **Schematic is the rule, not a style preference.** A probe carrying a real ticker, a real
mailbox handle, a real account id, a real person or company name is private data in a public
repository even with no file behind it, which would reintroduce the leak under the banner of
preventing it. Write `<ticker>`, `<run-id>`, `<account>`, `<date>` instead.
