#!/usr/bin/env python3
"""Negative controls for tools/data_boundary.py -- the gate that had none.

WHY THIS FILE EXISTS
--------------------
data_boundary.py shipped as a CI job (.github/workflows/pii-guard.yml) and as both git hooks
(.githooks/pre-commit, .githooks/pre-push), and it is called the PRIMARY control in every document
in this fleet. Nothing had ever made it go red. That is not a paperwork gap, it is the same defect
the file's own docstring names: measured on 2026-08-27, its RUN_SHAPES patterns matched 0 of the
116 files one real daily run of this skill writes, so it printed "clean" every day while asserting
nothing about the one thing it exists to catch. A gate whose green nobody has ever contradicted is
indistinguishable from a gate that cannot speak.

So every check below is written as a POISONED REPO: a scratch work tree constructed to violate one
rule, run through the real script, asserting a nonzero exit AND that the offending path is named in
the output. Naming matters as much as the exit code; "1 violation(s)" with no path is a verdict
nobody can act on, and it would also pass a test that only looked at the return code.

Paired with each of those is an OVER-REJECTION control: the same scratch repo without the poison
must exit 0. A gate that is always red is as useless as one that is always green, and it is the
easier of the two to write by accident.

WHAT IS SYNTHETIC HERE
----------------------
Every filename below is a SHAPE this skill's pipeline really produces, reconstructed by hand. The
per-handle and per-subreddit shards in a real run tree are named after actual accounts and actual
subreddits, so those names are replaced with the synthetic namespace (example-handle-N,
r/example-*). The shape is the thing under test; the names inside it are nobody's business, and a
test fixture is the last place a real one should be recovered from.

Stdlib + pytest only. No network, no gh, no real repos: every repo here is built in tmp_path.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from make_fixtures import _no_window
from make_fixtures import write_record, write_visibility
from make_fixtures import write_invalid_git_marker
from make_fixtures import write_ssh_config, make_ssh_layout
from make_fixtures import declaration_name_cases, write_declaration_name_fixture


@pytest.fixture
def ssh_configuration(tmp_path, monkeypatch):
    """Attestation tests consume only generated configuration; discovery is tested separately."""
    import data_boundary as db
    paths = [write_ssh_config(tmp_path / "ssh-home", "absent"),
             write_ssh_config(tmp_path / "ssh-system", "absent", "ssh/ssh_config"),
             write_ssh_config(tmp_path / "ssh-git", "absent", "etc/ssh/ssh_config")]
    monkeypatch.setattr(db, "_ssh_config_paths", lambda: [str(path) for path in paths])
    return paths


@pytest.mark.parametrize("variant", ["absent", "identity", "canonical", "unrelated", "remap", "wildcard",
                                     "include", "match-exec", "proxy", "canonicalize", "port"])
def test_source5_ssh_configuration_destinations(tmp_path, monkeypatch, variant, ssh_configuration):
    import data_boundary as db
    companion, receipt = _companion_case(tmp_path, "git@github.com:example-owner/demo-config.git")
    if variant != "absent":
        write_ssh_config(ssh_configuration[0].parent.parent, variant)
    original = subprocess.run
    def git_only(args, *positional, **kwargs):
        from pathlib import Path
        assert Path(str(args[0])).name.lower() in {"git", "git.exe"}, "Attestation executed a transport command"
        return original(args, *positional, **kwargs)
    monkeypatch.setattr(subprocess, "run", git_only)
    proven, errors = db._companion_visibility(str(companion), str(receipt))
    allowed = variant in {"absent", "identity", "canonical", "unrelated"}
    assert bool(errors) is not allowed, errors
    assert proven == (["example-owner/demo-config"] if allowed else [])


@pytest.mark.parametrize("override", ["GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_CONFIG_COUNT",
                                      "core.sshCommand", "ssh.variant", "remote.origin.vcs",
                                      "remote.origin.uploadpack", "remote.origin.receivepack"])
def test_source5_ssh_transport_overrides_are_unknown(tmp_path, monkeypatch, override):
    import data_boundary as db
    companion, receipt = _companion_case(tmp_path, "ssh://git@github.com/example-owner/demo-config.git")
    if override == "GIT_CONFIG_COUNT":
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.sshCommand")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "synthetic-command-that-must-never-run")
    elif override.startswith("GIT_"):
        monkeypatch.setenv(override, "synthetic-command-that-must-never-run")
    else:
        git(companion, "config", override, "synthetic-command-that-must-never-run")
    proven, errors = db._companion_visibility(str(companion), str(receipt))
    assert errors and proven == []


@pytest.mark.parametrize("client", ["system", "git", "unknown", "missing", "missing-profile"])
def test_source6_ssh_default_configuration_discovery(tmp_path, monkeypatch, client):
    import data_boundary as db
    import shutil
    layout = make_ssh_layout(tmp_path / "ssh-discovery")
    for variable, name in (("HOME", "environment-home"), ("USERPROFILE", "userprofile"),
                           ("SystemRoot", "windows"), ("ProgramData", "program-data")):
        monkeypatch.setenv(variable, str(layout[name]))
    monkeypatch.setattr(db, "_ssh_profile_home", lambda: None if client == "missing-profile"
                        else str(layout["account-home"]))
    monkeypatch.setattr(os.path, "expanduser", lambda path: str(layout["expanded-home"]))
    system_client = (str(layout["windows"] / "System32/OpenSSH/ssh.exe") if os.name == "nt"
                     else "/usr/bin/ssh")
    selected = {"system": system_client, "git": str(layout["git-installation"] / "usr/bin/ssh.exe"),
                "unknown": str(tmp_path / "unknown/ssh"), "missing": None,
                "missing-profile": system_client}[client]
    executables = {"ssh": selected, "git": str(layout["git-installation"] / "bin/git.exe")}
    monkeypatch.setattr(shutil, "which", lambda command: executables[command])
    paths = db._ssh_config_paths()
    if client != "system" and not (client == "git" and os.name == "nt"):
        assert paths is None
        return
    expected = {str(layout[name] / ".ssh/config") for name in
                ("environment-home", "userprofile", "account-home", "expanded-home")}
    if os.name == "nt":
        expected.update([str(layout["program-data"] / "ssh/ssh_config"),
                         str(layout["git-installation"] / "etc/ssh/ssh_config")])
    else:
        expected.add("/etc/ssh/ssh_config")
    assert set(paths) == expected


@pytest.mark.parametrize("location", [0, 1, 2])
def test_source6_ssh_include_is_unknown_in_every_location(tmp_path, ssh_configuration, location):
    import data_boundary as db
    target = ssh_configuration[location]
    write_ssh_config(target.parent, "include", target.name)
    companion, receipt = _companion_case(tmp_path, "git@github.com:example-owner/demo-config.git")
    proven, errors = db._companion_visibility(str(companion), str(receipt))
    assert errors and proven == []
    assert "Include or Match" in errors[0]


@pytest.mark.parametrize("remote", ["SSH://git@github.com/example-owner/demo-config.git",
                                    " ssh://git@github.com/example-owner/demo-config.git",
                                    "ssh://git@github.com:0/example-owner/demo-config.git",
                                    "ssh://git@github.com:/example-owner/demo-config.git"])
def test_source5_ssh_noncanonical_protocol_is_unknown(tmp_path, remote):
    import data_boundary as db
    assert db._github_repo_key(remote) is None
    companion, receipt = _companion_case(tmp_path, remote)
    proven, errors = db._companion_visibility(str(companion), str(receipt))
    assert errors and proven == []


@pytest.mark.parametrize("rewrite", [False, True])
def test_source5_ssh_rewrites_require_destination_attestation(tmp_path, rewrite, ssh_configuration):
    import data_boundary as db
    companion, receipt = _companion_case(tmp_path)
    write_ssh_config(ssh_configuration[0].parent.parent, "remap")
    if rewrite:
        git(companion, "config", "url.git@github.com:.insteadOf", "https://github.com/")
    proven, errors = db._companion_visibility(str(companion), str(receipt))
    assert bool(errors) is rewrite
    assert proven == ([] if rewrite else ["example-owner/demo-config"])


@pytest.mark.parametrize("ignored", [False, True])
@pytest.mark.parametrize("directory", ["runs", "nested/runs"])
def test_source3_invalid_git_marker_cannot_hide_physical_output(tmp_path, ignored, directory):
    repo = make_repo(tmp_path, manifest=base_manifest(),
                     files={".gitignore": directory + "/\n" if ignored else ""})
    write_record(repo, directory + "/events.jsonl")
    write_invalid_git_marker(repo, directory)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, directory + "/events.jsonl", "RUN-SHAPE")


@pytest.mark.parametrize("registered", [False, True])
def test_source3_outside_resolver_cannot_import_consumer_fallback(tmp_path, monkeypatch, registered):
    import data_boundary as db
    repo = make_repo(tmp_path, manifest=base_manifest())
    if registered:
        (repo / ".gitmodules").write_text('[submodule "security"]\npath = guards\n'
                                          'url = https://github.com/DaizeDong/fleet-guards.git\n', encoding="utf-8")
        git(repo, "add", ".gitmodules")
        git(repo, "update-index", "--add", "--cacheinfo", "160000",
            "1234567890abcdef1234567890abcdef12345678", "guards")
        (repo / "guards").mkdir()
    (repo / "tools").mkdir()
    sentinel = tmp_path / "imported.txt"
    (repo / "tools/datadir.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "Path(os.environ['FG_SYNTHETIC_RECEIPT']).write_text('imported')\n"
        "def resolve_data_dir(skill):\n    return None\n", encoding="utf-8")
    monkeypatch.setenv("FG_SYNTHETIC_RECEIPT", str(sentinel))
    with pytest.raises(RuntimeError):
        db._resolve_companion(str(repo))
    assert not sentinel.exists()

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(HERE, "data_boundary.py")
REPO_ROOT = os.path.dirname(HERE)

# Exit codes this gate promises. They are asserted by name so that collapsing two of them together
# breaks a test instead of quietly making "nothing was examined" look like "clean".
CLEAN = 0
VIOLATION = 1
NOT_EXAMINED = 2   # git unusable, or an empty file list: the scan did not happen
NOT_ARMED = 3      # no manifest, or --companion with no companion: nothing was declared to enforce

# The exact prefix of the success summary. Asserted as a whole string so that a refusal is free
# to use the word "clean" in a sentence explaining that this is NOT one.
PASS_LINE = "data_boundary: clean ("

AUDITED = "synthetic test manifest -- this repo writes nothing, which is why the list is empty"


def git(repo, *args):
    """Run git in `repo` with the machine's own config kept OUT of the way.

    GIT_CONFIG_GLOBAL / GIT_CONFIG_NOSYSTEM matter: this machine sets a global core.hooksPath that
    installs an identity assertion and a PII scan on every commit. A test that tripped those would
    fail for reasons that have nothing to do with the gate under test, and worse, could pass for
    them too.
    """
    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.path.join(str(repo), ".absent-global-gitconfig")
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    p = subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env, **_no_window())
    assert p.returncode == 0, "git %s failed in %s:\n%s" % (" ".join(args), repo, p.stderr)
    return p.stdout


def run_guard(repo, *args, env_extra=None, path=None, guard_path=None):
    """Invoke the real script exactly as CI and the hooks do, and return (rc, combined output)."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    if path is not None:
        env["PATH"] = path
    if env_extra:
        env.update(env_extra)
    p = subprocess.run([sys.executable, str(guard_path or GUARD), "--repo", str(repo), *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
                       **_no_window())
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def make_repo(tmp_path, name="scratch", files=None, manifest=None, track=True, remote=None):
    """A git work tree containing `files` (path -> text), with `manifest` written as .dataclass.json.

    `track=True` stages everything with --force, because the poison is often a path a real repo
    would gitignore and .gitignore is advisory: `git add -f` is precisely the move this gate exists
    to survive.
    """
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    if manifest is not None:
        (repo / ".dataclass.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                                              encoding="utf-8")
    for rel, text in (files or {}).items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    if remote is not None:
        git(repo, "remote", "add", "origin", remote)
    if track:
        git(repo, "add", "-A", "--force")
    return repo


def base_manifest(**over):
    m = {"data": [], "data_sealed": [], "fixture": [], "tool": [], "_audited": AUDITED}
    m.update(over)
    return m


def native_submodule_layout(tmp_path, relative, linked=False, resolver=False):
    """Generate an actual local submodule, optionally in a linked consumer worktree."""
    from pathlib import Path
    import shutil
    source = make_repo(tmp_path, name="module-source", files={"seed.md": "synthetic module\n"},
                       manifest=base_manifest())
    if resolver:
        (source / "tools").mkdir()
        shutil.copyfile(Path(HERE) / "datadir.py", source / "tools/datadir.py")
        git(source, "add", "tools/datadir.py")
    identity = ["-c", "user.name=Fixture", "-c", "user.email=fixture@users.noreply.github.com"]
    git(source, *identity, "commit", "-qm", "synthetic module")
    repo = make_repo(tmp_path, name="consumer", manifest=base_manifest())
    git(repo, "-c", "protocol.file.allow=always", "submodule", "add", "--name", "security", str(source), relative)
    git(repo, *identity, "commit", "-qm", "synthetic consumer")
    if linked:
        worktree = tmp_path / "linked-consumer"
        git(repo, "worktree", "add", "--detach", str(worktree))
        repo = worktree
        git(repo, "-c", "protocol.file.allow=always", "submodule", "update", "--init")
    git(repo, "config", "--file", ".gitmodules", "submodule.security.url",
        "https://github.com/DaizeDong/fleet-guards.git" if resolver else "https://github.com/example-owner/example-module.git")
    git(repo, "add", ".gitmodules")
    return repo, repo / relative


@pytest.mark.parametrize("relative", ["unlisted-kit", "vendor/security"])
@pytest.mark.parametrize("linked", [False, True])
def test_source3_real_submodules_preserve_boundary_and_pii_scope(tmp_path, relative, linked):
    import pii_guard as guard
    from make_fixtures import synthetic_token
    repo, module = native_submodule_layout(tmp_path, relative, linked)
    write_record(module, "runs/events.jsonl")
    token = synthetic_token("submodule-owned-content")
    (module / "notes.txt").write_text(token + "\n", encoding="utf-8")
    git(module, "add", "notes.txt")
    rc, out = run_guard(repo)
    assert rc == CLEAN, out
    policy = guard.Policy.of([guard.Token(token, "secret")])
    assert guard.scan_tree(str(repo), set(), policy) == []
    assert any(value == token for _, _, value, _ in guard.scan_tree(str(module), set(), policy))
    rc, out = run_guard(module)
    assert_blocked(rc, out, "runs/events.jsonl", "RUN-SHAPE")


@pytest.mark.parametrize("relative", ["security-kit", "vendor/security"])
def test_source3_resolver_uses_registered_native_kit(tmp_path, monkeypatch, relative):
    import data_boundary as db
    repo, _module = native_submodule_layout(tmp_path, relative, resolver=True)
    store = tmp_path / "private-store"
    (store / "data").mkdir(parents=True)
    monkeypatch.setenv("CONSUMER_CONFIG", str(store))
    assert os.path.realpath(db._resolve_companion(str(repo))) == os.path.realpath(store / "data")


def assert_not_a_pass(out):
    """The success SUMMARY line must be absent. Matching the bare word "clean" is not the same
    property: a refusal is allowed to contain the phrase "this is not a clean bill of health",
    and a test that forbids the word would push the next author toward a quieter refusal."""
    assert PASS_LINE not in out, "this run reported a pass it did not earn:\n%s" % out


def assert_blocked(rc, out, path, kind=None):
    """A verdict must carry the offending path. An exit code alone is not actionable."""
    assert rc == VIOLATION, "expected exit %d, got %d\n%s" % (VIOLATION, rc, out)
    assert path in out, "the gate blocked but never named %r:\n%s" % (path, out)
    if kind:
        assert kind in out, "expected finding kind %r in:\n%s" % (kind, out)


# ---------------------------------------------------------------------------------------------
# The shapes a REAL daily run of this skill writes. Reconstructed by hand from one run tree
# (116 files) and the live archive (40 files); the account-shaped and subreddit-shaped names are
# replaced with the synthetic namespace. Each entry is (relative path, why it is run output).
#
# The whole point of check 4 is that it catches these AT AN IN-REPO RELATIVE PATH, not only inside
# a conveniently named .run-YYYY-MM-DD/ directory. A pipeline pointed at the repo by a flag or an
# env var (--archive-dir, DAILY_HOTSPOTS_CONFIG) drops these at the root, with no dated directory
# to give them away, and that is the case the shipped pattern list missed entirely.
# ---------------------------------------------------------------------------------------------
RUN_ARTIFACTS_AT_REPO_ROOT = [
    "candidates.json",
    "sources.json",
    "sources_result.json",
    "sources_out.json",
    "result.json",
    "run_out.json",
    "roster_raw_1.json",
    "roster_shard_3.json",
    "roster_plan.json",
    "demand_cards.json",
    "supply_cards.json",
    "all_jobs.json",
    "raw_jobs.json",
    "dry.json",
    "reddit_out.json",
    "hn_out.json",
    "arxiv_out.json",
    "ph_out.json",
    "x_broad_out.json",
    "gdelt_raw.json",
    "roster.json",
    "roster-review.md",
    "opportunities.jsonl",
    "opportunities.after-interactive-run.jsonl",
    "pulls-2026-08.jsonl",
    "identity-sweep-2026-08.json",
    "dedup-state.json",
    "digests/2026/2026-08-27.md",
    "archive/opportunities.jsonl",
    "archive/pulls-2026-08.jsonl",
    "archive/dedup-state.json",
    "archive/digests/2026/2026-08-27.md",
    "archive/identity-sweep-2026-08.json",
    "archive/roster-review.md",
]

# The scratch tree a single run leaves behind, names synthesized. Every one of these is under a
# dated run directory, which is a second, independent way for the same file to be caught.
RUN_TREE = [
    ".run-2026-08-27/candidates.json",
    ".run-2026-08-27/sources.json",
    ".run-2026-08-27/result.json",
    ".run-2026-08-27/demand_cards.json",
    ".run-2026-08-27/roster_raw_1.json",
    ".run-2026-08-27/run_err.txt",
    ".run-2026-08-27/reddit_log.txt",
    ".run-2026-08-27/fetch_reddit.py",
    ".run-2026-08-27/digest-2026-08-27.interactive-backup.md",
    ".run-2026-08-27/opportunities.after-interactive-run.jsonl",
    ".run-2026-08-27/parts5/example-handle-1.json",
    ".run-2026-08-27/reddit_raw/example-subreddit.json",
    ".run-2026-08-27/_d/hits.jsonl",
    ".run-2026-08-27/_d/raw_example_1.json",
    ".run-2026-08-27-rerun-1214/candidates.json",
]


@pytest.mark.parametrize("rel", RUN_ARTIFACTS_AT_REPO_ROOT)
def test_check4_catches_a_real_run_artifact_at_an_in_repo_path(tmp_path, rel):
    """CHECK 4, THE ONE THAT WAS INERT. Each of these is a file a real run of this skill writes.

    Poison: the artifact is git-tracked at a repo-relative path, undeclared.
    Expected: exit 1, and the path named.
    """
    repo = make_repo(tmp_path, files={rel: "{}\n", "SKILL.md": "# tool\n"},
                     manifest=base_manifest())
    rc, out = run_guard(repo)
    assert_blocked(rc, out, rel, "RUN-SHAPE")


@pytest.mark.parametrize("rel", RUN_TREE)
def test_check4_catches_the_whole_run_tree(tmp_path, rel):
    """The per-run scratch tree, file by file. 116 of these land per real run."""
    repo = make_repo(tmp_path, files={rel: "x\n"}, manifest=base_manifest())
    rc, out = run_guard(repo)
    assert_blocked(rc, out, rel, "RUN-SHAPE")


def test_check4_catches_an_entire_run_tree_at_once(tmp_path):
    """A whole run pasted in must produce a finding PER FILE, not one summary line.

    A gate that says "1 violation" for 116 files teaches the reader that moving one file fixes it.
    """
    repo = make_repo(tmp_path, files={rel: "x\n" for rel in RUN_TREE}, manifest=base_manifest())
    rc, out = run_guard(repo)
    assert rc == VIOLATION, out
    for rel in RUN_TREE:
        assert rel in out, "the run tree was blocked but %r was never named:\n%s" % (rel, out)
    assert "%d violation(s)" % len(RUN_TREE) in out, out


def test_check4_over_rejection_tool_material_passes(tmp_path):
    """The other half of the control: hand-written TOOL material must NOT be flagged.

    These are real names from this repo. A shape list broad enough to swallow SKILL.md or the
    roster DESIGN NOTE gets switched off within a week, and then nothing is checked at all.
    """
    clean = {
        "SKILL.md": "# daily-hotspots\n",
        "README.md": "# readme\n",
        "reference/collect.md": "collection reference\n",
        "reference/roster-evolution.md": "how the roster evolves\n",
        "scripts/lib.py": "TRACKS = []\n",
        "scripts/run.py": "def main():\n    return 0\n",
        "scripts/archive.py": "def archive_card():\n    return None\n",
        "tools/datadir.py": "def resolve_data_dir(name):\n    return None\n",
        "tests/test_dedup.py": "def test_x():\n    assert True\n",
        "watchlist.example.json": "{}\n",
        "archive/opportunities.jsonl.example": '{"schema": 1}\n',
        "metrics/live-runs.jsonl.example": '{"schema": 1}\n',
        ".github/workflows/tests.yml": "name: tests\n",
    }
    repo = make_repo(tmp_path, files=clean, manifest=base_manifest())
    rc, out = run_guard(repo)
    assert rc == CLEAN, "a repo of pure tool material must pass:\n%s" % out
    assert "clean" in out


def test_check4_declaring_the_path_in_tool_is_the_documented_escape(tmp_path):
    """The per-path allowlist works, and it is per PATH, not per directory.

    Declaring one ledger under `tool` must not amnesty the one beside it, or the allowlist becomes
    the paragraph it was built to replace.
    """
    files = {"tests/fixtures/yield/opportunities.jsonl": "{}\n",
             "tests/fixtures/yield/pulls-2026-06.jsonl": "{}\n"}
    m = base_manifest(tool=["tests/fixtures/yield/opportunities.jsonl"])
    repo = make_repo(tmp_path, files=files, manifest=m)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "tests/fixtures/yield/pulls-2026-06.jsonl", "RUN-SHAPE")
    assert "1 violation(s)" in out, "the allowlisted path must not also be reported:\n%s" % out


# ---------------------------------------------------------------------------------------------
# CLAUDE CODE SESSION TRANSCRIPTS -- the shape check 4 could not see until 2026-09-27.
#
# A transcript is every prompt, file read and tool result of a session, verbatim. The names below
# are the SHAPES of a real Claude Code session tree, reduced by hand: the UUIDs are
# the all-zero nil-style form, the project directory is an example user, the agent ids are
# example ids. Before these shapes existed, every one of them passed check 4 except the last, which
# was caught only by the accident of a ledger called `transcript`.
# ---------------------------------------------------------------------------------------------
_NIL = "00000000-0000-4000-8000-000000000000"
TRANSCRIPT_SHAPES = [
    _NIL + ".jsonl",
    _NIL + ".jsonl.gz",
    "sessions/" + _NIL + ".jsonl",
    "C--Users-example-proj/" + _NIL + ".jsonl",
    "C--Users-example-proj/" + _NIL + "/subagents/agent-a0example.jsonl",
    "C--Users-example-proj/" + _NIL + "/subagents/agent-a0example.meta.json",
    "C--Users-example-proj/" + _NIL + "/subagents/workflows/wf_example/agent-a0example.jsonl.gz",
    "C--Users-example-proj/.fork-" + _NIL + ".tmp",
    "C--Users-example-proj/memory/MEMORY.md",
    "-home-example-proj/" + _NIL + ".jsonl",
    "subagents/agent-a0example.jsonl",
    _NIL + "/tool-results/toolu_example.txt",
    _NIL + "/workflows/wf_example.json",
    "backup/.claude/projects/notes.md",
    # Each arm alone, with no encoded project directory or UUID parent above it to catch it
    # instead (review 2026-09-27: deleting the .fork arm or the .meta.json arm left every test green).
    ".fork-" + _NIL + ".tmp",
    "subagents/agent-a0example.meta.json",
    # A session's sidecar folder copied without its UUID parent.
    "subagents/workflows/wf_example/journal.jsonl",
    "subagents/workflows/wf_example/journal.jsonl.gz",
    "tool-results/toolu_example.txt",
    "tool-results/toolu_example.json",
    "tool-results/pdf-" + _NIL + "/page-1.jpg",
    _NIL + "/custom-title.json",
]


@pytest.mark.parametrize("rel", TRANSCRIPT_SHAPES)
def test_check4_catches_a_claude_code_transcript(tmp_path, rel):
    """Poison: one session-tree file, tracked, undeclared. Expected: exit 1, the path named."""
    repo = make_repo(tmp_path, files={rel: "{}\n", "README.md": "# tool\n"},
                     manifest=base_manifest())
    rc, out = run_guard(repo)
    assert_blocked(rc, out, rel, "RUN-SHAPE")
    assert "CLAUDE CODE" in out, "caught, but for the wrong reason:\n%s" % out


def test_check4_transcript_over_rejection_ordinary_jsonl_and_uuids_pass(tmp_path):
    """The other half. `.jsonl` is the most ordinary fixture extension there is, and UUIDs appear
    in hand-written code, docs and lockfiles. None of these may trip the transcript shapes: a
    shape that reddens a lockfile is switched off within a week, and then nothing is checked."""
    clean = {
        "package-lock.json": "{}\n",
        "tests/fixtures/sample.jsonl": "{}\n",
        "tests/fixtures/session_small.jsonl": "{}\n",
        "tests/fixtures/agent-example.jsonl": "{}\n",
        "schemas/" + _NIL + ".json": "{}\n",
        "docs/" + _NIL + ".md": "an id in a doc name\n",
        "src/" + _NIL + "_migration.py": "X = 1\n",
        "src/agents/agent-runner.jsonl.example": "{}\n",
        "src/a--b.py": "X = 1\n",
        "src/convo_chain/transcript.py": "X = 1\n",
        "docs/subagents.md": "how subagents work\n",
        "-weird/notes.md": "a hyphen-led directory that is not an encoded project path\n",
        "docs/journal.jsonl": "{}\n",
        "workflows/wf_example/journal.jsonl": "{}\n",
        "tool-results/summary.txt": "a hand-written results note\n",
        "tests/custom-title.json": "{}\n",
        "src/.fork-helper.tmp": "scratch\n",
    }
    repo = make_repo(tmp_path, files=clean, manifest=base_manifest())
    rc, out = run_guard(repo)
    assert rc == CLEAN, "ordinary tool material wearing a UUID or .jsonl must pass:\n%s" % out


TRANSCRIPT_GEN = (
    "import argparse, os\n"
    "ap = argparse.ArgumentParser()\n"
    "ap.add_argument(\"--out\")\n"
    "a = ap.parse_args()\n"
    "open(os.path.join(a.out, \"" + _NIL + ".jsonl\"), \"w\", newline=\"\")"
    ".write('{\"type\": \"user\", \"synthetic\": true}\\n')\n"
)


def test_check4_a_generated_transcript_fixture_is_the_legitimate_route(tmp_path):
    """A tool that parses transcripts needs transcript-shaped fixtures. The route is the one every
    other fixture takes: declare it under `fixture`, and check 2 then demands the generator
    reproduce it byte for byte, which a pasted real session cannot satisfy."""
    rel = "fx/" + _NIL + ".jsonl"
    files = {rel: '{"type": "user", "synthetic": true}\n', "tools/make_fixtures.py": TRANSCRIPT_GEN}
    repo = make_repo(tmp_path, files=files, manifest=base_manifest(fixture=[rel]))
    rc, out = run_guard(repo)
    assert rc == CLEAN, "a generator-reproduced transcript fixture must pass:\n%s" % out


def test_check4_a_pasted_real_transcript_declared_as_fixture_is_still_blocked(tmp_path):
    """The escape hatch must not become the leak: declaring a real session as a fixture moves it
    from check 4 to check 2, and check 2 refuses it because no generator produces it."""
    rel = "fx/" + _NIL + ".jsonl"
    files = {rel: '{"type": "user", "message": "a real prompt"}\n',
             "tools/make_fixtures.py": TRANSCRIPT_GEN}
    repo = make_repo(tmp_path, files=files, manifest=base_manifest(fixture=[rel]))
    rc, out = run_guard(repo)
    assert_blocked(rc, out, rel, "HAND-EDITED")


def test_transcript_probes_calibrate(tmp_path):
    """A repo that writes transcripts can now declare them as probes and read CALIBRATED, which
    until this shape landed was a PROBE-MISS that blocked every commit."""
    probes = ["C--Users-example-proj/" + _NIL + ".jsonl",
              "C--Users-example-proj/" + _NIL + "/subagents/agent-a0example.jsonl",
              "C--Users-example-proj/.fork-" + _NIL + ".tmp"]
    repo = make_repo(tmp_path, files={"README.md": "# tool\n"},
                     manifest=base_manifest(_run_shape_probes=probes))
    rc, out = run_guard(repo, "--calibration")
    assert rc == CLEAN, out
    assert "PROBE-MISS" not in out and "NOT CALIBRATED" not in out, out


# ---------------------------------------------------------------------------------------------
# CHECK 1 -- a DATA-class path must not be in the index.
# ---------------------------------------------------------------------------------------------
def test_check1_declared_data_path_that_is_tracked_is_blocked(tmp_path):
    """Poison: the manifest itself says archive/opportunities.jsonl is real-run output, and it is
    staged anyway. This is the 2026-07 leak in one line."""
    m = base_manifest(data=["archive/opportunities.jsonl"])
    repo = make_repo(tmp_path, files={"archive/opportunities.jsonl": '{"id": "op-a"}\n',
                                      "archive/opportunities.jsonl.example": '{"id": "..."}\n'},
                     manifest=m)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive/opportunities.jsonl", "DATA-TRACKED")


def test_check1_covers_a_declared_DIRECTORY_not_just_the_exact_path(tmp_path):
    """`archive/` as a DATA declaration must cover everything under it. Otherwise the declaration
    is satisfied by renaming the file."""
    m = base_manifest(data=["archive/"])
    repo = make_repo(tmp_path, files={"archive/digests/2026/2026-08-27.md": "# digest\n"},
                     manifest=m)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive/digests/2026/2026-08-27.md", "DATA-TRACKED")


def test_check1_data_sealed_path_may_not_come_back(tmp_path):
    """A sealed path is one that HELD real data and was purged. .gitignore is advisory and
    `git add -f` walks straight through it, which is why make_repo forces the add."""
    m = base_manifest(data_sealed=["metrics/live-runs.jsonl"])
    repo = make_repo(tmp_path, files={"metrics/live-runs.jsonl": '{"run": 1}\n'}, manifest=m)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "metrics/live-runs.jsonl", "DATA-TRACKED")


@pytest.mark.parametrize("ignored", [False, True])
def test_check1_untracked_data_path_is_blocked(tmp_path, ignored):
    """DATA is physically absent from a tool repo, including ignored files."""
    m = base_manifest(data=["archive/opportunities.jsonl"])
    repo = make_repo(tmp_path, files={"archive/opportunities.jsonl.example": '{"id": "..."}\n'},
                     manifest=m)
    write_record(repo, "archive/opportunities.jsonl")
    if ignored:
        (repo / ".gitignore").write_text("archive/*.jsonl\n", encoding="utf-8")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive/opportunities.jsonl", "DATA-PRESENT")
    assert_not_a_pass(out)


def test_summary_only_claims_absent_when_data_is_absent(tmp_path):
    m = base_manifest(data=["archive/opportunities.jsonl"])
    repo = make_repo(tmp_path, files={"archive/opportunities.jsonl.example": '{"id": "..."}\n'},
                     manifest=m)
    rc, out = run_guard(repo)
    assert rc == CLEAN, out
    assert "absent from the worktree" in out, out


@pytest.mark.parametrize("declaration,relative", [
    ("archive/", "archive/nested/record.jsonl"),
    ("guards/records/", "guards/records/record.jsonl"),
    ("style/records/", "style/records/record.jsonl"),
    (".venv/records/", ".venv/records/record.jsonl"),
    ("archive/*.jsonl", "archive/.hidden.jsonl"),
])
def test_physical_data_declarations_cover_directories_and_globs(tmp_path, declaration, relative):
    repo = make_repo(tmp_path, manifest=base_manifest(data_sealed=[declaration]))
    write_record(repo, relative)
    rc, out = run_guard(repo)
    assert rc == VIOLATION, out
    assert "DATA-PRESENT" in out, out
    assert declaration.rstrip("/").split("*")[0] in out, out
    assert_not_a_pass(out)


def test_physical_sealed_directory_cannot_return_empty(tmp_path):
    repo = make_repo(tmp_path, manifest=base_manifest(data_sealed=["archive/"]))
    (repo / "archive").mkdir()
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive", "DATA-PRESENT")


@pytest.mark.parametrize("declaration", ["./private-store/", "private-store//", "private-store/./"])
def test_source2_noncanonical_data_declarations_cannot_bypass(tmp_path, declaration):
    repo = make_repo(tmp_path, manifest=base_manifest(data_sealed=[declaration]))
    write_record(repo, "private-store/item.json")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "private-store", "DATA-PATH")


@pytest.mark.parametrize("ignored", [False, True])
def test_source2_physical_undeclared_run_shape(tmp_path, ignored):
    repo = make_repo(tmp_path, manifest=base_manifest(),
                     files={".gitignore": "metrics/\n" if ignored else ""})
    write_record(repo, "metrics/live-runs.jsonl")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "metrics/live-runs.jsonl", "RUN-SHAPE")


def test_source2_physical_tool_exemption_survives(tmp_path):
    repo = make_repo(tmp_path, manifest=base_manifest(tool=["metrics/live-runs.jsonl"]))
    write_record(repo, "metrics/live-runs.jsonl")
    rc, out = run_guard(repo)
    assert rc == CLEAN, out


def _companion_case(tmp_path, remote="https://github.com/example-owner/demo-config.git"):
    import datetime
    companion = make_repo(tmp_path, name="demo-config", remote=remote)
    write_record(companion, "archive/record.jsonl")
    git(companion, "add", "archive/record.jsonl")
    receipt = write_visibility(tmp_path / "visibility.json", {
        "example-owner/demo-config": "PRIVATE",
        "example-owner/public-copy": "PUBLIC",
    }, datetime.datetime.now(datetime.timezone.utc).isoformat())
    return companion, receipt


def test_private_companion_keeps_versioned_data(tmp_path):
    companion, receipt = _companion_case(tmp_path)
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert rc == CLEAN, out
    assert "PRIVATE" in out and "example-owner/demo-config" in out, out
    assert "archive/record.jsonl" in git(companion, "ls-files")
    assert (companion / "archive" / "record.jsonl").is_file()


@pytest.mark.parametrize("mode", ["explicit", "resolver"])
@pytest.mark.parametrize("visibility", ["public-copy", "unknown"])
def test_source2_companion_attests_actual_nested_data_repo(tmp_path, mode, visibility):
    from pathlib import Path
    import shutil
    companion, receipt = _companion_case(tmp_path)
    nested = make_repo(companion, name="data", remote="https://github.com/example-owner/%s.git" % visibility)
    write_record(nested, "archive/record.jsonl")
    git(nested, "add", "archive/record.jsonl")
    # The parent ignores the nested store, so only destination attestation can catch this.
    (companion / ".gitignore").write_text("data/\n", encoding="utf-8")
    git(companion, "add", ".gitignore")
    if mode == "explicit":
        repo, args, env = companion, ["--companion-dir", str(companion)], {}
    else:
        repo = make_repo(tmp_path, name="demo", manifest=base_manifest())
        (repo / "tools").mkdir()
        for name in ("datadir.py", "data_boundary.py", "pii_guard.py"):
            shutil.copyfile(Path(HERE) / name, repo / "tools" / name)
        git(repo, "add", "tools")
        args, env = ["--companion"], {"DEMO_CONFIG": str(companion)}
    rc, out = run_guard(repo, *args, "--visibility-map", str(receipt), env_extra=env,
                        guard_path=repo / "tools/data_boundary.py" if mode == "resolver" else None)
    assert_blocked(rc, out, visibility, "VISIBILITY")


def test_source2_companion_attests_redirected_data_destination(tmp_path):
    companion, receipt = _companion_case(tmp_path)
    target = make_repo(tmp_path, name="redirected",
                       remote="https://github.com/example-owner/public-copy.git")
    write_record(target, "archive/record.jsonl")
    git(target, "add", "archive/record.jsonl")
    link = companion / "data"
    if os.name == "nt":
        result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
                                capture_output=True, text=True, **_no_window())
        assert result.returncode == 0, result.stdout + result.stderr
    else:
        link.symlink_to(target, target_is_directory=True)
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert_blocked(rc, out, "public-copy", "VISIBILITY")


def test_source2_private_nested_data_repo_is_legitimate(tmp_path):
    companion, receipt = _companion_case(tmp_path)
    nested = make_repo(companion, name="data", remote="https://github.com/example-owner/demo-config.git")
    write_record(nested, "archive/record.jsonl")
    git(nested, "add", "archive/record.jsonl")
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert rc == CLEAN, out
    assert "PRIVATE verified: example-owner/demo-config" in out
    assert "verified DATA destination:" in out


@pytest.mark.parametrize("remote", [
    None,
    "https://github.com/example-owner/public-copy.git",
    "https://github.com/example-owner/unknown.git",
    "https://example.invalid/example-owner/demo-config.git",
])
def test_companion_public_or_unknown_remote_is_blocked(tmp_path, remote):
    companion, receipt = _companion_case(tmp_path, remote)
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert_blocked(rc, out, "companion", "VISIBILITY")
    assert "correct: this is the private repo" not in out, out


@pytest.mark.parametrize("setting,value", [
    ("remote.origin.pushurl", "https://github.com/example-owner/public-copy.git"),
    ("url.https://github.com/example-owner/public-copy.git.pushInsteadOf",
     "https://github.com/example-owner/demo-config.git"),
    ("remote.backup.url", "https://github.com/example-owner/public-copy.git"),
])
def test_companion_checks_all_effective_push_destinations(tmp_path, setting, value):
    companion, receipt = _companion_case(tmp_path)
    git(companion, "config", setting, value)
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert_blocked(rc, out, "example-owner/public-copy", "VISIBILITY")


@pytest.mark.parametrize("stamp", [None, "invalid", "2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"])
def test_companion_cannot_rely_on_an_undated_stale_or_future_receipt(tmp_path, stamp):
    companion, receipt = _companion_case(tmp_path)
    write_visibility(receipt, {"example-owner/demo-config": "PRIVATE"}, stamp)
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert_blocked(rc, out, "companion", "VISIBILITY")


@pytest.mark.parametrize("contents", [None, "{broken", "[]", "{}"])
def test_companion_missing_or_damaged_receipt_is_blocked(tmp_path, contents):
    companion, receipt = _companion_case(tmp_path)
    if contents is None:
        receipt.unlink()
    else:
        receipt.write_text(contents, encoding="utf-8")
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert_blocked(rc, out, "companion", "VISIBILITY")


def test_companion_checks_every_pushurl(tmp_path):
    companion, receipt = _companion_case(tmp_path)
    git(companion, "config", "--add", "remote.origin.pushurl", "https://github.com/example-owner/demo-config.git")
    git(companion, "config", "--add", "remote.origin.pushurl", "https://github.com/example-owner/public-copy.git")
    rc, out = run_guard(companion, "--companion-dir", str(companion), "--visibility-map", str(receipt))
    assert_blocked(rc, out, "example-owner/public-copy", "VISIBILITY")


@pytest.mark.parametrize("remote", [
    "git@github.com:example-owner/demo-config.git",
    "ssh://git@github.com/example-owner/demo-config.git",
])
def test_private_companion_supports_canonical_ssh_urls(tmp_path, remote, ssh_configuration):
    import data_boundary as db
    companion, receipt = _companion_case(tmp_path, remote)
    proven, errors = db._companion_visibility(str(companion), str(receipt))
    assert errors == []
    assert proven == ["example-owner/demo-config"]


def test_physical_data_is_blocked_even_if_tool_remote_is_private(tmp_path):
    repo = make_repo(tmp_path, remote="https://github.com/example-owner/demo-config.git",
                     manifest=base_manifest(data_sealed=["archive/"]))
    write_record(repo, "archive/record.jsonl")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive", "DATA-PRESENT")


def test_data_glob_staged_but_deleted_from_disk_still_blocks(tmp_path):
    repo = make_repo(tmp_path, manifest=base_manifest(data_sealed=["storage/*.json"]))
    record = write_record(repo, "storage/item.json")
    git(repo, "add", "storage/item.json")
    record.unlink()
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "storage/item.json", "DATA-TRACKED")


@pytest.mark.skipif(os.name != "nt", reason="Windows paths compare without case")
def test_physical_data_declaration_respects_windows_case(tmp_path):
    repo = make_repo(tmp_path, manifest=base_manifest(data_sealed=["ARCHIVE/RECORD.JSONL"]))
    write_record(repo, "archive/record.jsonl")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive/record.jsonl", "DATA-PRESENT")


# ---------------------------------------------------------------------------------------------
# CHECK 3 -- every DATA path ships a schema, so the uninitialized tool is still usable.
# ---------------------------------------------------------------------------------------------
def test_check3_data_path_without_a_schema_is_blocked(tmp_path):
    m = base_manifest(data=["archive/opportunities.jsonl"])
    repo = make_repo(tmp_path, files={"README.md": "# readme\n"}, manifest=m)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive/opportunities.jsonl.example", "NO-SCHEMA")


@pytest.mark.parametrize("schema_name", ["watchlist.json.example", "watchlist.example.json"])
def test_check3_over_rejection_either_naming_convention_satisfies_it(tmp_path, schema_name):
    m = base_manifest(data=["watchlist.json"])
    repo = make_repo(tmp_path, files={schema_name: "{}\n"}, manifest=m)
    rc, out = run_guard(repo)
    assert rc == CLEAN, "%s should satisfy the schema requirement:\n%s" % (schema_name, out)


def test_check3_a_declared_output_DIRECTORY_is_not_owed_a_schema(tmp_path):
    """There is no single shape to publish for a whole directory, so a trailing slash is exempt.
    This is an exemption, so it is pinned: widening it to bare paths would silence check 3."""
    m = base_manifest(data=["archive/digests/"])
    repo = make_repo(tmp_path, files={"README.md": "# readme\n"}, manifest=m)
    rc, out = run_guard(repo)
    assert rc == CLEAN, out


# ---------------------------------------------------------------------------------------------
# CHECK 5 -- an empty `data` list has to be a finding, not a default.
# ---------------------------------------------------------------------------------------------
def test_check5_empty_data_list_with_no_audit_note_is_blocked(tmp_path):
    """The manifest a fresh repo gets by accident. It declares nothing, so checks 1 and 3 iterate
    zero times, and without this the repo reports clean on the strength of a default."""
    repo = make_repo(tmp_path, files={"README.md": "# readme\n"},
                     manifest={"data": [], "data_sealed": [], "fixture": []})
    rc, out = run_guard(repo)
    assert_blocked(rc, out, ".dataclass.json", "UNAUDITED")


@pytest.mark.parametrize("note", ["", "   ", "\n\t "])
def test_check5_whitespace_is_not_an_audit(tmp_path, note):
    """A key present with an empty value is the cheapest way to silence this check, so it must not
    work. This is the difference between a note and a field."""
    repo = make_repo(tmp_path, files={"README.md": "# readme\n"},
                     manifest={"data": [], "fixture": [], "_audited": note})
    rc, out = run_guard(repo)
    assert_blocked(rc, out, ".dataclass.json", "UNAUDITED")


def test_check5_over_rejection_a_real_note_or_the_older_key_passes(tmp_path):
    for key in ("_audited", "_armed"):
        repo = make_repo(tmp_path, name="audited-" + key, files={"README.md": "# readme\n"},
                         manifest={"data": [], "fixture": [], key: AUDITED})
        rc, out = run_guard(repo)
        assert rc == CLEAN, "%s should satisfy the audit requirement:\n%s" % (key, out)


def test_check5_a_nonempty_data_list_needs_no_note(tmp_path):
    """A declaration IS the finding. Requiring prose next to a real list would be prose for its
    own sake, which is the thing this repo keeps deciding is not a control."""
    m = {"data": ["archive/opportunities.jsonl"], "fixture": []}
    repo = make_repo(tmp_path, files={"archive/opportunities.jsonl.example": "{}\n"}, manifest=m)
    rc, out = run_guard(repo)
    assert rc == CLEAN, out


# ---------------------------------------------------------------------------------------------
# CHECK 2 -- a fixture must be byte-identical to what the generator emits.
# ---------------------------------------------------------------------------------------------
FAKE_GEN = (
    "import argparse, json, os\n"
    "BLOB = json.dumps({\"_synthetic\": \"generated\", \"host\": \"example.com\"}, indent=2) + \"\\n\"\n"
    "ap = argparse.ArgumentParser()\n"
    "ap.add_argument(\"--out\")\n"
    "a = ap.parse_args()\n"
    "open(os.path.join(a.out, \"sample.json\"), \"w\", newline=\"\").write(BLOB)\n"
)


def _generated_bytes():
    return json.dumps({"_synthetic": "generated", "host": "example.com"}, indent=2) + "\n"


def _fixture_repo(tmp_path, name, fixture_text, generator=FAKE_GEN, declare="fx/sample.json"):
    files = {"fx/sample.json": fixture_text}
    if generator is not None:
        files["tools/make_fixtures.py"] = generator
    return make_repo(tmp_path, name=name, files=files,
                     manifest=base_manifest(fixture=[declare]))


def test_check2_a_hand_pasted_fixture_is_blocked(tmp_path):
    """THE MOVE THAT CAUSED MOST OF THE 2026-07 LEAKS: someone pastes a convenient real record into
    a golden file. A real record cannot be regenerated, so byte-equality is what makes that fail at
    commit time instead of at audit time months later."""
    repo = _fixture_repo(tmp_path, "handedited",
                         _generated_bytes().replace("example.com", "a-real-looking-host.test"))
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "fx/sample.json", "HAND-EDITED")


def test_check2_a_declared_fixture_with_no_generator_at_all_is_blocked(tmp_path):
    """A GUARD FILE IT DEPENDS ON IS ABSENT. Deleting tools/make_fixtures.py must not turn check 2
    into a no-op, which is exactly what "if the generator is missing, skip" would do."""
    repo = _fixture_repo(tmp_path, "nogen", _generated_bytes(), generator=None)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "tools/make_fixtures.py", "NO-GENERATOR")


def test_check2_a_generator_that_crashes_is_blocked_not_skipped(tmp_path):
    """A generator that exits nonzero proves nothing about the fixtures. Treating that as "could
    not check, carry on" is the fail-open shape this whole file exists to rule out."""
    repo = _fixture_repo(tmp_path, "brokengen", _generated_bytes(),
                         generator="import sys\nsys.exit(3)\n")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "tools/make_fixtures.py", "GENERATOR-FAILED")


def test_check2_a_fixture_the_generator_does_not_produce_is_blocked(tmp_path):
    """Declared, present, and unreproducible: nothing proves it is synthetic."""
    repo = _fixture_repo(tmp_path, "notgen", "{}\n", declare="fx/other.json")
    (repo / "fx" / "other.json").write_text("{}\n", encoding="utf-8")
    git(repo, "add", "-A", "--force")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "fx/other.json", "NOT-GENERATED")


def test_check2_a_declared_fixture_that_is_missing_is_blocked(tmp_path):
    repo = _fixture_repo(tmp_path, "missing", _generated_bytes())
    (repo / "fx" / "sample.json").unlink()
    git(repo, "add", "-A", "--force")
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "fx/sample.json", "MISSING")


def test_check2_over_rejection_a_generated_fixture_passes(tmp_path):
    repo = _fixture_repo(tmp_path, "good", _generated_bytes())
    rc, out = run_guard(repo)
    assert rc == CLEAN, "a fixture that matches its generator must pass:\n%s" % out
    assert "1 FIXTUREs generator-reproducible" in out, out


def test_source2_untracked_generated_run_shaped_fixture_is_exempt(tmp_path):
    repo = make_repo(tmp_path, files={"tools/make_fixtures.py": FAKE_GEN},
                     manifest=base_manifest(fixture=["runs/sample.json"]))
    destination = repo / "runs"
    destination.mkdir()
    generated = subprocess.run([sys.executable, str(repo / "tools/make_fixtures.py"),
                                "--out", str(destination)], capture_output=True, text=True,
                                **_no_window())
    assert generated.returncode == 0, generated.stderr
    rc, out = run_guard(repo)
    assert rc == CLEAN, out
    assert "1 FIXTUREs generator-reproducible" in out


def test_check2_crlf_is_not_a_hand_edit(tmp_path):
    """Windows checkouts rewrite line endings. If that read as a hand-edited fixture, the gate
    would be red on every clone on this operator's own machine, and a permanently red gate gets
    disabled within the week."""
    repo = _fixture_repo(tmp_path, "crlf", _generated_bytes())
    # write_bytes, not write_text: write_text translates again on Windows and would produce
    # \r\r\n, a third file that is neither what a checkout writes nor what the generator emits.
    (repo / "fx" / "sample.json").write_bytes(
        _generated_bytes().replace("\n", "\r\n").encode("utf-8"))
    git(repo, "add", "-A", "--force")
    rc, out = run_guard(repo)
    assert rc == CLEAN, out


# ---------------------------------------------------------------------------------------------
# FAIL CLOSED, NOT OPEN.
#
# The ways this gate could decide it "cannot check". All of them must be nonzero and must say so.
# The gate deliberately never asks whether the remote is public, so the visibility cases below are
# about proving it does not start asking and then shrug when the answer is unavailable.
# ---------------------------------------------------------------------------------------------
def test_a_directory_that_is_not_a_work_tree_exits_not_examined(tmp_path):
    d = tmp_path / "not-a-repo"
    d.mkdir()
    (d / "candidates.json").write_text("{}\n", encoding="utf-8")
    rc, out = run_guard(d)
    assert rc == NOT_EXAMINED, "expected %d, got %d\n%s" % (NOT_EXAMINED, rc, out)
    assert "NOTHING was examined" in out, out
    assert "clean" not in out.lower(), "a failed scan must never say clean:\n%s" % out


def test_a_shell_dot_git_directory_exits_not_examined(tmp_path):
    """An empty .git directory has really happened on this machine and stopped a work journal for
    days. It is the canonical way a scan silently examines nothing."""
    d = tmp_path / "shell"
    (d / ".git").mkdir(parents=True)
    (d / "candidates.json").write_text("{}\n", encoding="utf-8")
    rc, out = run_guard(d)
    assert rc == NOT_EXAMINED, "expected %d, got %d\n%s" % (NOT_EXAMINED, rc, out)
    assert "NOTHING was examined" in out, out


def test_git_missing_from_PATH_exits_not_examined(tmp_path):
    """The interpreter-probe lesson, applied to git: a tool that cannot run must not read as a tool
    that found nothing."""
    repo = make_repo(tmp_path, files={"candidates.json": "{}\n"}, manifest=base_manifest())
    empty = tmp_path / "empty-path"
    empty.mkdir()
    rc, out = run_guard(repo, path=str(empty))
    assert rc == NOT_EXAMINED, "expected %d, got %d\n%s" % (NOT_EXAMINED, rc, out)
    assert "NOTHING was examined" in out, out


@pytest.mark.parametrize("remote", [
    None,                                               # no remote at all: no visibility to read
    "https://example.invalid/nobody/unknown-repo.git",  # a host no visibility map covers
    "git@example.invalid:nobody/unknown-repo.git",
    "../a-local-path-that-is-not-a-hosted-repo",
])
def test_unknown_remote_visibility_still_enforces(tmp_path, remote):
    """FAIL CLOSED ON VISIBILITY. This gate must never grow a "skip if the remote looks private"
    branch. pii_guard has one and it is right there, because a content scan of a private repo is
    noise. The boundary is a different question: it is about where a skill WRITES, and a repo whose
    visibility cannot be determined is exactly the repo that has to be treated as public.

    Asserted behaviorally rather than by reading the source: with no remote, with a remote on a host
    no map covers, and with a bare path remote, the same poisoned file is still blocked.
    """
    repo = make_repo(tmp_path, name="vis-%d" % (abs(hash(str(remote))) % 999983),
                     files={"archive/opportunities.jsonl": '{"id": "op-a"}\n'},
                     manifest=base_manifest(), remote=remote)
    rc, out = run_guard(repo)
    assert_blocked(rc, out, "archive/opportunities.jsonl", "RUN-SHAPE")


def test_no_manifest_does_not_launder_a_tracked_run_artifact(tmp_path):
    """DELETING THE MANIFEST MUST NOT DISARM THE GATE.

    Before this test, an absent .dataclass.json returned 0 immediately, before check 4 ever ran. So
    the one-line way past the primary control was to delete the file that arms it, after which the
    repo could track an entire archive with the gate still reporting success. CI papered over this
    with a `test -f .dataclass.json` step in pii-guard.yml, which says out loud that the fail-open
    was known; the hooks had no such step, and a workaround in one caller is not a property of the
    gate. Check 4 is manifest-INDEPENDENT by design, so it must still run.
    """
    repo = make_repo(tmp_path, manifest=None, files={
        "archive/opportunities.jsonl": '{"id": "op-a"}\n',
        "archive/digests/2026/2026-08-27.md": "# digest\n",
        "candidates.json": "{}\n",
    })
    rc, out = run_guard(repo)
    assert rc == VIOLATION, "expected %d, got %d\n%s" % (VIOLATION, rc, out)
    for rel in ("archive/opportunities.jsonl", "archive/digests/2026/2026-08-27.md",
                "candidates.json"):
        assert rel in out, "not named: %r\n%s" % (rel, out)


def test_no_manifest_is_reported_as_not_armed_not_as_clean(tmp_path):
    """Nothing declared and nothing wrong are different findings and must not share an exit code.

    A repo with no manifest has had checks 1, 2, 3 and 5 assert exactly nothing about it. Reporting
    that as 0 makes a disarmed gate look identical to a passing one in a CI log.
    """
    repo = make_repo(tmp_path, manifest=None, files={"README.md": "# readme\n"})
    rc, out = run_guard(repo)
    assert rc == NOT_ARMED, "expected %d, got %d\n%s" % (NOT_ARMED, rc, out)
    assert_not_a_pass(out)


def test_zero_tracked_files_is_not_a_clean_bill_of_health(tmp_path):
    """THE ORIGINAL DEFECT IN ITS PUREST FORM: a checker fed nothing printing the same green as a
    checker that found nothing wrong.

    `git ls-files` exits 0 and returns an empty list in a fresh repo, and returned one in the
    incident this script's own `_run` docstring describes. Every per-file check then iterates zero
    times and the summary says "clean". The count inside that success line was the only difference
    from a real pass, and a count inside a success message is not a signal anybody reads.
    """
    repo = make_repo(tmp_path, files={"README.md": "# readme\n"}, manifest=base_manifest(),
                     track=False)
    rc, out = run_guard(repo)
    assert rc == NOT_EXAMINED, "expected %d, got %d\n%s" % (NOT_EXAMINED, rc, out)
    assert "NOTHING was examined" in out, out
    assert_not_a_pass(out)


def test_clean_and_not_examined_do_not_share_an_exit_code(tmp_path):
    """The property, stated once, across the three states a caller has to tell apart."""
    armed = make_repo(tmp_path, name="armed", files={"README.md": "# readme\n"},
                      manifest=base_manifest())
    empty = make_repo(tmp_path, name="empty", files={"README.md": "# readme\n"},
                      manifest=base_manifest(), track=False)
    unarmed = make_repo(tmp_path, name="unarmed", files={"README.md": "# readme\n"}, manifest=None)
    codes = {"clean": run_guard(armed)[0],
             "nothing examined": run_guard(empty)[0],
             "not armed": run_guard(unarmed)[0]}
    assert len(set(codes.values())) == 3, "these three states must be distinguishable: %r" % codes
    assert codes["clean"] == CLEAN


def test_resolver_lookup_prefers_the_submodule_over_a_copy_beside_this_file(tmp_path, monkeypatch):
    import data_boundary as db
    repo, _module = native_submodule_layout(tmp_path, "guards", resolver=True)
    store = tmp_path / "synthetic-store"
    store.mkdir()
    monkeypatch.setenv("CONSUMER_CONFIG", str(store))
    (repo / "tools").mkdir()
    (repo / "tools/datadir.py").write_text("raise RuntimeError('stale consumer resolver imported')\n", encoding="utf-8")
    assert os.path.realpath(db._resolve_companion(str(repo))) == os.path.realpath(store)


@pytest.mark.parametrize("key", ["data", "data_sealed", "fixture", "tool"])
@pytest.mark.parametrize("declaration", [
    pytest.param(path, id=label) for label, path in declaration_name_cases()["ambiguous"]
])
def test_source9_windows_alias_declarations_are_rejected(key, declaration):
    import data_boundary as db
    findings = []
    db.validate_declarations({key: [declaration]}, findings)
    assert [(kind, path) for kind, path, _reason in findings] == [("DATA-PATH", declaration)]


@pytest.mark.parametrize("key", ["data", "data_sealed", "fixture", "tool"])
@pytest.mark.parametrize("declaration", [
    pytest.param(path, id=label) for label, path in declaration_name_cases()["canonical"]
])
def test_source9_canonical_declarations_remain_valid(key, declaration):
    import data_boundary as db
    findings = []
    db.validate_declarations({key: [declaration]}, findings)
    assert findings == []


@pytest.mark.parametrize("key", ["data", "data_sealed"])
@pytest.mark.parametrize("level", ["directory", "leaf"])
@pytest.mark.parametrize("suffix", [pytest.param(".", id="dot"), pytest.param(" ", id="space")])
@pytest.mark.parametrize("presence", ["physical", "index-only", "absent"])
@pytest.mark.parametrize("aliased", [False, True], ids=["canonical", "alias"])
def test_source9_cli_declarations_cannot_hide_data(tmp_path, key, level, suffix, presence, aliased):
    repo = make_repo(tmp_path, manifest=base_manifest())
    declaration, relative, record = write_declaration_name_fixture(
        repo, key, level, suffix, aliased, present=presence != "absent")
    if presence == "index-only":
        git(repo, "add", relative)
        record.unlink()
    elif presence == "physical" and aliased and os.name == "nt":
        canonical = record.parent if level == "directory" else record
        assert os.path.samefile(canonical, repo / declaration.rstrip("/"))
    rc, out = run_guard(repo)
    if aliased:
        assert_blocked(rc, out, declaration, "DATA-PATH")
        assert_not_a_pass(out)
    elif presence == "absent":
        assert rc == CLEAN, out
    else:
        kind = "DATA-TRACKED" if presence == "index-only" else "DATA-PRESENT"
        target = declaration.rstrip("/") if presence == "physical" else relative
        assert_blocked(rc, out, target, kind)
        assert_not_a_pass(out)
