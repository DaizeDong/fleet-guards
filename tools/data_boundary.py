#!/usr/bin/env python3
"""data_boundary -- a public skill repo is an UNINITIALIZED TOOL. Enforced by construction.

WHY THIS EXISTS, AND WHY pii_guard WAS NOT ENOUGH
-------------------------------------------------
pii_guard is a sieve at the exit: it reads what you are about to publish and looks for things that
smell private. It works, and it has caught real leaks. But it is the wrong primary control, because
it accepts the premise that real data is flowing toward the exit at all.

The 2026-07 audit found real-run output sitting in PUBLIC repos -- a research skill's verdict ledger,
a shopping skill's purchase records, a social skill's posting account -- not because anyone pasted it
into a doc, but because the skills WROTE it there during real runs. `metrics/*.jsonl` was append-only
telemetry of the operator's actual life, git-tracked, on GitHub. (What it recorded was his; the point
here is the mechanism, so the specifics stay out of this file.)

These repos already had a private-companion-config boundary. It only ever covered INPUTS -- the
credentials, the mailboxes, the account slugs. Nothing covered OUTPUTS: what the skill LEARNED from a
real run. That is the door every remaining leak walked out of, and no amount of content scanning
fixes a door.

So: every path in a public repo belongs to exactly one class, declared in `.dataclass.json`.

  TOOL     code, SKILL.md, docs.                 Public. Hand-written. Contains no data at all.
  FIXTURE  tests, goldens, examples.             Public, but SYNTHETIC ONLY, and PRODUCED BY A
                                                 GENERATOR -- never a copy of a real record. The
                                                 generator is the proof: a hand-pasted real email
                                                 cannot be regenerated, so it fails here.
  DATA     anything a real run produced:         PRIVATE companion repo. Physically absent from the
           telemetry, real goldens, calibration, public repo. The loader resolves it from outside.
           caches, verdicts, config.             The public repo ships only a `*.example` schema.

THE POINT IS NOT THAT THE DATA IS HIDDEN. It is that an agent writing the public repo has NOTHING
REAL WITHIN REACH to reuse. You cannot copy a convenient example out of a file that is not there.
That closes the artifact leak completely -- which is more than a scanner can promise.

WHAT IT DOES NOT CLOSE
----------------------
Prose. An agent that is reading the operator's inbox can still type a real employer's name into a
CHANGELOG from memory. No boundary reaches that; deleting a file does not make anyone forget. That
is what pii_guard is FOR, and it is why it stays -- demoted from primary control to backstop.

CHECKS
  1. no DATA-class path is git-tracked or physically present in the tool worktree
  2. every FIXTURE path is byte-identical to what tools/make_fixtures.py produces  (the copy-paste)
  3. every DATA path has a `<path>.example` schema in the repo (so the tool is usable uninitialized)
  4. no tracked or physically present path has an undeclared real-run output shape

`data_sealed` is a fourth, narrower declaration: a path that USED to hold real data, has been
purged, and must stay dead. Checked like DATA in (1), exempt from (3) -- a dead path is not owed a
schema; shipping one would advertise a path the tool no longer uses.

WHY CHECK 4 EXISTS (2026-07-31)
-------------------------------
Checks 1..3 only ever look at what the manifest DECLARES. A manifest that declares nothing therefore
enforces nothing: an independent verifier cloned six public repos whose `data` list was empty,
committed `metrics/live-runs.jsonl` and `runs/transcript.json` into each, and this script exited 0
on all six. Each of those manifests carried a careful prose note concluding that the skill writes its
real-run output outside the repo. The notes were largely accurate. They were also inert: PROSE IS
NOT A CONTROL, and every one of those skills can still be pointed at a repo-relative path by a flag
or an env var (`--archive-dir`, `--state-path`, `--status-json`, `LLMCALL_LEDGER`, `SCHEDULE_DB_PATH`),
so "the default resolver points elsewhere" was never the same statement as "nothing can land here".

So the empty declaration now has to survive a mechanical question instead of an argument: does this
repo TRACK anything shaped like the output a real run produces? The shapes below are not a guess at
what data looks like -- that is pii_guard's losing game -- they are the literal places and names this
fleet's skills write to. A repo with nothing to declare passes because the repo is genuinely empty of
run output, and it starts failing the moment that stops being true.

An exemption is possible and it is per-path: list the file under `tool` in the manifest with a
reason. That is an allowlist entry visible in the diff, which is the opposite of a paragraph.

  python data_boundary.py [--repo .]     exit 0 clean / 1 violation
Stdlib only.
"""
import argparse
import fnmatch
import importlib.util
import json
import os
import ntpath
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field


# ------------------------------------------------- spawning processes (identical in every kit file)
# A console program started by a process that has NO console (pythonw, a scheduled task, a service)
# is handed a brand-new console, and Windows shows it as a window. Measured 2026-10-05: a daemon
# under pythonw ran a companion proof on every log line, each proof ran about 19 git commands, and
# the machine took roughly 9,000 terminal windows in eight hours. So every spawn in this kit goes
# through _no_window(), and tools/test_no_console_window.py fails on any spawn that does not.
#
# The flag is added ONLY when this process has no console. A process that has one already shares it
# with its children and never opens a window; giving those children CREATE_NO_WINDOW would instead
# move their unredirected output and terminal prompts into a hidden console, where a hook's findings
# would vanish (measured: an unredirected child's output is simply lost). DETACHED_PROCESS and
# CREATE_NEW_CONSOLE are refused outright: the first makes Windows ignore CREATE_NO_WINDOW and
# leaves a console-less child whose own children open windows again, and the second opens a window
# by definition.
#
# Each file carries its own copy because consumers load these files one at a time by path; a
# shared sibling module would be a new way for a single copied file to fail. That test holds
# every copy identical, so the copies cannot drift.
def _console_less_windows():
    """True on Windows when this process has no console, so a console child would get a window.

    A hidden console counts as a console: children of a CREATE_NO_WINDOW child share it unseen.
    If the console cannot be queried the answer is True, the side on which no window can open.
    """
    import sys
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return not ctypes.WinDLL("kernel32").GetConsoleCP()
    except (ImportError, AttributeError, OSError):
        return True


def _no_window(**kwargs):
    """Return subprocess keywords that can never open a console window.

    Merges into any creationflags the caller passes: subprocess.run(args, **_no_window(cwd=root)).
    """
    flags = kwargs.get("creationflags", 0) or 0
    if flags & 0x00000018:              # DETACHED_PROCESS | CREATE_NEW_CONSOLE
        raise ValueError("DETACHED_PROCESS and CREATE_NEW_CONSOLE can open console windows")
    if _console_less_windows():
        kwargs["creationflags"] = flags | 0x08000000      # CREATE_NO_WINDOW
    return kwargs


MANIFEST = ".dataclass.json"

# A file whose name says "this is a published SHAPE, not a record". Exempt from the shape check, in
# either naming convention, because check 3 REQUIRES a schema next to every declared DATA path and
# `metrics/live-runs.jsonl.example` must not therefore become a violation of check 4.
SHAPE_EXEMPT = re.compile(r"\.(example|sample|tmpl|template)(\.|$)", re.I)

# The shapes real runs leave behind in this fleet. Each entry is (why, pattern).
#
# WHAT THIS LIST IS FOR, AND WHAT IT IS NOT. It answers one question about a NAME: does this look
# like something a run produced. It is not a description of any particular skill's output, and the
# moment it starts becoming one it stops being maintainable by anyone but that skill's author.
#
# WHY IT CANNOT BE TRUSTED ON ITS OWN. Checks 1, 2, 3 and 5 read a manifest and object to what they
# find there, so a mistake in them surfaces as a wrong verdict. Check 4 objects only to what it
# RECOGNISES, so a list that recognises nothing prints byte for byte what a repo with nothing to
# find prints. That is not hypothetical. The predecessor of this list was assembled from a handful
# of skills' filenames and never held against a real run: measured against one skill's actual daily
# output it matched 0 of 116 files, and across the fleet it matched 16 of 54 representative names
# with 7 of 18 repos scoring zero, while every one of those repos writes output on every run.
#
# So a repo does not rely on this list alone. Each declares `_run_shape_probes` in its own
# .dataclass.json: the SCHEMATIC names ITS runs produce, held against this list with
# `--explain`. That is where a skill's inventory belongs. This file stays generic, and a probe that
# matches nothing here is a gap in this list reported by name rather than a silent miss.
#
# WHERE THESE PATTERNS CAME FROM. Six of the twelve were calibrated in daily-hotspots against a real
# run, the only place in the fleet where that had been done, and promoted here on 2026-08-30 after
# being scored against every git-tracked file in all 18 public repos: zero undeclared hits, so
# nothing turns red on adoption. They carry some vocabulary harvested from real skills (roster,
# candidates, cards, shards) and that is deliberate, because these ARE the words this fleet's
# pipelines use. What is NOT promoted is the per-skill inventory that surrounded them: which files
# that one skill writes, in what size, on which day. That belongs in its probes, not here.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

RUN_SHAPES = (
    ("a jsonl ledger under metrics/ -- the exact shape of the 2026-07 leak",
     re.compile(r"(^|/)metrics/.*\.(jsonl|ndjson)$", re.I)),
    ("anything under a runs/ directory -- per-run output",
     re.compile(r"(^|/)runs/", re.I)),
    ("a DATED RUN DIRECTORY -- one whole tree per real run, scratch and captures alike",
     re.compile(r"(^|/)\.?runs?[-_]\d{4}-\d{2}-\d{2}", re.I)),
    ("a dated file under an output directory -- a dated file is a record of a day, not a tool",
     re.compile(r"(^|/)(reports?|archive|digests?|logs?|out|output|state|snapshots?)/"
                r".*(\d{4}-\d{2}-\d{2}|\d{4}-\d{2}(?!\d)|\d{8})", re.I)),
    ("a jsonl ledger under an output directory",
     re.compile(r"(^|/)(archive|logs?|state|out|output|runs|reports?)/.*\.(jsonl|ndjson)$", re.I)),
    ("a DATE-STAMPED or MONTH-SHARDED record -- the date is there because a run happened",
     re.compile(r"(^|/)[A-Za-z0-9_.-]*[-_]\d{4}-\d{2}(-\d{2})?"
                r"([-_.][A-Za-z0-9_.-]*)?\.(jsonl|ndjson|json|md|txt|csv|log|rss|html|py)$", re.I)),
    ("a filename this fleet uses for a live ledger",
     re.compile(r"(^|/)(ledger|live-runs|events|dry-run|verdicts|opportunities|history|transcript"
                r"|pulls-\d{4}-\d{2})([-_.][A-Za-z0-9_.-]+)?\.(jsonl|ndjson)$", re.I)),
    ("a filename this fleet uses for real-run state",
     re.compile(r"(^|/)(escalation_state|fleet-check-status|bandit-state|throttle-state"
                r"|dedup-state)\.json$", re.I)),
    # `roster-evolution.md` is the DESIGN NOTE for the roster and must not match; `roster-review.md`
    # is the report a real run emits and must. Hence the .md arm is a name, not a wildcard: a shape
    # broad enough to swallow the documentation would be turned off within a week.
    ("a ROSTER -- this skill evolves it from real runs, so it is output, not configuration",
     re.compile(r"(^|/)roster([-_][A-Za-z0-9_.-]*)?\.(json|jsonl)$"
                r"|(^|/)roster[-_]review\.md$", re.I)),
    # NOTE: the trailing arm deliberately excludes `.md`. With it, any `*_log.md` matched,
    # and `feedback_log.md` / `change_log.md` / `audit_log.md` are ordinary hand-written
    # documentation idioms. A raw capture is what a source returned; nobody returns markdown.
    # Measured 2026-08-30: that one character class was the only over-match this list
    # produced across every tracked file in all 18 repos, and it reported a real file with a
    # reason that had nothing to do with why the file is interesting.
    ("a RAW THIRD-PARTY CAPTURE -- whatever a source returned on the day it was polled",
     re.compile(r"(^|/)(raw|reddit_raw|captures?|parts\d*|shards?|chunks?|_d)/"
                r"|(^|/)raw[-_][A-Za-z0-9_.-]+\.(json|jsonl|ndjson|txt|html)$"
                r"|[-_](raw|out|log|err|dump)\.(json|jsonl|ndjson|txt|log)$", re.I)),
    ("a COLLECTION INTERMEDIATE -- the pipeline's own working set for one run",
     re.compile(r"(^|/)(candidates?|signals?|clusters?|cards|supply_cards|demand_cards|demand_\w+"
                r"|all_jobs|raw_jobs|sources|sources_result|result|run_out|roster_plan"
                r"|roster_raw_\d+|roster_shard_\d+|dry)\.(json|jsonl|ndjson)$", re.I)),
    ("a database file -- nobody hand-writes one, so it came from a run",
     re.compile(r"\.(db|sqlite|sqlite3)$", re.I)),
    # CLAUDE CODE SESSION TRANSCRIPTS (added 2026-09-27). A transcript is the most complete record
    # of a person this machine produces: every prompt, every file read, every tool result, verbatim.
    # Until this date none of the shapes above recognised one, so a real session committed into a
    # public repo passed check 4. Measured with --explain against a schematic listing of the real
    # session tree: 1 of 6 names matched, and only by the accident of a ledger called transcript.
    #
    # These four were calibrated against a real Claude Code session tree, read from OUTSIDE
    # every repo and reduced to shapes before anything was written here: 1697 top-level
    # <uuid>.jsonl, ~6000 subagents/**/agent-<id>.jsonl (some .jsonl.gz), 13800 agent-<id>.meta.json,
    # and <uuid>/tool-results/ and <uuid>/workflows/ sidecars. Scored against every tracked file of
    # every local consumer before promotion. Deliberately NOT here: a bare `*.jsonl`, which is the
    # most ordinary test-fixture extension there is. Each arm below needs something no hand-written
    # file carries: a full RFC 4122 UUID as the whole stem, a `subagents/agent-` path, a UUID
    # directory holding a session sidecar, or Claude Code's encoded project directory name.
    # The workflow-journal, tool-result and custom-title arms catch a session's sidecar folder
    # copied WITHOUT its UUID parent (review 2026-09-27: 593 journals and every tool-result
    # passed once the parent was stripped). Each still needs a name no hand-written file carries.
    ("a CLAUDE CODE SESSION TRANSCRIPT -- a UUID-named .jsonl is one whole conversation, verbatim",
     re.compile(r"(^|/)" + _UUID + r"\.jsonl(\.gz)?$"
                r"|(^|/)\.fork-" + _UUID + r"\.tmp$", re.I)),
    ("a CLAUDE CODE SUBAGENT TRANSCRIPT -- subagents/**/agent-<id>.jsonl and its .meta.json",
     re.compile(r"(^|/)subagents/(.+/)?agent-[A-Za-z0-9_.-]+\.(jsonl(\.gz)?|meta\.json)$"
                r"|(^|/)subagents/workflows/wf_[A-Za-z0-9_-]+/journal\.jsonl(\.gz)?$", re.I)),
    ("a CLAUDE CODE SESSION SIDECAR -- tool results and workflow state kept beside a transcript",
     re.compile(r"(^|/)" + _UUID + r"/(subagents|tool-results|workflows)/"
                r"|(^|/)" + _UUID + r"/custom-title\.json$"
                r"|(^|/)tool-results/toolu_[A-Za-z0-9_-]+\.(txt|json)$"
                r"|(^|/)tool-results/pdf-" + _UUID + r"/page-[0-9]+\.(jpg|jpeg|png)$", re.I)),
    # The encoded form replaces every path separator (and the drive colon) with '-': a Windows
    # project becomes `C--Users-name-proj`, a POSIX one `-home-name-proj`. The POSIX arm names the
    # roots rather than accepting any leading hyphen, because `-foo/` is otherwise just an odd name.
    ("a CLAUDE CODE PROJECT DIRECTORY -- everything under it is some session's transcript or memory",
     re.compile(r"(^|/)[A-Za-z]--[A-Za-z0-9._-]+/"
                r"|(^|/)-(home|Users|root|mnt|workspaces?|tmp|var|opt|srv|private)-[A-Za-z0-9._-]*/"
                r"|(^|/)\.claude/projects/", re.I)),
)


class GitError(RuntimeError):
    """A git invocation this check depends on did not succeed.

    Raised, never swallowed. See _run for why an exception and not an empty string.
    """


def _run(args, cwd, env=None):
    """Run a git command and return its stdout.

    THIS USED TO FAIL OPEN, and on the PRIMARY control that is worse than on the backstop.
    The old body was `return p.stdout if p.returncode == 0 else ""`. `tracked()` read that
    empty string as an ANSWER (no tracked files), every per-file check then iterated zero
    times, and main() printed "data_boundary: clean (... 0 tracked files ...)" and exited 0
    having examined nothing. Anything that breaks git produced that: a shell .git directory
    (a shape that has actually occurred on this machine), a directory that is not a repo,
    git missing from PATH, an index.lock, a dubious-ownership refusal.

    pii_guard and dash_guard were hardened against exactly this and this file was the
    outlier, which meant the two scanners disagreed about the same broken environment:
    pii_guard --tree exited 2 saying NOTHING was examined while data_boundary next to it
    printed clean and exited 0. install.py:86 calls this file the PRIMARY control, so the
    control was the one lying.

    A nonzero exit now RAISES, carrying git's own stderr. A clean report requires that the
    scan actually happened.

    encoding="utf-8" is load bearing, not decoration: without it text=True decodes with the
    locale codepage (cp936 here) while git emits UTF-8, and errors="replace" silently turns
    a repo path containing non-ASCII into mojibake. The `git ls-files` that follows then
    runs in a directory that does not exist.
    """
    environment = dict(os.environ if env is None else env)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        p = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env=environment, **_no_window())
    except (OSError, ValueError) as e:
        raise GitError("cannot execute `%s` in %s: %s\n"
                       "  git must be runnable for this check to mean anything."
                       % (" ".join(args), cwd, e)) from e
    if p.returncode != 0:
        raise GitError("`%s` exited %d in %s\n  %s"
                       % (" ".join(args), p.returncode, cwd,
                          (p.stderr or "").strip() or "(no stderr)"))
    return p.stdout


def _repo_root(start):
    """Resolve the work tree root, or raise.

    The old body ended in `or start`, so a directory that is not a work tree quietly became
    its own "repo root". Everything downstream then scanned a non-repo and reported clean.
    That is the same defect pii_guard was fixed for; refusing here is the whole point.
    """
    root = _run(["git", "rev-parse", "--show-toplevel"], start).strip()
    if not root:
        raise GitError("git named no toplevel for %s (is it a work tree?)" % start)
    return root


def load_manifest(root):
    p = os.path.join(root, MANIFEST)
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def tracked(root):
    """Every git-tracked path, NUL-separated so non-ASCII names survive.

    Why -z: `git ls-files` without it renders any path containing a non-ASCII byte as a
    C-quoted escape string (quotes included, e.g. "ä¸­...md"). Those strings are
    not paths. They do not open, and every regex anchored on a real suffix misses them.
    Callers read this list as an ANSWER, so such a file got counted in the tracked total and
    then silently excluded from every per-file match. Measured 2026-08-19: a tracked
    metrics/<CJK>-live-runs.jsonl produced "clean (... 3 tracked files carry no real-run
    shape)" with rc=0, while byte-identical content under an ASCII name produced rc=1.
    -z makes git emit raw bytes with NUL separators, so the name round-trips.
    """
    return {p for p in _run(["git", "ls-files", "-z"], root).split("\0") if p}


def gitlinks(root):
    """Return submodule paths and object IDs recorded by the parent index."""
    result = {}
    for entry in _run(["git", "ls-files", "--stage", "-z"], root).split("\0"):
        if entry:
            metadata, path = entry.split("\t", 1)
            mode, sha, stage = metadata.split()
            if mode == "160000" and stage == "0":
                result[path] = sha
    return result


def _covered(rel, pats):
    """Is `rel` the declared path itself, or under it when the declaration names a directory?"""
    return any(rel == p or rel.startswith(p.rstrip("/") + "/") for p in pats)


def _data_covered(rel, patterns):
    return any(fnmatch.fnmatch(rel, p.rstrip("/"))
               or fnmatch.fnmatch(rel, p.rstrip("/") + "/*") for p in patterns)


def validate_declarations(m, out):
    """Require one spelling before any declaration is used by any check."""
    for key in ("data", "data_sealed", "fixture", "tool"):
        values = m.get(key, [])
        if not isinstance(values, list):
            out.append(("DATA-PATH", MANIFEST, "%s must be a list of relative paths" % key))
            continue
        for value in values:
            path = value[:-1] if isinstance(value, str) and value.endswith("/") else value
            if (not isinstance(path, str) or not path or "\\" in path
                    or ntpath.splitdrive(path)[0] or path.startswith("/")
                    or any(part in ("", ".", "..") or part.endswith((".", " "))
                           for part in path.split("/"))):
                out.append(("DATA-PATH", str(value),
                            "%s declarations require canonical repository-relative paths" % key))


def physical_paths(root):
    """Enumerate files and links without reading contents or entering linked trees.

    Ordinary container directories are not additional run artifacts. Declared DATA directories
    have their own absence check, including empty directories.
    """
    def scan_error(error):
        raise error

    submodules = gitlinks(root)
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=scan_error):
        descend = []
        for name in sorted(dirs + files):
            if name == ".git":
                continue
            path = os.path.join(directory, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if name in dirs:
                info = os.lstat(path)
                linked = os.path.islink(path) or bool(getattr(info, "st_file_attributes", 0) & 0x400)
                if linked:
                    yield rel + "/"
                elif rel not in submodules:
                    descend.append(name)
            else:
                yield rel
        dirs[:] = descend


def check_data_not_tracked(root, m, files, out):
    """A DATA path in the index means the skill wrote the operator's real life into a public repo.

    `data_sealed` is the same rule for a path that is DEAD: it held real data once, the data has
    been moved out and purged from history, and it must never come back. .gitignore already covers
    it, but .gitignore is advisory -- `git add -f` walks straight through, and an agent that wants
    a file tracked will find that flag. This makes the seal enforceable. It differs from `data`
    only in that a dead path is not owed a schema: publishing one would advertise a path the tool
    no longer uses.
    """
    pats = m.get("data", []) + m.get("data_sealed", [])
    for rel in sorted(files):
        if _data_covered(rel, pats):
            out.append(("DATA-TRACKED", rel,
                        "real-run output must live in the private companion config, not here"))


def check_data_absent_from_worktree(root, m, out):
    """Declared DATA must be absent, including ignored files and sealed directories.

    Inspect names only. Literal prefixes prune unrelated trees without exempting directory
    names such as guards/ or .venv/. Never follow a link into a possible data store.
    """
    pats = [p.rstrip("/") for p in m.get("data", []) + m.get("data_sealed", [])]
    if not pats:
        return
    prefixes = []
    for pattern in pats:
        parts = pattern.split("/")
        if not pattern or os.path.isabs(pattern) or ".." in parts or "\\" in pattern:
            out.append(("DATA-PATH", pattern, "DATA declarations must be repository-relative paths"))
            return
        literal = []
        for part in parts:
            if any(char in part for char in "*?["):
                break
            literal.append(part)
        prefixes.append(os.path.normcase("/".join(literal)).replace("\\", "/"))

    def may_contain(rel):
        rel = os.path.normcase(rel).replace("\\", "/")
        return any(not p or p == rel or p.startswith(rel + "/") or rel.startswith(p + "/")
                   for p in prefixes)

    def scan_error(error):
        raise error

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=scan_error):
        descend = []
        for name in sorted(dirnames + filenames):
            if name == ".git":
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            relevant = _data_covered(rel, pats)
            is_dir = name in dirnames
            if is_dir and may_contain(rel):
                info = os.lstat(full)
                linked = os.path.islink(full) or bool(getattr(info, "st_file_attributes", 0) & 0x400)
                if linked:
                    relevant = True
                elif not relevant:
                    descend.append(name)
            if relevant:
                out.append(("DATA-PRESENT", rel,
                            "DATA paths must be physically absent from the tool worktree; "
                            "use the private companion repository"))
        dirnames[:] = descend


def check_data_has_schema(root, m, out):
    """An uninitialized tool must still be USABLE: ship the shape, never the contents.

    Without this, "keep real data out of the repo" degrades into "the repo no longer explains what it
    expects", and the next person to wire it up guesses -- or, far more likely, an agent recreates a
    convenient real-looking file to work against. The schema is what makes the empty tool honest.

    Both conventions are accepted: `x.jsonl.example` and the older `config.example.json`. A DATA path
    ending in `/` is a whole output directory; there is no single shape to publish for it.
    """
    for pat in m.get("data", []):
        if pat.endswith("/"):
            continue
        stem, ext = os.path.splitext(pat)
        if any(os.path.isfile(os.path.join(root, c))
               for c in (pat + ".example", stem + ".example" + ext)):
            continue
        out.append(("NO-SCHEMA", pat + ".example",
                    "publish the schema so the tool is usable uninitialized"))


def check_fixtures_are_generated(root, m, out):
    """The whole reason fixtures are generated: a real record CANNOT be regenerated.

    Hand-pasting a real email into a golden file is the single move that produced most of the 2026-07
    leaks. Requiring byte-equality with a deterministic generator makes that move fail loudly at
    commit time, instead of relying on someone noticing, months later, that a sender address in a
    test fixture was somebody's actual inbox.
    """
    fixtures = m.get("fixture", [])
    if not fixtures:
        return
    gen = os.path.join(root, "tools", "make_fixtures.py")
    if not os.path.isfile(gen):
        out.append(("NO-GENERATOR", "tools/make_fixtures.py",
                    "fixtures are declared but nothing can regenerate them -- so nothing proves "
                    "they are synthetic"))
        return
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run([sys.executable, gen, "--out", td], cwd=root,
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           **_no_window())
        if p.returncode != 0:
            out.append(("GENERATOR-FAILED", "tools/make_fixtures.py",
                        (p.stderr or "").strip().splitlines()[-1] if p.stderr else "non-zero exit"))
            return
        for rel in fixtures:
            live = os.path.join(root, rel)
            fresh = os.path.join(td, os.path.basename(rel))
            if not os.path.isfile(fresh):
                out.append(("NOT-GENERATED", rel, "generator does not produce this fixture"))
                continue
            if not os.path.isfile(live):
                out.append(("MISSING", rel, "declared fixture is absent; run make_fixtures.py"))
                continue
            a = open(live, "rb").read().replace(b"\r\n", b"\n")
            b = open(fresh, "rb").read().replace(b"\r\n", b"\n")
            if a != b:
                out.append(("HAND-EDITED", rel,
                            "does not match the generator -- a real record cannot be regenerated. "
                            "Change the SCHEMA, then run: python tools/make_fixtures.py"))


def _resolver_path(target):
    """Select a tracked resolver from this tool or the target's registered guard submodule."""
    modules = os.path.join(target, ".gitmodules")
    selected = []
    if os.path.isfile(modules):
        config = {}
        for entry in _run(["git", "config", "--file", modules, "--null", "--list"], target).split("\0"):
            if entry:
                key, _, value = entry.partition("\n")
                config.setdefault(key, []).append(value)
        for key, values in config.items():
            if not key.startswith("submodule.") or not key.endswith(".url"):
                continue
            if any(_github_repo_key(value) == ("daizedong", "fleet-guards") for value in values):
                paths = config.get(key[:-3] + "path", [])
                if len(values) != 1 or len(paths) != 1:
                    raise RuntimeError("guard submodule declaration is ambiguous")
                selected.append(paths[0])
    if len(selected) > 1:
        raise RuntimeError("multiple guard submodules are registered; resolver provenance is ambiguous")
    if selected:
        relative = selected[0]
        if (not relative or "\\" in relative or ntpath.splitdrive(relative)[0]
                or any(part in ("", ".", "..") for part in relative.split("/"))):
            raise RuntimeError("guard submodule path must be canonical and repository-relative")
        if relative not in gitlinks(target):
            raise RuntimeError("guard submodule has no authoritative gitlink in the index")
        deployment = os.path.realpath(os.path.join(target, relative))
        if os.path.commonpath([deployment, target]) != target or deployment == target:
            raise RuntimeError("guard submodule resolves outside the target worktree")
        if not os.path.isdir(deployment) or os.path.realpath(_repo_root(deployment)) != deployment:
            raise RuntimeError("guard submodule checkout is incomplete")
    else:
        deployment = os.path.realpath(_repo_root(os.path.dirname(os.path.abspath(__file__))))
        if deployment != target or os.path.dirname(os.path.abspath(__file__)) != os.path.join(target, "tools"):
            raise RuntimeError("no guard submodule is registered; run the target's own tools/data_boundary.py "
                               "or supply --companion-dir explicitly")
    resolver = os.path.join(deployment, "tools", "datadir.py")
    if not os.path.isfile(resolver) or os.path.realpath(resolver) != resolver:
        raise RuntimeError("the selected guard deployment has no local tools/datadir.py")
    info = os.lstat(resolver)
    if getattr(info, "st_file_attributes", 0) & 0x400:
        raise RuntimeError("the selected resolver is a redirected file")
    entries = _run(["git", "ls-files", "--stage", "-z", "--", "tools/datadir.py"], deployment).split("\0")
    entries = [entry for entry in entries if entry]
    if len(entries) != 1 or entries[0].split("\t", 1)[0].split()[0] not in ("100644", "100755"):
        raise RuntimeError("the selected tools/datadir.py is not a tracked regular source file")
    return resolver


def _resolve_companion(start):
    """Ask the intended deployment's resolver for the writer's actual DATA destination."""
    target = os.path.realpath(_repo_root(start))
    resolver = _resolver_path(target)
    spec = importlib.util.spec_from_file_location("_data_boundary_datadir", resolver)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fn = getattr(mod, "resolve_data_dir", None)
    if fn is None:
        raise RuntimeError("the selected resolver has no resolve_data_dir API")
    destination = fn(os.path.basename(target))
    return str(destination) if destination else None


def _github_repo_key(url):
    """Recognize an unambiguous GitHub destination without exposing URL credentials."""
    from urllib.parse import urlsplit
    if url.startswith("git@github.com:"):
        path = url[len("git@github.com:"):]
    else:
        if not url.startswith(("https://", "ssh://")) or any(ord(char) < 32 for char in url):
            return None
        try:
            parsed = urlsplit(url)
            if (parsed.scheme not in ("https", "ssh") or parsed.hostname != "github.com"
                    or parsed.password or parsed.query or parsed.fragment or parsed.port is not None
                    or parsed.netloc.endswith(":")
                    or parsed.username not in (None, "git")):
                return None
        except ValueError:
            return None
        path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", path):
        return None
    owner, name = path.lower().split("/")
    return None if name in (".", "..") else (owner, name)


def _github_publication_route(url):
    """Parse a publication identity while retaining the SSH host that needs proof."""
    from urllib.parse import urlsplit
    if not isinstance(url, str) or any(character.isspace() or ord(character) < 32 for character in url):
        return None, None
    if url.startswith("https://"):
        return _github_repo_key(url), None
    if "?" in url or "#" in url:
        return None, None
    if url.startswith("git@"):
        match = re.fullmatch(r"git@([A-Za-z0-9][A-Za-z0-9_.-]*):([^:]+)", url)
        if not match:
            return None, None
        host, path = match.groups()
    elif url.startswith("ssh://"):
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            if (parsed.username != "git" or parsed.password is not None or parsed.port is not None
                    or not host or parsed.netloc.casefold() != ("git@" + host).casefold()
                    or not parsed.path.startswith("/")):
                return None, None
        except ValueError:
            return None, None
        path = parsed.path[1:]
    else:
        return None, None
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", host):
        return None, None
    key = _github_repo_key("git@github.com:" + path)
    return (key, host.casefold()) if key is not None else (None, None)


def _ssh_profile_home():
    """OpenSSH can use the account profile independently of HOME or USERPROFILE."""
    try:
        if os.name == "nt":
            import ctypes
            buffer = ctypes.create_unicode_buffer(32768)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 0x28, None, 0, buffer) != 0:
                return None
            return buffer.value or None
        import pwd
        return pwd.getpwuid(os.getuid()).pw_dir
    except (OSError, ImportError, AttributeError, KeyError):
        return None


def _git_windows_installation(selected):
    """Recognize launcher layouts, including the executable Git prepends inside hooks."""
    from pathlib import Path

    if not selected:
        return None
    executable = Path(selected)
    if (not executable.is_absolute() or executable.name.casefold() != "git.exe"
            or ".." in executable.parts):
        return None
    if executable.parent.name.casefold() in {"bin", "cmd"}:
        installation = executable.parent.parent
        return installation.parent if installation.name.casefold() in {"mingw32", "mingw64"} else installation
    if (executable.parent.name.casefold() == "git-core"
            and executable.parents[1].name.casefold() == "libexec"
            and executable.parents[2].name.casefold() in {"mingw32", "mingw64"}):
        return executable.parents[3]
    return None


def _ssh_config_sources():
    """Conservative scan paths and plausible chains for the selected recognized client."""
    import shutil
    from pathlib import Path
    client = shutil.which("ssh")
    canonical = lambda path: os.path.normcase(os.path.realpath(path))
    profile = _ssh_profile_home()
    if not profile:
        return None
    homes = {profile, os.path.expanduser("~"), os.environ.get("HOME"), os.environ.get("USERPROFILE")}
    candidates = [str(Path(home) / ".ssh/config") for home in homes if home and home != "~"]
    user_paths = {os.path.normcase(os.path.abspath(path)): path for path in sorted(candidates)}
    if not user_paths:
        return None
    user_paths = set(user_paths.values())
    paths = set(user_paths)
    if os.name == "nt":
        windows, program_data = os.environ.get("SystemRoot"), os.environ.get("ProgramData")
        if not windows or not program_data:
            return None
        system = str(Path(program_data) / "ssh/ssh_config")
        clients = {canonical(Path(windows) / "System32/OpenSSH/ssh.exe"): system}
        paths.add(system)
        installation = _git_windows_installation(shutil.which("git"))
        if installation is not None:
            system = str(installation / "etc/ssh/ssh_config")
            bundled = installation / "usr/bin/ssh.exe"
            clients[canonical(bundled)] = system
            paths.add(system)
            # Git for Windows prepends its bundled tools when launching SSH.
            if bundled.is_file():
                client = str(bundled)
    else:
        clients = {canonical(name): "/etc/ssh/ssh_config" for name in ("/usr/bin/ssh", "/bin/ssh")}
        paths.add("/etc/ssh/ssh_config")
    if not client:
        return None
    selected_system = clients.get(canonical(client))
    if selected_system is None:
        return None
    return {"paths": sorted(paths), "chains": [(name, selected_system) for name in sorted(user_paths)]}


def _ssh_config_paths():
    sources = _ssh_config_sources()
    return sources["paths"] if sources is not None else None


def _ssh_configuration_problem(host="github.com"):
    """Prove a literal SSH host under a deliberately small static OpenSSH policy.

    Never invoke ssh -G: evaluating Match exec there can execute configuration commands.
    Unknown clients, redirects, Includes, Match, proxies and unsupported active options fail closed.
    Server authentication must retain default trust files and default, yes, or ask verification.
    Callers supply the explicit git user from a parsed URL. Aliases additionally require
    explicit HostName github.com in every plausible chain; conflicting User options fail.
    """
    import fnmatch
    import shlex
    import stat
    from pathlib import Path
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", host):
        return "SSH hostname is outside the static policy"
    host = host.casefold()
    if host == "github.com":
        paths, chains = _ssh_config_paths(), None
    else:
        sources = _ssh_config_sources()
        paths = sources["paths"] if sources is not None else None
        chains = sources["chains"] if sources is not None else None
    if paths is None:
        return "SSH client or default configuration locations are unproven"
    if host != "github.com" and (not chains or any(
            len(chain) != 2 or any(name not in paths for name in chain) for chain in chains)):
        return "SSH alias configuration chains are unproven"
    harmless = {"identityfile", "identitiesonly", "batchmode", "preferredauthentications",
                "passwordauthentication", "pubkeyauthentication", "kbdinteractiveauthentication",
                "loglevel",
                "connecttimeout", "serveraliveinterval", "serveralivecountmax", "tcpkeepalive",
                "addkeystoagent", "identityagent", "hashknownhosts", "sendenv", "gssapiauthentication"}
    fixed = {"hostname": "github.com", "user": "git", "port": "22"}
    explicit = {}
    for name in paths:
        explicit[name] = set()
        path = Path(name)
        try:
            for node in [*reversed(path.parents), path]:
                try:
                    info = node.lstat()
                except FileNotFoundError:
                    continue
                if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                        or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    return "SSH configuration has an unproven filesystem alias"
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                continue
            if len(data) > 65536:
                return "SSH configuration exceeds the static attestation limit"
            if b"\x00" in data:
                return "SSH configuration contains an unsupported NUL byte"
            active = True
            for line in data.decode("utf-8-sig").split("\n"):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                # The subset avoids parser-dependent inline comments and continuation rules.
                if "#" in line:
                    return "SSH configuration has unsupported inline syntax"
                fields = shlex.split(re.sub(r"^(\s*[A-Za-z]+)\s*=\s*", r"\1 ", line))
                if len(fields) < 2:
                    return "SSH configuration has an unsupported directive"
                key, values = fields[0].lower(), fields[1:]
                if key in {"include", "match"}:
                    return "SSH Include or Match cannot establish a static destination"
                if key == "host":
                    if "\\" in line or any("[" in value for value in values):
                        return "SSH Host pattern is outside the static policy"
                    matches = lambda value: fnmatch.fnmatchcase(host, value)
                    active = (any(matches(value) for value in values if not value.startswith("!"))
                              and not any(matches(value[1:]) for value in values if value.startswith("!")))
                elif active and key in fixed:
                    if (len(values) != 1 or "\\" in line
                            or (values[0] if key == "user" else values[0].lower()) != fixed[key]):
                        return "SSH configuration changes the canonical destination"
                    explicit[name].add(key)
                elif active and key == "stricthostkeychecking":
                    if len(values) != 1 or values[0].lower() not in {"yes", "ask"}:
                        return "SSH configuration does not preserve server authentication"
                elif active and key in {"userknownhostsfile", "globalknownhostsfile"}:
                    return "SSH configuration overrides the default server trust files"
                elif active and key not in harmless:
                    return "SSH configuration contains an unproven active option"
        except (OSError, UnicodeError, ValueError):
            return "SSH configuration could not be statically verified"
    if chains is not None and any(
            "hostname" not in set().union(*(explicit[name] for name in chain))
            for chain in chains):
        return "SSH alias lacks an explicit GitHub hostname in every configuration chain"
    return None


def _companion_location(destination, env):
    """Discover administration and a containing worktree under a specified Git policy."""
    root = _run(["git", "rev-parse", "--show-toplevel"], destination, env=env).strip()
    admin = _run(["git", "rev-parse", "--absolute-git-dir"], destination, env=env).strip()
    if not root or not admin:
        raise GitError("Git named no worktree or administration for the DATA destination")
    root, admin = os.path.realpath(root), os.path.realpath(admin)
    try:
        contains_data = os.path.normcase(os.path.commonpath([root, destination])) == os.path.normcase(root)
    except ValueError:
        contains_data = False
    if not contains_data:
        raise GitError("Git worktree does not contain the physical DATA destination")
    return root, admin


def _companion_git_context(destination):
    """Authorize ownership with existing Git policy, then bind the physical DATA repository.

    The hook's repository and index selectors belong to its caller. Clear them only for
    this separate proof. Existing ownership permission is checked before carrying that
    permission into a second discovery with process URL rewrites excluded.
    """
    selectors = {
        "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE",
        "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE", "GIT_PREFIX", "GIT_INTERNAL_SUPER_PREFIX",
        "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_CONFIG",
    }
    effective = {key: value for key, value in os.environ.items()
                 if key.upper() not in selectors}
    destination = os.path.realpath(destination)
    authorized_root, authorized_admin = _companion_location(destination, effective)
    physical = {key: value for key, value in effective.items()
                if not key.upper().startswith("GIT_CONFIG_")}
    physical.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                    GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_COUNT="1",
                    GIT_CONFIG_KEY_0="safe.directory",
                    GIT_CONFIG_VALUE_0=authorized_root.replace(os.sep, "/"))
    # Carry only this filesystem option; URL/config redirects remain outside the baseline.
    for entry in _run(["git", "config", "--null", "--list"], destination, env=effective).split("\0"):
        key, separator, value = entry.partition("\n")
        if key.lower() == "core.longpaths":
            physical.update(GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_1="core.longpaths",
                            GIT_CONFIG_VALUE_1=value if separator else "true")
    root, admin = _companion_location(destination, physical)
    if os.path.normcase(admin) != os.path.normcase(authorized_admin):
        raise GitError("Physical Git administration differs from the authorized repository")
    for environment in (physical, effective):
        environment.update(GIT_DIR=admin, GIT_WORK_TREE=root,
                           GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0")
    return root, physical, effective


def _companion_visibility(root, visibility_map, git_context=None):
    """Require both physical and effective destinations to have fresh PRIVATE receipts."""
    root, physical, effective = git_context or _companion_git_context(root)
    proven = set()
    for environment in (physical, effective):
        destinations, errors = _companion_visibility_once(root, visibility_map, environment)
        if errors:
            return [], errors
        proven.update(destinations)
    return sorted(proven), []


@dataclass(frozen=True)
class PrivateCompanionProof:
    """A read-only proof snapshot; private process configuration is excluded from repr."""

    root: str
    repositories: tuple
    signature: str
    _context: tuple = field(repr=False, compare=False)


def _private_configurations(context):
    root, physical, effective = context
    return tuple(_run(["git", "config", "--null", "--list"], root, env=environment)
                 for environment in (physical, effective))


def _private_signature(context, configurations):
    import hashlib

    root, physical, effective = context
    locations = [{key: value for key, value in environment.items()
                  if key.casefold() in {"path", "home", "userprofile", "systemroot", "programdata"}}
                 for environment in (physical, effective)]
    payload = [root, physical["GIT_DIR"], locations, configurations]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def prove_private_companion(destination, visibility_map=None):
    """Prove current PRIVATE publication routes without scanning or modifying DATA.

    Local built-in Git discovery/configuration reads precede transport attestation.
    This delegates to the same physical/effective policy as the companion audit;
    it never invokes SSH, a remote helper, or a network operation. Callers must
    repeat the proof before writing: a snapshot is not a filesystem lock.
    """
    from types import MappingProxyType

    context = _companion_git_context(destination)
    before = _private_configurations(context)
    repositories, errors = _companion_visibility(context[0], visibility_map, context)
    if errors:
        raise GitError("PRIVATE companion proof failed: " + "; ".join(errors))
    if before != _private_configurations(context):
        raise GitError("Companion configuration changed during PRIVATE proof")
    frozen_context = (context[0], MappingProxyType(dict(context[1])), MappingProxyType(dict(context[2])))
    return PrivateCompanionProof(context[0], tuple(sorted(repositories)),
                                 _private_signature(context, before), frozen_context)


def read_private_companion_git(proof, *arguments):
    """Read HEAD or ignore status under a still-current proof's bound Git context.

    Only rev-parse --verify HEAD and check-ignore --no-index -q -- RELATIVE_PATH
    are supported. A single trailing / preserves directory-only ignore semantics,
    including before the directory exists. The latter preserves native status 0/1. Other failures raise
    GitError without exposing captured environment or configuration values.
    """
    if not isinstance(proof, PrivateCompanionProof):
        raise GitError("A current PRIVATE companion proof is required")
    if arguments == ("rev-parse", "--verify", "HEAD"):
        accepted = {0}
    elif len(arguments) == 5 and arguments[:4] == ("check-ignore", "--no-index", "-q", "--"):
        relative = arguments[4]
        path = relative[:-1] if isinstance(relative, str) and relative.endswith("/") else relative
        if (not isinstance(relative, str) or not relative or "\0" in relative
                or ntpath.splitdrive(relative)[0] or relative.startswith(("/", "\\"))
                or (relative != "." and any(part in {"", ".", ".."}
                                            for part in path.replace("\\", "/").split("/")))):
            raise GitError("The ignore query requires a canonical relative path")
        accepted = {0, 1}
    else:
        raise GitError("Unsupported read-only companion Git query")
    if _private_signature(proof._context, _private_configurations(proof._context)) != proof.signature:
        raise GitError("Companion configuration changed after PRIVATE proof")
    try:
        result = subprocess.run(["git", *arguments], cwd=proof.root, env=proof._context[2],
                                capture_output=True, text=True, encoding="utf-8", errors="replace",
                                **_no_window())
    except (OSError, ValueError) as error:
        raise GitError("Read-only companion Git query could not run") from error
    if result.returncode not in accepted:
        raise GitError("Read-only companion Git query failed with status %d" % result.returncode)
    if _private_signature(proof._context, _private_configurations(proof._context)) != proof.signature:
        raise GitError("Companion configuration changed during read-only query")
    return result


_HTTPS_PERFORMANCE_KEYS = {
    "version", "maxrequests", "minsessions", "postbuffer", "lowspeedlimit",
    "lowspeedtime", "keepaliveidle", "keepaliveinterval", "keepalivecount",
}
_HTTPS_PERFORMANCE_ENV = {"git_http_low_speed_limit", "git_http_low_speed_time"}
_PROXY_ENV = {"http_proxy", "https_proxy", "all_proxy"}
_GITHUB_NO_PROXY = {"github.com", ".github.com"}


def _no_proxy_exempts_github(env):
    """Prove that an environment proxy cannot carry Git's connection to github.com.

    Git hands NO_PROXY/no_proxy to libcurl as CURLOPT_NOPROXY, and libcurl then connects
    directly to an exempted host whatever proxy the environment names. A launcher that
    proxies only its own API traffic (a local split-billing tunnel) can therefore keep
    github.com on the default route. Only forms that every supported libcurl reads the
    same way count: the whole value "*", or a comma-separated entry that is exactly
    github.com or .github.com. Every spelling present must exempt it, because which one
    Git reads differs between Windows and POSIX. Trust overrides are judged separately.
    """
    values = [value for name, value in env.items() if name.casefold() == "no_proxy"]
    if not values:
        return False
    for value in values:
        if not isinstance(value, str):
            return False
        if value.strip() == "*":
            continue
        if not any(entry.strip().casefold() in _GITHUB_NO_PROXY for entry in value.split(",")):
            return False
    return True


def _git_bundled_ca(value, env):
    """Recognize the selected Git for Windows installation's default CA bundle.

    Explicitly naming that bundle preserves the client's packaged trust. A custom
    file, missing file or filesystem alias cannot receive this default-trust credit.
    This checks package layout and topology, without reading certificate contents.
    Git for Windows may hard-link its launcher; executable integrity remains a
    prerequisite of invoking Git. The certificate bundle must have one link.
    """
    import shutil
    import stat
    from pathlib import Path
    if os.name != "nt" or not isinstance(value, str):
        return False
    selected = shutil.which("git", path=env.get("PATH"))
    installation = _git_windows_installation(selected)
    if installation is None:
        return False
    executable, requested = Path(selected), Path(value)
    if not requested.is_absolute() or ".." in requested.parts:
        return False
    candidates = [installation / architecture / "etc/ssl/certs/ca-bundle.crt"
                  for architecture in ("mingw32", "mingw64")]
    canonical = lambda path: os.path.normcase(os.path.abspath(path))
    if canonical(requested) not in {canonical(path) for path in candidates}:
        return False
    try:
        for path in (executable, requested):
            for node in [*reversed(path.parents), path]:
                info = node.lstat()
                if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                        or path == requested and stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    return False
            if not stat.S_ISREG(info.st_mode):
                return False
    except (OSError, ValueError):
        return False
    return True


def _https_configuration_problem(config_entries, env):
    """Prove default HTTPS routing and trust under a small static configuration policy.

    A PRIVATE receipt identifies the repository, but cannot authorize a different
    connection selected by a proxy, resolver, custom trust file, or transport helper.
    Standard TLS backends and Git for Windows' own bundle preserve default trust. A
    proxy variable is not an override when NO_PROXY exempts github.com for Git.
    Diagnostics name only the category; configuration values can contain secrets.
    """
    bypassed = _no_proxy_exempts_github(env)
    for name in env:
        key = name.casefold()
        if key in _PROXY_ENV and bypassed:
            continue
        if (key in _PROXY_ENV | {"curl_ca_bundle", "ssl_cert_file", "ssl_cert_dir",
                                 "curl_ssl_backend", "git_exec_path"}
                or key.startswith(("git_ssl_", "git_proxy_ssl_"))
                or (key.startswith("git_http_") and key not in _HTTPS_PERFORMANCE_ENV)):
            return "unproved HTTPS environment override"
    # Inspect every occurrence, including URL scopes and values before an empty reset.
    for key, value in config_entries:
        key = key.casefold()
        option = key.rsplit(".", 1)[-1]
        if key.startswith("remote.") and option.startswith("proxy"):
            return "unproved remote HTTPS proxy"
        if not key.startswith("http."):
            continue
        if option in _HTTPS_PERFORMANCE_KEYS:
            continue
        if option == "sslverify" and value is not None and value.strip().casefold() in {"true", "yes", "on", "1"}:
            continue
        if (option == "sslbackend" and isinstance(value, str)
                and value.casefold() in ({"openssl", "schannel"} if os.name == "nt" else {"openssl"})):
            continue
        if option == "sslcainfo" and _git_bundled_ca(value, env):
            continue
        if (key in {"http.extraheader", "http.https://github.com/.extraheader"}
                and isinstance(value, str)
                and re.fullmatch(r"(?i)authorization: *(?:basic [A-Za-z0-9+/]+=*|bearer [A-Za-z0-9._~+/-]+=*)", value)):
            continue
        return "unproved HTTP configuration override"
    return None


def _companion_visibility_once(root, visibility_map, env):
    """Require fresh PRIVATE evidence for every effective fetch and push destination.

    Reuse pii_guard's visibility receipt format and maximum age. Git expands insteadOf and
    pushInsteadOf through get-url. Explicit remote selectors must name an attested remote.
    SSH aliases require a static proof of their literal host before receipts authorize DATA.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pii_guard.py")
    try:
        spec = importlib.util.spec_from_file_location("_boundary_visibility", path)
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        visibility = guard._load_visibility(visibility_map)
    except (OSError, ValueError, RuntimeError, ImportError, AttributeError):
        return [], ["companion visibility receipt could not be verified"]
    if visibility is None:
        return [], ["companion has no visibility receipt; visibility is UNKNOWN"]
    public, private, age = visibility
    if age is None or not 0 <= age <= guard.VIS_MAX_AGE_S:
        return [], ["companion visibility receipt is undated, stale or future-dated; visibility is UNKNOWN"]
    remotes = _run(["git", "remote"], root, env=env).splitlines()
    if not remotes:
        return [], ["companion has no configured remote; visibility is UNKNOWN"]
    config = {}
    config_entries = []
    for entry in _run(["git", "config", "--null", "--list"], root, env=env).split("\0"):
        if entry:
            key, separator, value = entry.partition("\n")
            config_entries.append((key, value if separator else None))
            config[key.lower()] = value
    for key, value in config_entries:
        normalized = key.casefold()
        if (normalized == "remote.pushdefault"
                or normalized.startswith("branch.") and normalized.rsplit(".", 1)[-1] in {"remote", "pushremote"}):
            if value == "." or value not in remotes:
                return [], ["companion remote selection is not a configured remote; visibility is UNKNOWN"]
    if any(key.startswith("remote.") and key.rsplit(".", 1)[-1] in {"vcs", "uploadpack", "receivepack"}
           for key in config):
        return [], ["companion has a custom remote transport command; visibility is UNKNOWN"]
    ssh_override = (any(name.upper() in {"GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_EXEC_PATH"}
                        for name in env)
                    or any(name in config for name in ("core.sshcommand", "ssh.variant")))
    ssh_checks = {}
    https_check = []
    proven, errors = set(), []
    for remote in remotes:
        for role, options in (("fetch", []), ("push", ["--push"])):
            urls = _run(["git", "remote", "get-url", *options, "--all", remote], root, env=env).splitlines()
            if not urls:
                errors.append("companion remote %s %s has no destination; visibility is UNKNOWN" % (remote, role))
            for url in urls:
                key, ssh_host = _github_publication_route(url)
                if key is not None and url.startswith("https://"):
                    if not https_check:
                        https_check.append(_https_configuration_problem(config_entries, env))
                    if https_check[0]:
                        errors.append("companion HTTPS destination is UNKNOWN: " + https_check[0])
                        continue
                if key is not None and ssh_host is not None:
                    if ssh_host not in ssh_checks:
                        ssh_checks[ssh_host] = ("custom SSH transport override" if ssh_override
                                                else _ssh_configuration_problem(ssh_host))
                    if ssh_checks[ssh_host] is not None:
                        errors.append("companion SSH destination is UNKNOWN: " + str(ssh_checks[ssh_host]))
                        continue
                if key is None:
                    errors.append("companion remote %s %s destination is UNKNOWN" % (remote, role))
                elif key[1] in public.get(key[0], set()):
                    errors.append("companion destination %s/%s is PUBLIC" % key)
                elif key not in private:
                    errors.append("companion destination %s/%s is UNKNOWN" % key)
                else:
                    proven.add("%s/%s" % key)
    return sorted(proven), sorted(set(errors))


def check_companion(companion, max_report, visibility_map=None):
    """Is the PRIVATE companion repo's real-run output actually under version control?

    THIS IS NOT THE SAME QUESTION AS THE ONE ABOVE, and conflating them has already caused one
    wrong verdict in this fleet. The rule is "DATA never in a PUBLIC repo", not "DATA never in
    git": a private companion repo is exactly where a person's real output legitimately lives, with
    a remote, a history and a backup. So this check does not object to run output being tracked
    there. It objects to run output being NEITHER tracked NOR ignored -- sitting loose in the
    working tree, in a limbo where it is not backed up by anything and where it buries `git status`
    under so much noise that a genuinely new file cannot be seen. Measured on the operator's
    companion 2026-08-27: 35 loose run trees, 1640 files, 1.5 GB, against 40 tracked files. The
    signal-to-noise ratio of `git status` there was 0.

    Deliberately opt-in (`--companion`) and deliberately NOT part of the public repo's CI: there is
    no companion on a CI runner, and a check that cannot run must say so rather than pass. Absent
    companion exits 3, which is neither clean nor a violation.
    """
    try:
        destination = os.path.realpath(companion)
        context = _companion_git_context(destination)
        root, _physical, effective = context
        proven, visibility_errors = _companion_visibility(root, visibility_map, context)
        if visibility_errors:
            for error in visibility_errors:
                print("data_boundary --companion: VISIBILITY BLOCKED: %s" % error, file=sys.stderr)
            return 1
        print("data_boundary --companion: PRIVATE verified: %s" % ", ".join(proven))
        print("  verified DATA destination: %s" % destination)
        status = _run(["git", "status", "--porcelain", "--untracked-files=all", "-z"], root, env=effective)
        tracked_files = {p for p in _run(["git", "ls-files", "-z"], root, env=effective).split("\0") if p}
    except GitError as e:
        print("data_boundary --companion: SCAN FAILED, NOTHING was examined.\n  %s" % e,
              file=sys.stderr)
        return 2

    loose = sorted(f[3:] for f in status.split("\0") if f.startswith("?? "))
    loose_shaped = [f for f in loose if shape_of(f) and not f.endswith("/")]
    # `git status -z` reports an untracked DIRECTORY as one entry ending in `/`; expand it so the
    # count is files, not directories. A directory reported as "1 item" is how 1640 files hide.
    for d in [f for f in loose if f.endswith("/")]:
        for r, _dirs, fs in os.walk(os.path.join(root, d)):
            for x in fs:
                rel = os.path.relpath(os.path.join(r, x), root).replace("\\", "/")
                if shape_of(rel):
                    loose_shaped.append(rel)
    tracked_shaped = [f for f in tracked_files if shape_of(f)]

    print("data_boundary --companion: %s" % root)
    print("  tracked files wearing a run shape:  %d   (correct: this is the private repo)"
          % len(tracked_shaped))
    print("  LOOSE files wearing a run shape:    %d   (neither tracked nor ignored)"
          % len(loose_shaped))
    if not loose_shaped:
        return 0

    shown = sorted(loose_shaped)[:max_report]
    for f in shown:
        print("    %s" % f, file=sys.stderr)
    withheld = len(loose_shaped) - len(shown)
    # The bound and what it dropped are both printed. A listing that silently stops at N teaches
    # the reader that N is the whole answer.
    print("    ... %d more not listed (--max-report %d)" % (withheld, max_report), file=sys.stderr)
    print("\n%d file(s) of real-run output are loose in %s: not tracked, and not ignored either.\n"
          "Decide, do not drift. Both dispositions are legitimate in a PRIVATE repo:\n"
          "  TRACK   if the files are curated output you would want to diff and restore.\n"
          "  IGNORE  if they are per-run scratch: raw third-party captures, fetch logs, stderr\n"
          "          dumps, one-off scripts. Check first that the curated record is already\n"
          "          tracked, then add the pattern to that repo's .gitignore.\n"
          "Leaving them loose is the one option that is not a decision."
          % (len(loose_shaped), root), file=sys.stderr)
    return 1


def check_run_shape_probes(root, m, out, phase_blocking=False):
    """Has the shape list ever been held against THIS repo's real output?

    Check 4 objects only to what it RECOGNISES, so a shape list that recognises nothing produces
    byte for byte the output of a repo with nothing to find. That is not a hypothetical: measured
    across this fleet on 2026-08-29, the shared list matched 16 of 54 representative output names
    drawn from the 18 skills, 7 repos scored exactly zero, and two of the few hits were accidents
    where an 18 digit account id and a 9 digit handle each happened to contain 8 consecutive digits
    and so read as a date. Every one of those repos writes real output on every run.

    `_audited` cannot close this. It asks whether somebody typed a paragraph, and four of roughly
    ten such notes were wrong in their load bearing sentence. A sentence is not a measurement.

    `_run_shape_probes` is: a list of SCHEMATIC filenames naming what this skill's real runs produce.
    Every probe must match some RUN_SHAPE, so a probe that misses is a coverage gap reported by
    name. An EMPTY list is reported as NOT CALIBRATED, which is a third state next to clean and
    violation, because "this list was held against this repo and fits" and "nobody has ever looked"
    are different facts and printed the same green until now.

    PROBES ARE SCHEMATIC AND THAT RULE IS LOAD BEARING. A probe carrying a real ticker, a real
    mailbox handle, a real channel id or a real counterparty name is private data in a public repo
    even with no file behind it, and it would reintroduce the leak in miniature under the banner of
    fixing it. Build the list by running `--explain` over a real run's listing from OUTSIDE the
    repo, then rewrite every name into its schematic form before committing it.

    Gameable by construction: a repo can satisfy this by listing `metrics/x.jsonl` for a skill that
    writes nothing of the kind. Nothing mechanical closes that, which is why the list is reviewed
    the way a .pii-allow entry is reviewed, in the diff, by a person. What it does remove is the
    silent case, where nobody had to decide anything at all.

    `phase_blocking` stays False until a repo's list is filled. Both vendored hooks end in
    `[ "$rc" -eq 0 ] && exit 0` followed by exit 1, so flipping this on globally while 17 repos
    carry empty lists would be 17 simultaneously broken work trees whose only reachable fix is
    --no-verify. The flip condition is mechanical: list non-empty and every probe matching.
    """
    probes = m.get("_run_shape_probes")
    if probes is None or not [p for p in probes if str(p).strip()]:
        if phase_blocking:
            out.append(("NOT-CALIBRATED", MANIFEST,
                        "\"_run_shape_probes\" is empty, so nobody has ever held the run-shape list "
                        "against what this skill actually writes. Build it with "
                        "`data_boundary.py --explain <names from a real run>` and commit the "
                        "SCHEMATIC forms."))
        return "uncalibrated"
    missed = []
    for p in probes:
        rel = str(p).strip().replace(chr(92), "/")
        if not rel:
            continue
        why = shape_of(rel)
        if not why or why.startswith("(shape-exempt"):
            missed.append(rel)
    if missed:
        out.append(("PROBE-MISS", MANIFEST,
                    "declared probe(s) match no run shape, so this list has never been held "
                    "against this repo's output, or the shape list has drifted away from it: "
                    + ", ".join(missed[:6]) + ("" if len(missed) <= 6 else
                                               " (+%d more)" % (len(missed) - 6))))
        return "miss"
    return "calibrated"


def check_empty_data_is_audited(root, m, out):
    """An empty `data` list has to be a conclusion someone reached, not a default.

    THIS IS THE CHECK THAT MAKES `_audited` MEAN ANYTHING. The convention of recording an
    `_audited` (or `_armed`) note next to an empty data list has been followed for a long time:
    measured 2026-08-20, ten of the eleven manifests with an empty list carried one. And until
    that date NOTHING READ THEM. `grep -rn "_armed|_audited"` over the guard sources returned
    zero hits, so the entire evidence that "this skill genuinely produces no in-repo data" was a
    sentence no program had ever looked at. data_boundary is the primary control, and its own
    docstring says PROSE IS NOT A CONTROL; this was prose.

    An empty list is the single most consequential value in this file, because every per-file
    check below iterates it. Empty means "assert nothing", and it is also exactly what a fresh
    manifest looks like. Requiring a human-written reason is what separates the two.

    Deliberately NOT satisfied by any non-empty string of whitespace, and deliberately naming
    both keys: `_armed` is the older spelling and several manifests still use it.
    """
    if m.get("data"):
        return
    note = m.get("_audited") or m.get("_armed")
    if note is None or not str(note).strip():
        out.append(("UNAUDITED", MANIFEST,
                    "an empty \"data\" list asserts nothing, and nothing here says that was a "
                    "finding rather than a default. Add \"_audited\" naming where this skill's "
                    "real output actually goes (usually its private companion repo) and how that "
                    "was verified."))


def shape_of(rel):
    """Which RUN_SHAPE does this path wear, if any? Returns the reason string, or None.

    The matching itself is not new; it ran inline inside check 4 and the answer was appended to a
    findings list and then thrown away. Making it a function is what lets anything else ask the
    question, and the two callers that matter are --explain, which is how a human holds this list
    against a real run's filenames, and the probe check, which is how that holding is recorded.

    A shape-exempt name (`*.example`, `*.sample`, `*.tmpl`, `*.template`) returns a distinct string
    rather than None, because "this is a published schema, not a record" and "nothing here looks
    like output" are different answers and the caller may care which it got.
    """
    if SHAPE_EXEMPT.search(os.path.basename(rel)):
        return "(shape-exempt: a published schema, not a record)"
    for why, pat in RUN_SHAPES:
        if pat.search(rel):
            return why
    return None


def explain(paths):
    """Score arbitrary path names against RUN_SHAPES and print the result. Never touches the repo.

    THE SHAPE LIST IS THE ONE PART OF THIS FILE THAT CAN BE WRONG IN SILENCE. Checks 1, 2, 3 and 5
    read a manifest and object to what they find there, so a mistake in them shows up as a wrong
    verdict. Check 4 objects only to what it RECOGNISES, so a list that recognises nothing produces
    exactly the output of a repo with nothing to find. Measured across this fleet on 2026-08-29: the
    canonical list matched 16 of 54 representative output names, and 7 of 18 repos scored zero,
    while every one of those repos writes real output on every run.

    So this is the instrument that makes the gap visible. Feed it the file listing a real run
    produced (from OUTSIDE any public repo) and read the misses. It is argv-driven and cannot see
    the repository, so it can neither block nor leak on its own.
    """
    hits = 0
    for p in paths:
        rel = p.replace(chr(92), "/")
        while rel.startswith("./"):
            rel = rel[2:]
        why = shape_of(rel)
        if why and not why.startswith("(shape-exempt"):
            hits += 1
            print("HIT   %-58s %s" % (rel[:58], why))
        else:
            print("----  %-58s %s" % (rel[:58], why or "no shape matches this name"))
    print("data_boundary --explain: %d of %d name(s) wear a known run shape" % (hits, len(paths)))
    return hits


def check_no_undeclared_run_shapes(root, m, files, out):
    """The check that survives an EMPTY manifest -- see "WHY CHECK 4 EXISTS" at the top of this file.

    Checks 1..3 are declaration-driven, so a repo that declares nothing is checked for nothing. This
    one runs over tracked and physical names: any path shaped like real-run output must be
    ACCOUNTED FOR by name in the manifest, under `data`/`data_sealed` (check 1 then reports it),
    `fixture` (check 2 then proves it is generator-reproducible), or `tool` (a per-path allowlist
    entry, which shows up in the diff and has to be argued for -- the .pii-allow pattern).

    Default-deny is the point. Nothing here needs the manifest to be right; it needs the repo to be
    empty of run output, which is a fact about the working tree that no note can talk its way out of.
    """
    declared = (m.get("data", []) + m.get("data_sealed", [])
                + m.get("fixture", []) + m.get("tool", []))
    for rel in sorted(files):
        if _covered(rel, declared):
            continue
        why = shape_of(rel)
        if why and not why.startswith("(shape-exempt"):
            out.append(("RUN-SHAPE", rel, why))


def main(private_proof=None):
    ap = argparse.ArgumentParser(description="Enforce the TOOL / FIXTURE / DATA boundary.")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--explain", nargs="+", metavar="PATH",
                    help="score these path NAMES against the run-shape list and exit. Reads no "
                         "repository and needs no manifest. This is how you hold the list against "
                         "the filenames a real run produced, which is the only way to learn that "
                         "it recognises none of them.")
    ap.add_argument("--require-hit", action="store_true",
                    help="with --explain, exit 1 when no supplied name matched any shape")
    ap.add_argument("--companion", action="store_true",
                    help="also audit the PRIVATE companion repo for run output that is neither "
                         "tracked nor ignored (exit 3 if no companion resolves: NOTHING checked)")
    ap.add_argument("--companion-dir", metavar="PATH",
                    help="the companion to audit; attest data/ when present, otherwise this path")
    ap.add_argument("--visibility-map", metavar="PATH",
                    help="companion visibility receipt (default: ~/.pii-guard/visibility.json); "
                         "all effective remote destinations must have fresh PRIVATE evidence")
    ap.add_argument("--max-report", type=int, default=20,
                    help="cap the --companion listing (the cap and the count withheld are printed)")
    ap.add_argument("--calibration", action="store_true",
                    help="also say whether this repo's run-shape probe list has ever been filled. "
                         "Off by default: it never blocks, so printing it every run turns it into "
                         "background noise rather than information.")
    a = ap.parse_args()

    if a.explain:
        # Deliberately before any repository work: --explain must be usable from anywhere, including
        # against a listing taken from OUTSIDE every public repo, which is where real run output
        # lives. Without --require-hit it always exits 0, so it can never become a gate by accident.
        hits = explain(a.explain)
        return 1 if (a.require_hit and hits == 0) else 0

    if a.companion or a.companion_dir:
        # Deliberately opt-in and deliberately NOT in CI: there is no companion on a CI runner, and
        # a check that cannot run must say so rather than pass. Exit 3 when none resolves.
        try:
            comp = a.companion_dir or _resolve_companion(os.path.abspath(a.repo))
        except (RuntimeError, OSError, ImportError) as error:
            print("data_boundary --companion: RESOLVER BLOCKED: %s" % error, file=sys.stderr)
            return 2
        if a.companion_dir and os.path.isdir(os.path.join(comp, "data")):
            comp = os.path.join(comp, "data")
        if comp is None:
            print("data_boundary --companion: no private companion repo resolved, so\n"
                  "  NOTHING was examined. This is not a clean bill of health. Point\n"
                  "  $%s_CONFIG at it, or pass --companion-dir."
                  % os.path.basename(os.path.abspath(a.repo)).upper().replace("-", "_"),
                  file=sys.stderr)
            return 3
        return check_companion(comp, a.max_report, a.visibility_map)

    try:
        root = _repo_root(os.path.abspath(a.repo))
        files = tracked(root)
    except GitError as e:
        # Exit 2, distinct from 0 (clean) and 1 (violations), mirroring pii_guard. "clean" and
        # "never ran" must not be the same output on the primary control.
        print("data_boundary: SCAN FAILED, git could not be used, so NOTHING was examined.\n  %s"
              % e, file=sys.stderr)
        return 2

    if not files:
        # AN EMPTY FILE LIST IS NOT A CLEAN REPO (promoted from daily-hotspots 2026-08-29, negative
        # control: tools/test_data_boundary.py::test_zero_tracked_files_is_not_a_clean_bill_of_health).
        #
        # `git ls-files` can exit 0 and hand back nothing: a fresh work tree, an index git rebuilt
        # as empty, a `--repo` pointed one directory off. Every per-file check below then iterates
        # zero times and the summary printed "clean (... 0 tracked files ...)" with rc=0. A count
        # inside a success message was the ONLY thing separating that from a real pass, and this
        # file's own `_run` docstring is a paragraph about how that exact shape was the defect on
        # the primary control. Same verdict as an unusable git, because it is the same fact.
        print("data_boundary: 0 tracked files in %s, so NOTHING was examined. This is not a clean\n"
              "  bill of health, the scan had no input. Check that --repo names the work tree you\n"
              "  meant and that the index is populated (`git ls-files | head`)." % root,
              file=sys.stderr)
        return 2

    m = load_manifest(root)
    manifest_absent = m is None
    if manifest_absent:
        # A MISSING MANIFEST USED TO DISARM THE WHOLE GATE (promoted 2026-08-29, negative controls:
        # test_no_manifest_does_not_launder_a_tracked_run_artifact and
        # test_no_manifest_is_reported_as_not_armed_not_as_clean).
        #
        # The old body returned 0 right here, so the one-line route past the primary control was
        # `rm .dataclass.json`: the repo could then track an entire real archive and both hooks
        # would report success. Measured 2026-08-29 in a scratch repo: a tracked
        # `metrics/verdicts.jsonl` is 2 violations with the manifest present and rc=0 with it
        # deleted, the file still tracked either way. That the fail-open was KNOWN is written into
        # CI: .github/workflows/pii-guard.yml carries a `test -f .dataclass.json` step whose error
        # text says data_boundary "would exit 0 on every run and leave the primary control inert".
        # A workaround in one caller is not a property of the gate, and the hooks never had it.
        #
        # Check 4 is manifest-INDEPENDENT by construction: it runs off the tracked file list and
        # asks whether anything WEARS the shape of run output. So it still runs, against an empty
        # manifest, and a run artifact is still caught. Only the declaration-driven checks (1, 2,
        # 3, 5) are genuinely unanswerable without a manifest, and that is reported as NOT ARMED
        # with its own exit code rather than as a pass.
        m = {}

    out = []
    validate_declarations(m, out)
    if out:
        for kind, path, reason in out:
            print("%s: %s: %s" % (kind, path, reason), file=sys.stderr)
        return 1
    if private_proof is not None:
        if os.path.normcase(os.path.realpath(root)) != os.path.normcase(os.path.realpath(private_proof.root)):
            raise GitError("Private scope does not identify the scanned worktree")
        read_private_companion_git(private_proof, "check-ignore", "--no-index", "-q", "--", ".")
    absent = m if private_proof is None else {"data_sealed": m.get("data_sealed", [])}
    check_data_not_tracked(root, absent, files, out)
    try:
        check_data_absent_from_worktree(root, absent, out)
        all_paths = files | set(physical_paths(root))
    except (OSError, GitError) as e:
        print("data_boundary: SCAN FAILED while checking physical DATA paths: %s" % e, file=sys.stderr)
        return 2
    check_data_has_schema(root, m, out)
    check_fixtures_are_generated(root, m, out)
    check_no_undeclared_run_shapes(root, m, all_paths, out)
    calib = None
    if not manifest_absent:
        # Check 5 asks whether an EMPTY data list was a finding. With no manifest at all there is
        # no list to have been a finding, and reporting UNAUDITED against a file that does not
        # exist would tell the reader to edit a note when what is missing is the whole manifest.
        check_empty_data_is_audited(root, m, out)
        # Check 6, PHASE 1: a probe that misses is a violation now, an EMPTY probe list is reported
        # and does not block. See check_run_shape_probes for why the flip is per repo and later.
        calib = check_run_shape_probes(root, m, out, phase_blocking=False)

    if not out and manifest_absent:
        print("data_boundary: NOT ARMED. There is no %s in %s, so checks 1, 2, 3 and 5 asserted\n"
              "  NOTHING about this repo. Check 4 ran (it needs no manifest) and found no tracked or\n"
              "  physical file wearing the shape of real-run output, across %d names, that is the\n"
              "  only statement this run is entitled to make.\n"
              "  Declare the repo's classes in %s to arm the rest."
              % (MANIFEST, root, len(all_paths), MANIFEST), file=sys.stderr)
        return 3

    if calib == "uncalibrated" and a.calibration:
        # ASKED FOR, NOT ANNOUNCED. This line used to print on every run, on the argument that a
        # report saying only "clean, N files" cannot distinguish a repo with nothing to find from a
        # shape list that matches nothing. That argument is still true and the line is still here,
        # behind --calibration.
        #
        # What changed is the judgement about an unconditional notice that never blocks. It fires on
        # most repos, on every single invocation, and nothing about it can ever go red. A notice in
        # that position is read a handful of times and then becomes background, at which point it is
        # worse than absent: it occupies the place where a real warning would have been noticed. The
        # fleet has the same finding written down twice already, in the checks that were demoted to
        # advisory precisely because a permanent amber gets tuned out.
        #
        # The protection did not move. Check 4 still runs on every shape, a missing manifest is
        # still NOT ARMED, an empty file list is still a scan failure, and a probe list that exists
        # and does not match is still a VIOLATION. What is now silent is only the absence of a probe
        # list, which is a question about measurement rather than a finding about this repo.
        print("data_boundary: NOT CALIBRATED for this repo. The probe list in %s is empty,\n"
              "  so check 4 asserted only that no tracked or physical file matches a list nobody has\n"
              "  held against this skill's own output. Build it by running a real run's\n"
              "  filenames through --explain and committing the SCHEMATIC forms." % MANIFEST,
              file=sys.stderr)

    if not out:
        if private_proof is not None:
            read_private_companion_git(private_proof, "check-ignore", "--no-index", "-q", "--", ".")
            print("data_boundary: PRIVATE structural checks passed (%d declared DATA paths permitted, "
                  "%d FIXTUREs generator-reproducible, %d tracked or physical paths classified)"
                  % (len(m.get("data", [])), len(m.get("fixture", [])), len(all_paths)))
            return 0
        print("data_boundary: clean (%d DATA + %d sealed paths not tracked and absent from the worktree, %d FIXTUREs "
              "generator-reproducible, %d tracked or physical paths carry no undeclared real-run shape)"
              % (len(m.get("data", [])), len(m.get("data_sealed", [])),
                 len(m.get("fixture", [])), len(all_paths)))
        return 0

    print("data_boundary: %d violation(s) -- this repo is not an uninitialized tool\n" % len(out),
          file=sys.stderr)
    for kind, path, why in out:
        print("  %-16s %-52s %s" % (kind, path, why), file=sys.stderr)
    print("\nA public skill repo ships the TOOL and a SYNTHETIC fixture set. Everything a real run\n"
          "produced -- telemetry, real goldens, calibration, verdicts, config -- belongs in the\n"
          "private companion repo, and the loader resolves it from there.\n"
          "\nRUN-SHAPE means: this file or link looks like output, and no class claims it. Move it out\n"
          "(the usual answer), or -- if it really is hand-written TOOL material that happens to wear\n"
          "the shape -- add the exact path to \"tool\" in %s with a reason." % MANIFEST,
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
