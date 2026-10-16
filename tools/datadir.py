#!/usr/bin/env python3
"""datadir -- where a skill's REAL-RUN OUTPUT goes. Never the repo.

These skills already had a private-companion-config boundary, and it worked. But it only ever
covered INPUTS: the credentials, the mailboxes, the account slugs. Nothing covered OUTPUTS -- what
the skill LEARNED from a real run. So a forward-tracking tool appended the operator's actual research
verdicts (one row per decision, hundreds of them) to a git-tracked `metrics/*.jsonl`, and another
skill's ledger recorded what was bought and where it shipped -- straight into public repos, on every
run, by design.

No content scanner catches that. There is no email in it, no phone, no ZIP. It is just the
operator's life, correctly formatted. The fix is not a better sieve, it is a pipe that does not
point at the public repo in the first place.

  resolve_data_dir("small-cap-deepdive")  ->  the private directory, or None

Discovery order (first existing wins):
  1. $<SKILL>_DATA_DIR                       explicit override / hot-swap
  2. $<SKILL>_CONFIG                         the PRIVATE COMPANION REPO, wherever it is pinned:
                                             <config>/data/ when that exists, else <config> itself
  3. <sibling>/data/, then <sibling>         the convention: the companion repo beside this one,
                                             named <skill>-config, proven by its remote or marker
  4. None                                    -> the tool is UNINITIALIZED, which is exactly what a
                                                freshly cloned public skill SHOULD be

There is no location after the sibling convention: an uninitialized machine answers None, and
writers raise DataDirNotInitialized with what to set up.

WHY STEP 2 EXISTS (added 2026-07-31)
------------------------------------
Every skill in this fleet already resolves its private companion repo from `$<SKILL>_CONFIG`, and
several of those repos have been pinned somewhere other than the dotfile path (`$MARKET_INTEL_CONFIG`
and `$DAILY_HOTSPOTS_CONFIG` both point into ~/CodesClaude). This resolver did not know that, so it
looked only at the dotfile path, found nothing, and answered None -- "uninitialized" -- for skills
that were writing a real ledger every day. An out-of-band control then asked THIS function where the
data was, got None, and reported the skill as nothing-to-check. A checker that is told nothing
reports a clean sheet, which is the failure mode the whole data boundary exists to avoid. The
resolver now follows the same pointer the skill itself follows.

PRIVATE COMPANION REPO IS THE DESTINATION, NOT AN ACCIDENT
----------------------------------------------------------
Real-run output LIVES IN the private companion repo, versioned and backed up like everything else
there. The rule was never "data must not be in git" -- it is "data must never be in a PUBLIC repo,
and a public repo never has an in-repo fallback". Those are different predicates and conflating them
condemns the correct shape: a private repo is exactly where a person's real data legitimately lives.

WHY THIS FILE DOES NOT CHECK VISIBILITY ITSELF
----------------------------------------------
The tempting next step is to have this function refuse a data dir that sits in a PUBLIC repo. It
cannot do that honestly. This file is loaded by every consumer through fleet_guards.runtime, is
stdlib-only by contract, and must work on a fresh machine: no ~/.pii-guard/visibility.json,
no `gh`, possibly no network. Fail-closed there bricks every fresh clone on a question that has no
local answer; fail-open makes the assertion decorative precisely where it matters. So visibility is
enforced at commit time by the consumer's .githooks (publication_guard), not here.

What this file CAN assert with no map, no network and no git binary is strictly weaker and always
true: a skill's data dir is never inside the skill's OWN repo. Public or private, the tool repo and
the companion repo are two different repos, and a data dir that resolved into this one is either an
in-repo fallback or a misconfigured pointer -- the exact shape that put a real SEC contact email in
a public repo under the label "legacy fallback". That one is checked here, and it raises.

`data_path()` raises a DataDirNotInitialized with instructions rather than silently falling back to a
path inside the repo. A silent in-repo fallback is how this happened: `reference/config.json` was the
documented "legacy fallback", and the operator's real SEC contact email ended up committed in it.
A fallback into the repo is not a convenience, it is the leak.

Consumers reach it through the installed package: fleet_guards.runtime.companion_resolver(
source_root=<absolute repo root>). Every entry point takes source_root explicitly; nothing is
inferred from where this file sits. Stdlib only.
"""
import os
import re
from pathlib import Path


class DataDirNotInitialized(RuntimeError):
    pass


class DataDirInsideOwnRepo(RuntimeError):
    """The resolved data dir is inside the skill repo that ships this file. Always a defect."""


class DataDirResolutionError(RuntimeError):
    """A filesystem error prevented establishing the tool/output boundary."""


def _env_var(skill):
    return skill.upper().replace("-", "_") + "_DATA_DIR"


def _config_env_var(skill):
    return skill.upper().replace("-", "_") + "_CONFIG"


def _source_root(source_root):
    """The consumer repository whose output is being placed. Callers always name it."""
    path = Path(source_root)
    if not path.is_absolute():
        raise ValueError("source_root must be absolute")
    return str(path.resolve())


def assert_outside_own_repo(p, skill, *, source_root):
    """Raise DataDirInsideOwnRepo when p is inside the consumer's own source repository."""
    try:
        root = _source_root(source_root)
        target, repo = os.path.realpath(str(p)), os.path.realpath(root)
    except OSError as exc:
        raise DataDirResolutionError(
            "%s data directory resolution failed; output is not authorized" % skill) from exc
    # normcase for the COMPARISON only; the message keeps the real casing so it is greppable.
    t, r = os.path.normcase(target), os.path.normcase(repo)
    # The separator is load-bearing: `<root>-config` must NOT count as inside `<root>`, and the
    # companion repo is named exactly that way in every skill in this fleet.
    if t == r or t.startswith(r + os.sep):
        raise DataDirInsideOwnRepo(
            "%s resolved its data dir to %s, which is INSIDE its own repo %s.\n"
            "Real-run output belongs in the PRIVATE COMPANION repo, never in the tool repo.\n"
            "Repoint it:\n"
            "    set %s to the companion repo (its data/ subdir is used when present)\n"
            "    or set %s to an explicit private directory"
            % (skill, target, repo, _config_env_var(skill), _env_var(skill)))



def _convention_root(skill, *, source_root):
    """The fleet convention: a skill's companion repo is its SIBLING, named `<skill>-config`.

    Every companion repo in this fleet already follows this. Nothing looked for it, and that
    was the whole defect. Discovery depended entirely on a per-skill environment variable, so
    the answer to "where is this skill's data" depended on whether someone had remembered to
    export a variable on this particular machine.

    Measured 2026-08-20 across eight skills that have real data:
      resolved to the companion repo   3   (their env var happened to be set)
      resolved to a $HOME dotfile      3   (one of them WHILE its companion repo sat beside it)
      answered "uninitialized"         3   (one of those had 153 tracked files in its companion)
    The last group is the bad one: `datadir.py` returned None, callers correctly reported the
    skill as having no data, and an out-of-band coverage check counted them as SKIP. Three real
    private repos were invisible to the boundary tooling, and the report was green.

    Derived from the consumer's own source root rather than a hardcoded path, deliberately. The
    absolute location differs per machine, and a home-anchored literal in a public repo is
    exactly what pii_guard blocks.
    """
    return Path(_source_root(source_root)).parent / ("%s-config" % skill)


_MARKER = ".companion"


class CompanionUnproven(RuntimeError):
    """A directory sits at a candidate path but carries no proof of being the companion."""


def _remote_url(path):
    """The origin URL from a worktree's shared Git configuration, or None.

    Read as text rather than shelled out to git. Follow a gitdir file for linked worktrees, then commondir for the shared configuration of a linked worktree.
    """
    g = path / ".git"
    cfg = None
    if g.is_dir():
        cfg = g / "config"
    elif g.is_file():
        try:
            line = g.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        if line.startswith("gitdir:"):
            gitdir = (path / line.split(":", 1)[1].strip()).resolve()
            common = gitdir / "commondir"
            if common.is_file():
                try:
                    common_path = common.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    return None
                if not common_path:
                    return None
                gitdir = (gitdir / common_path).resolve()
            cfg = gitdir / "config"
    if cfg is None or not cfg.is_file():
        return None
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # Deliberately limited Git syntax: ordinary sections and literal URL values. Includes,
    # worktree configuration, escaped/continued URLs, duplicates and malformed sections
    # cannot establish identity without resolving configuration outside this shared file.
    in_origin = False
    in_extensions = False
    urls = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = re.fullmatch(r'\[\s*([A-Za-z][A-Za-z0-9.-]*)(?:\s+"([^"\\]*)")?\s*\]\s*(?:[#;].*)?', line)
            if section is None or section[1].lower() in ("include", "includeif"):
                return None
            in_origin = section[1].lower() == "remote" and section[2] == "origin"
            in_extensions = section[1].lower() == "extensions" and section[2] is None
            continue
        setting = re.fullmatch(r'([A-Za-z][A-Za-z0-9-]*)(?:\s*=\s*(.*))?', line)
        if setting is None:
            return None
        if in_extensions and setting[1].lower() == "worktreeconfig":
            return None
        if not in_origin or setting[1].lower() != "url":
            continue
        value = setting[2]
        if value is None or "\\" in value:
            return None
        if value.startswith('"'):
            quoted = re.fullmatch(r'"([^"\\]*)"\s*(?:[#;].*)?', value)
            if quoted is None:
                return None
            value = quoted[1]
        elif '"' in value:
            return None
        else:
            value = re.split(r'[#;]', value, maxsplit=1)[0].strip()
        if not value:
            return None
        urls.append(value)
    return urls[0] if len(urls) == 1 else None


def _proves_companion(path, skill):
    """Does this directory carry PROOF that it is `skill`'s companion?

    2026-09-02. Before this, the only test was is_dir(), so ANY directory sitting at a candidate
    path won. That is not theoretical. A directory was created at the convention path during
    unrelated work, the env pointer was out of scope, and the resolver returned the empty decoy as
    both the companion root and the data dir, without raising. Writes would have landed in a
    directory nothing backs up, while the real companion kept being backed up as usual: two stores
    for one skill.

    The failure DIRECTION is what makes it worth code. "Uninitialised" is a safe answer, because
    the caller says so and stops. A confident wrong path is not, because nothing downstream can
    tell it from a right one.

    Two proofs, either sufficient:
      * the git remote. A companion's origin ends in <skill>-config; a decoy has no remote at all.
        This costs nothing extra: the collision itself supplies the distinguishing fact.
      * an explicit .companion marker naming the skill, for a companion that is not a git repo
        yet. Explicit precisely so that an accident cannot produce one.
    """
    marker = path / _MARKER
    if marker.is_file():
        try:
            for line in marker.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    return line.strip() == skill
        except OSError:
            return False
        return False
    url = _remote_url(path)
    if not url:
        return False
    base = url.rstrip("/").rsplit("/", 1)[-1]
    if base.endswith(".git"):
        base = base[:-4]
    if ":" in base:
        base = base.rsplit(":", 1)[-1]
    return base == ("%s-config" % skill)


def _unproven_error(skill, dirs):
    return CompanionUnproven(
        "%s: found %d director%s at the companion path(s) below, and NONE of them carries proof\n"
        "of being %s's companion. Refusing to return one, because guessing here is how a skill\n"
        "ends up writing real-run output to a directory that nothing backs up or pushes.\n"
        "%s\n"
        "Fix it in whichever way is true:\n"
        "    * if one of them IS the companion, give it its remote, or write its name into a\n"
        "      %s file inside it (one line, exactly: %s)\n"
        "    * if none of them is, delete the stray directory\n"
        "    * or point %s at the real companion explicitly"
        % (skill, len(dirs), "y" if len(dirs) == 1 else "ies", skill,
           "\n".join("      %s" % d for d in dirs), _MARKER, skill, _config_env_var(skill)))


def _candidates(skill, *, source_root):
    """Discovery order, as (Path, explicit) pairs. See the module docstring.

    `explicit` marks a path that carries the operator's INTENT on its face: an environment
    variable they set. That is taken on trust: someone who types a path has already supplied the intent that the proof below stands in
    for, and demanding a marker there would break every deliberate override for no safety gain.
    The CONVENTION path is different in kind and that is why it alone is checked. This module
    DERIVES it -- the sibling of whatever worktree the file happens to sit in -- so an
    unrelated directory can come to occupy it, which is exactly what happened on 2026-09-02.
    A guess has to be proven; a path someone typed does not.
    """
    out = []
    d = os.environ.get(_env_var(skill))
    if d:
        out.append((Path(os.path.expanduser(d)), True))
    c = os.environ.get(_config_env_var(skill))
    if c:
        root = Path(os.path.expanduser(c))
        # A companion repo that keeps its output under data/ gets data/; one that files it directly
        # at the repo root (daily-hotspots' archive/ is the fleet's other shape) gets the root.
        out.append((root / "data", True))
        out.append((root, True))
    # The convention comes after the env vars so an explicit override still wins. Nothing comes
    # after it: an uninitialized machine answers None.
    root = _convention_root(skill, source_root=source_root)
    out.append((root / "data", False))
    out.append((root, False))
    return out


def resolve_companion_root(skill, *, source_root):
    """The private companion REPO root for `skill`, or None. Never a path inside the skill's repo.

    resolve_data_dir answers "where does real-run output go", which is usually `<companion>/data`.
    This answers the adjacent question, "where is the companion itself", which is what a caller
    looking for config.json, a registry or a runbook needs.

    IT EXISTS SO THERE IS ONE DISCOVERY ORDER, NOT TWO. One skill in this fleet carried a second
    resolver of its own, for its config file rather than its data, and that one probed only
    environment variables and home dotfiles without knowing the sibling convention. The consequence,
    measured 2026-08-30: this function found the companion while the other returned nothing, so the
    skill fell through to a shipped example default that was repo relative and wrote 4029 real-run
    files into its own public repository. Two answers to one question, and the wrong one was the one
    that decided where files landed.

    So a caller that needs the companion asks here rather than re-deriving the order. The order is
    the same as resolve_data_dir's, minus the data/ suffix probes, and the same rejection applies: a
    companion that resolves inside the skill's own repo raises rather than being returned.

    An unproven directory is SKIPPED rather than raised on immediately, so a real companion later
    in the order still wins over a stray directory earlier in it. Only when the whole order is
    exhausted with nothing proven does the stray become an error -- at which point staying silent
    would mean answering "uninitialised" while a directory the operator can see sits right there.
    """
    unproven = []
    for p, explicit in _candidates(skill, source_root=source_root):
        if not p.is_dir():
            continue
        # _candidates yields <root>/data before <root>. A caller asking for the companion ROOT gets
        # the parent in that case, so both companion shapes in this fleet answer the same way.
        root = p.parent if p.name == "data" and p.parent.is_dir() else p
        if not explicit and not _proves_companion(root, skill):
            if root not in unproven:
                unproven.append(root)
            continue
        assert_outside_own_repo(root, skill, source_root=source_root)
        return root
    if unproven:
        raise _unproven_error(skill, unproven)
    return None


def resolve_data_dir(skill, *, source_root):
    """Return the private data dir for `skill`, or None if the tool is uninitialized.

    Raises DataDirInsideOwnRepo if the resolved directory sits inside this skill's own repo, and
    CompanionUnproven if the only thing found was a directory that cannot show it is the companion.
    source_root binds sibling discovery and source exclusion to the consumer repository.
    """
    unproven = []
    for p, explicit in _candidates(skill, source_root=source_root):
        if not p.is_dir():
            continue
        if not explicit:
            # The proof lives on the companion ROOT, not on its data/ subdir, so a <root>/data
            # candidate is judged by its parent.
            root = p.parent if p.name == "data" and p.parent.is_dir() else p
            if not _proves_companion(root, skill):
                if root not in unproven:
                    unproven.append(root)
                continue
        assert_outside_own_repo(p, skill, source_root=source_root)
        return p
    if unproven:
        raise _unproven_error(skill, unproven)
    return None


def data_path(skill, relpath, *, source_root):
    """Resolve <private data dir>/<relpath>. Never returns a path inside the repo."""
    base = resolve_data_dir(skill, source_root=source_root)
    if base is None:
        raise DataDirNotInitialized(
            "%s has no private data directory, so it has nowhere to put real-run output.\n"
            "This is the correct state for a freshly cloned public skill: it ships as an\n"
            "uninitialized tool. Initialize its PRIVATE COMPANION repo first:\n"
            "    create a PRIVATE repository with an origin and clone it beside this one as %s-config\n"
            "    or set %s to the companion repo (data/ under it is used when present)\n"
            "    or set %s to an explicit private directory\n"
            "A directory in the home folder is not a companion: nothing versions or backs it up.\n"
            "Real-run output NEVER goes back into THIS repo -- this repo carries only the schema\n"
            "(<file>.example) and a synthetic fixture set."
            % (skill, skill, _config_env_var(skill), _env_var(skill)))
    p = base / relpath
    assert_outside_own_repo(p, skill, source_root=source_root)
    try:
        p.resolve().relative_to(base.resolve())
    except ValueError:
        raise ValueError("relpath must stay inside the private data directory") from None
    return p
