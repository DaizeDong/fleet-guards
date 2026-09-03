#!/usr/bin/env python3
"""Tests for tools/datadir.py -- the resolver that decides WHERE real-run output goes.

WHY THESE EXIST
---------------
This file is the pipe. If it points at the wrong place, no scanner downstream can help: a verdict
ledger with an entry price in it has no email, no phone and no ZIP to smell. The 2026-07 leak was
not a scanning failure, it was a resolver that had a fallback into the repo.

Two properties are pinned here, and they are the two that have actually broken:

  1. The resolver FOLLOWS the same pointer the skill follows. It knew only the dotfile path for
     months while several companion repos were pinned elsewhere with $<SKILL>_CONFIG, so it
     answered None -- "uninitialized" -- for skills that were writing a real ledger every day. An
     out-of-band control then asked it where the data was, was told nothing, and reported a clean
     sheet. A checker that is handed nothing prints the same green as a checker that found nothing
     wrong.

  2. It REFUSES a data dir inside its own repo. That is the in-repo-fallback shape, the one that
     put a real contact address in a public repo under the label "legacy fallback". The check is
     deliberately narrow so it needs no visibility map, no gh and no network: this file ships in
     public repos and must work on a stranger's fresh clone. Whether the CONTAINING repo is public
     is a question with no local answer, so it is asked out of band, by the fleet checker that has
     the map.

Stdlib + pytest only. No network, no gh, no real repos.
"""
from __future__ import annotations

import importlib.util
import os
import shutil

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
DATADIR = os.path.join(HERE, "datadir.py")


def load(path, name="datadir_under_test"):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dd = load(DATADIR)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in ("DEMO_DATA_DIR", "DEMO_CONFIG", "DEMO_CONFIG_DIR"):
        monkeypatch.delenv(v, raising=False)
    # HOME is read for the dotfile fallbacks; point it somewhere empty so a real machine's
    # ~/.demo-config cannot make a test pass or fail by accident.
    yield


def _isolate_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


# --- discovery order -----------------------------------------------------------------------------
def test_uninitialized_returns_none(monkeypatch, tmp_path):
    """A freshly cloned public skill knows nothing about anybody. That is the SHIPPING state."""
    _isolate_home(monkeypatch, tmp_path)
    assert dd.resolve_data_dir("demo") is None


def test_explicit_data_dir_wins(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    store = tmp_path / "explicit"
    store.mkdir()
    monkeypatch.setenv("DEMO_DATA_DIR", str(store))
    assert str(dd.resolve_data_dir("demo")) == str(store)


def test_config_env_resolves_to_companion_data_subdir(monkeypatch, tmp_path):
    """The fleet's primary shape: the companion repo keeps run output under data/."""
    _isolate_home(monkeypatch, tmp_path)
    cfg = tmp_path / "demo-config"
    (cfg / "data").mkdir(parents=True)
    monkeypatch.setenv("DEMO_CONFIG", str(cfg))
    assert str(dd.resolve_data_dir("demo")) == str(cfg / "data")


def test_config_env_falls_back_to_companion_root(monkeypatch, tmp_path):
    """The fleet's other shape: output filed directly under the companion repo (archive/, ...).

    Returning the companion ROOT is the honest answer to "where does this skill's real-run output
    live", and it is what makes the out-of-band boundary check able to see the skill at all. The
    predecessor returned None here, which reads as "nothing to check".
    """
    _isolate_home(monkeypatch, tmp_path)
    cfg = tmp_path / "demo-config"
    (cfg / "archive").mkdir(parents=True)
    monkeypatch.setenv("DEMO_CONFIG", str(cfg))
    assert str(dd.resolve_data_dir("demo")) == str(cfg)


def test_config_dir_alias_is_honored(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    cfg = tmp_path / "demo-config"
    (cfg / "data").mkdir(parents=True)
    monkeypatch.setenv("DEMO_CONFIG_DIR", str(cfg))
    assert str(dd.resolve_data_dir("demo")) == str(cfg / "data")


def test_dotfile_companion_still_works(monkeypatch, tmp_path):
    home = _isolate_home(monkeypatch, tmp_path)
    (home / ".demo-config" / "data").mkdir(parents=True)
    assert str(dd.resolve_data_dir("demo")) == str(home / ".demo-config" / "data")


def test_standalone_dotfile_is_the_last_resort(monkeypatch, tmp_path):
    home = _isolate_home(monkeypatch, tmp_path)
    (home / ".demo-data").mkdir(parents=True)
    assert str(dd.resolve_data_dir("demo")) == str(home / ".demo-data")


def test_data_path_raises_with_instructions_not_a_repo_fallback(monkeypatch, tmp_path):
    """The whole point: no silent in-repo fallback, ever. Raise and say what to do."""
    _isolate_home(monkeypatch, tmp_path)
    with pytest.raises(dd.DataDirNotInitialized) as e:
        dd.data_path("demo", "metrics/live-runs.jsonl")
    msg = str(e.value)
    assert "DEMO_CONFIG" in msg and "DEMO_DATA_DIR" in msg
    assert "NEVER goes back into THIS repo" in msg


# --- the narrow refusal --------------------------------------------------------------------------
def _skill_repo(tmp_path, name="fakeskill"):
    """A copy of datadir.py deployed at <repo>/tools/datadir.py inside a fake worktree."""
    repo = tmp_path / name
    (repo / "tools").mkdir(parents=True)
    (repo / ".git").mkdir()
    (repo / "data").mkdir()
    shutil.copy2(DATADIR, repo / "tools" / "datadir.py")
    return repo, load(str(repo / "tools" / "datadir.py"), "dd_" + name)


def test_data_dir_inside_own_repo_is_refused(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    repo, mod = _skill_repo(tmp_path)
    monkeypatch.setenv("FAKESKILL_DATA_DIR", str(repo / "data"))
    with pytest.raises(mod.DataDirInsideOwnRepo):
        mod.resolve_data_dir("fakeskill")


def test_repo_root_itself_is_refused(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    repo, mod = _skill_repo(tmp_path)
    monkeypatch.setenv("FAKESKILL_DATA_DIR", str(repo))
    with pytest.raises(mod.DataDirInsideOwnRepo):
        mod.resolve_data_dir("fakeskill")


def test_sibling_companion_repo_is_not_mistaken_for_inside(monkeypatch, tmp_path):
    """`<repo>-config` must NOT count as inside `<repo>`.

    Every companion repo in this fleet is named exactly that way, so a prefix comparison without the
    separator would reject the one shape the doctrine prescribes. This is the regression test for
    the separator, not a style preference.
    """
    _isolate_home(monkeypatch, tmp_path)
    repo, mod = _skill_repo(tmp_path)
    comp = tmp_path / "fakeskill-config"
    (comp / "data").mkdir(parents=True)
    monkeypatch.setenv("FAKESKILL_CONFIG", str(comp))
    assert str(mod.resolve_data_dir("fakeskill")) == str(comp / "data")


def test_refusal_also_applies_when_creating(monkeypatch, tmp_path):
    """create=True is the WRITE path. A writer that shrugs has only bad options."""
    _isolate_home(monkeypatch, tmp_path)
    repo, mod = _skill_repo(tmp_path)
    monkeypatch.setenv("FAKESKILL_DATA_DIR", str(repo / "not-yet"))
    with pytest.raises(mod.DataDirInsideOwnRepo):
        mod.resolve_data_dir("fakeskill", create=True)
    assert not (repo / "not-yet").exists(), "refused, and must not have created it anyway"


def test_no_worktree_means_no_refusal(monkeypatch, tmp_path):
    """Deployed outside a worktree there is nothing to be inside of; do not invent a failure."""
    _isolate_home(monkeypatch, tmp_path)
    loose = tmp_path / "loose" / "tools"
    loose.mkdir(parents=True)
    shutil.copy2(DATADIR, loose / "datadir.py")
    mod = load(str(loose / "datadir.py"), "dd_loose")
    store = tmp_path / "loose" / "data"
    store.mkdir()
    monkeypatch.setenv("LOOSE_DATA_DIR", str(store))
    assert str(mod.resolve_data_dir("loose")) == str(store)


# --------------------------------------------------------------------- submodule boundary (2026-09-01)
def test_own_repo_root_walks_past_a_submodule_to_the_superproject(tmp_path, monkeypatch):
    """The kit is consumed as a submodule at <repo>/guards, and a submodule's .git is a FILE.

    A walk that stops at the first .git of any kind stops at <repo>/guards. Everything downstream
    then answers about the KIT instead of the repo it is protecting: the sibling convention looks
    beside guards/, which is inside the public repo, and _reject_if_inside_own_repo compares
    against guards/ so it does not fire on a path inside that public repo.

    This is the regression for that. It fails against the pre-2026-09-01 walk, which is the only
    reason it is worth keeping: measured by reverting the isdir/isfile split and watching it go red.
    """
    superproject = tmp_path / "consumer"
    (superproject / ".git").mkdir(parents=True)          # a real worktree: .git is a DIRECTORY
    kit = superproject / "guards" / "tools"
    kit.mkdir(parents=True)
    (superproject / "guards" / ".git").write_text("gitdir: ../.git/modules/guards\n", encoding="utf-8")

    module_file = kit / "datadir.py"
    module_file.write_text("", encoding="utf-8")
    monkeypatch.setattr(dd, "__file__", str(module_file))

    assert dd._own_repo_root() == str(superproject), (
        "the walk stopped inside the submodule, so every companion answer is now about the guard "
        "kit rather than the repo whose data must stay out of it")


def test_a_path_inside_the_superproject_is_still_rejected_when_running_from_a_submodule(tmp_path, monkeypatch):
    """The consequence the walk fix exists to prevent, asserted at the rejection itself.

    Own-repo rejection is the last thing standing between a resolver and a public repo. Getting the
    root wrong does not disable it loudly; it just makes it compare against the wrong tree and pass.
    """
    superproject = tmp_path / "consumer"
    (superproject / ".git").mkdir(parents=True)
    kit = superproject / "guards" / "tools"
    kit.mkdir(parents=True)
    (superproject / "guards" / ".git").write_text("gitdir: ../.git/modules/guards\n", encoding="utf-8")
    monkeypatch.setattr(dd, "__file__", str(kit / "datadir.py"))

    inside = superproject / "myskill-config"
    inside.mkdir()
    with pytest.raises(Exception):
        dd._reject_if_inside_own_repo(inside, "myskill")


def test_assert_outside_own_repo_is_reachable_by_its_public_name(tmp_path, monkeypatch):
    """The public name exists and rejects, not merely exists.

    Deleted twice by refactors tidying away what looked like a duplicate of the private helper.
    Three writers in daily-hotspots call it before every write, so its absence is 100 failing
    tests in a skill that runs every day, reported as "module has no attribute" -- a message that
    names the symbol and not the consequence.

    An existence check would not have caught the second loss either, because what matters is that
    a path inside the repo still raises. So this asserts the behaviour through the public name.
    """
    assert callable(getattr(dd, "assert_outside_own_repo", None)), (
        "the public name is gone again; three writers reach for it before every write")
    repo = tmp_path / "toolrepo"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.setattr(dd, "__file__", str(repo / "tools" / "datadir.py"))
    inside = repo / "data"
    inside.mkdir()
    with pytest.raises(dd.DataDirInsideOwnRepo):
        dd.assert_outside_own_repo(inside, "toolrepo")


# --- a CONVENTION-path candidate must prove it is the companion ----------------------------------
# 2026-09-02. The resolver accepted any directory that merely EXISTED at a candidate path. That is
# not theoretical: a directory was created at the convention path during unrelated work, the env
# pointer was not in scope, and the resolver returned the empty decoy as both the companion root
# and the data dir with no exception. Writes would have landed there while the real companion kept
# being backed up as usual -- two stores for one skill.
#
# The failure DIRECTION is what makes it serious. "Uninitialised" is a safe answer: the caller says
# so and stops. A confident wrong path is not, because nothing downstream can tell it from a right
# one.
#
# The check is deliberately narrow. Only the CONVENTION path is proven, because only it is DERIVED
# -- the sibling of whatever worktree this file sits in, a location unrelated work can come to
# occupy. A `~/.<skill>-config` dotfile is somebody's deliberate mkdir and is treated as intent;
# companions of that shape are not always git repos, so demanding proof there would break them
# to fix a hole they are not in.

def _fake_sibling_layout(monkeypatch, tmp_path):
    """Put the module in a worktree so `_convention_roots` resolves to tmp_path/<skill>-config."""
    repo = tmp_path / "myskill"
    (repo / ".git").mkdir(parents=True)
    kit = repo / "guards" / "tools"
    kit.mkdir(parents=True)
    (repo / "guards" / ".git").write_text("gitdir: ../.git/modules/guards\n", encoding="utf-8")
    monkeypatch.setattr(dd, "__file__", str(kit / "datadir.py"))
    return tmp_path / "demo-config"


def test_bare_directory_at_convention_path_is_refused(monkeypatch, tmp_path):
    """A directory with no proof of being the companion must RAISE, not be returned."""
    _isolate_home(monkeypatch, tmp_path)
    decoy = _fake_sibling_layout(monkeypatch, tmp_path)
    decoy.mkdir()
    with pytest.raises(dd.CompanionUnproven) as ei:
        dd.resolve_data_dir("demo")
    msg = str(ei.value)
    # The message has to tell the operator what to do and WHICH directory, not merely that
    # something was wrong. A refusal nobody can act on gets worked around, not fixed.
    assert "demo" in msg and str(decoy) in msg


def test_bare_directory_also_refused_for_companion_root(monkeypatch, tmp_path):
    """Both entry points, because callers use both and a hole in either is the whole hole."""
    _isolate_home(monkeypatch, tmp_path)
    decoy = _fake_sibling_layout(monkeypatch, tmp_path)
    decoy.mkdir()
    with pytest.raises(dd.CompanionUnproven):
        dd.resolve_companion_root("demo")


def test_git_remote_proves_identity(monkeypatch, tmp_path):
    """A git worktree whose origin ends in <skill>-config IS the companion. The collision itself
    supplies the distinguishing fact, so this proof costs nothing to obtain."""
    _isolate_home(monkeypatch, tmp_path)
    comp = _fake_sibling_layout(monkeypatch, tmp_path)
    (comp / ".git").mkdir(parents=True)
    (comp / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = git@github.com:Someone/demo-config.git\n', encoding="utf-8")
    assert str(dd.resolve_data_dir("demo")) == str(comp)


def test_marker_file_proves_identity(monkeypatch, tmp_path):
    """Not every companion is a git repo. An explicit marker is the other proof, and it is explicit
    precisely so that an accident cannot produce one."""
    _isolate_home(monkeypatch, tmp_path)
    comp = _fake_sibling_layout(monkeypatch, tmp_path)
    comp.mkdir()
    (comp / ".companion").write_text("demo\n", encoding="utf-8")
    assert str(dd.resolve_data_dir("demo")) == str(comp)


def test_marker_naming_another_skill_is_not_proof(monkeypatch, tmp_path):
    """A marker naming somebody else's skill is somebody else's companion."""
    _isolate_home(monkeypatch, tmp_path)
    comp = _fake_sibling_layout(monkeypatch, tmp_path)
    comp.mkdir()
    (comp / ".companion").write_text("something-else\n", encoding="utf-8")
    with pytest.raises(dd.CompanionUnproven):
        dd.resolve_data_dir("demo")


def test_a_proven_companion_later_in_the_order_beats_a_stray_earlier(monkeypatch, tmp_path):
    """The stray is SKIPPED, not fatal, so a working setup keeps working.

    Raising on the first unproven directory would have been the simpler rule and the wrong one: a
    stray at the convention path would then break a skill whose real companion is its dotfile, and
    a gate that breaks working setups gets disabled rather than satisfied.
    """
    home = _isolate_home(monkeypatch, tmp_path)
    stray = _fake_sibling_layout(monkeypatch, tmp_path)
    stray.mkdir()
    real = home / ".demo-config"
    real.mkdir()
    assert str(dd.resolve_data_dir("demo")) == str(real)


def test_dotfile_needs_no_proof(monkeypatch, tmp_path):
    """A companion of this shape need not be a git repo, so demanding proof here would break it
    to close a hole it is not in."""
    home = _isolate_home(monkeypatch, tmp_path)
    _fake_sibling_layout(monkeypatch, tmp_path)   # convention path exists as a concept, not on disk
    d = home / ".demo-config"
    d.mkdir()
    assert str(dd.resolve_data_dir("demo")) == str(d)


def test_explicit_env_override_needs_no_proof(monkeypatch, tmp_path):
    """Someone who types a path has already supplied the intent the proof stands in for."""
    _isolate_home(monkeypatch, tmp_path)
    store = tmp_path / "explicit"
    store.mkdir()
    monkeypatch.setenv("DEMO_DATA_DIR", str(store))
    assert str(dd.resolve_data_dir("demo")) == str(store)
