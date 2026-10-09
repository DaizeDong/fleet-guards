"""Synchronization must fail visibly and only move the selected submodule."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import urllib.request

import pytest

from make_fixtures import _no_window
from make_fixtures import (fleet_unknown_route, fleet_visibility_payload, make_fleet_receipt_alias,
                           make_fleet_visibility_fixture)


def module():
    path = Path(__file__).with_name("fleet_sync.py")
    assert path.exists(), "fleet_sync implementation is missing"
    spec = importlib.util.spec_from_file_location("fleet_sync", path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def test_only_exact_github_source_urls_are_accepted():
    sync = module()
    assert sync.source_from_url("https://github.com/DaizeDong/fleet-guards.git") == "DaizeDong/fleet-guards"
    assert sync.source_from_url("git@github.com:DaizeDong/fleet-style.git") == "DaizeDong/fleet-style"
    assert sync.source_from_url("https://example.com/DaizeDong/fleet-guards.git") is None
    assert sync.source_from_url("https://github.com/DaizeDong/fleet-guards-extra.git") is None


@pytest.mark.parametrize("path", ["../guards", "/guards", "C:/guards", "a/../guards", "guards\nother", ".git/modules"])
def test_unsafe_submodule_paths_are_rejected(path):
    with pytest.raises(ValueError):
        module().validate_path(path)


def test_selection_respects_url_branch_and_actual_path():
    sync = module()
    contents = '''[submodule "security"]
path = vendor/security
url = https://github.com/DaizeDong/fleet-guards.git
branch = main
[submodule "other"]
path = unrelated
url = https://github.com/example/other.git
'''
    assert sync.select_modules(contents, "DaizeDong/fleet-guards") == [
        {"path": "vendor/security", "source": "DaizeDong/fleet-guards", "branch": "main"}
    ]
    assert sync.select_modules(contents, "DaizeDong/fleet-style") == []


def test_target_registry_requires_nonempty_valid_unique_subscriptions():
    sync = module()
    assert sync.parse_targets('[{"repository":"example/consumer","credential":"primary"}]') == [
        {"repository": "example/consumer", "credential": "primary"}
    ]
    for value in ("[]", '{}', '[{"repository":"https://example.com","credential":"primary"}]',
                  '[{"repository":"example/consumer","credential":"missing space"}]',
                  '[{"repository":"example/consumer","credential":"a"},{"repository":"example/consumer","credential":"b"}]'):
        with pytest.raises(ValueError):
            sync.parse_targets(value)


def test_latest_unsuccessful_ci_attempt_is_not_treated_as_green():
    sync = module()
    sha = "a" * 40
    assert sync.successful_run({"workflow_runs": [{"head_sha": sha, "event": "push", "status": "completed", "conclusion": "success"}]}, sha)
    assert not sync.successful_run({"workflow_runs": [
        {"head_sha": sha, "event": "push", "status": "completed", "conclusion": "failure"},
        {"head_sha": sha, "event": "push", "status": "completed", "conclusion": "success"},
    ]}, sha)
    assert not sync.successful_run({"workflow_runs": []}, sha)


def test_dispatch_failure_is_not_success_and_does_not_expose_target(capsys, monkeypatch):
    sync = module()
    targets = [{"repository": "example/consumer", "credential": "primary"}]
    def fail(*args, **kwargs):
        raise RuntimeError("private target and token must not appear")
    monkeypatch.setattr(sync, "api", fail)
    with pytest.raises(RuntimeError, match="1 subscription"):
        sync.dispatch_targets(targets, {"primary": "synthetic-token"}, "DaizeDong/fleet-guards", "a" * 40)
    out = capsys.readouterr().out
    assert "example/consumer" not in out
    assert "synthetic-token" not in out


def test_obsolete_delivery_cannot_roll_consumer_back(monkeypatch):
    sync = module()
    monkeypatch.setattr(sync, "api", lambda *a, **k: {"name": "main", "commit": {"sha": "b" * 40}})
    assert sync.verified_tip("DaizeDong/fleet-guards", "a" * 40, "synthetic-token") is None


def test_dispatch_payload_uses_an_exact_commit(monkeypatch):
    sync = module()
    calls = []
    monkeypatch.setattr(sync, "api", lambda *a, **kw: calls.append((a, kw)))
    sync.dispatch_targets([{"repository": "example/consumer", "credential": "primary"}],
                          {"primary": "synthetic-token"}, "DaizeDong/fleet-style", "a" * 40)
    assert calls[0][1]["body"] == {"event_type": "fleet-submodule-update", "client_payload": {
        "source_repository": "DaizeDong/fleet-style", "source_sha": "a" * 40}}


def test_missing_credentials_fail_before_any_dispatch(monkeypatch):
    sync = module()
    calls = []
    monkeypatch.setattr(sync, "api", lambda *a, **k: calls.append(a))
    with pytest.raises(ValueError):
        sync.dispatch_targets([{"repository": "example/consumer", "credential": "unknown"}], {},
                              "DaizeDong/fleet-guards", "a" * 40)
    assert not calls


@pytest.fixture
def hook_checkout(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True, **_no_window())
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / ".githooks"
    directory.mkdir()
    for name in ("pre-commit", "pre-push"):
        path = directory / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        subprocess.run(["git", "add", "--chmod=+x", str(path)], check=True, **_no_window())
    return directory


def test_executable_tracked_hooks_are_accepted(hook_checkout):
    module().require_hooks()


def test_missing_hook_is_rejected(hook_checkout):
    (hook_checkout / "pre-push").unlink()
    with pytest.raises(RuntimeError, match="shim"):
        module().require_hooks()


def test_hook_without_executable_git_mode_is_rejected(hook_checkout):
    subprocess.run(["git", "update-index", "--chmod=-x", ".githooks/pre-commit"], check=True,
                   **_no_window())
    with pytest.raises(RuntimeError, match="non-executable"):
        module().require_hooks()


@pytest.mark.skipif(os.name == "nt", reason="Windows does not enforce POSIX executable bits")
def test_hook_without_filesystem_execute_permission_is_rejected(hook_checkout):
    (hook_checkout / "pre-push").chmod(0o644)
    with pytest.raises(RuntimeError, match="non-executable"):
        module().require_hooks()


@pytest.fixture
def visibility_fixture(tmp_path, monkeypatch):
    fixture = make_fleet_visibility_fixture(tmp_path, all_routes=True)
    for key in list(os.environ):
        monkeypatch.delenv(key)
    for key, value in fixture["repo"].env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(fixture["repo"].root)
    return fixture


@pytest.fixture
def visibility_api(visibility_fixture, monkeypatch):
    fixture = visibility_fixture
    calls = []
    response = {"state": "PRIVATE"}

    class Response(io.BytesIO):
        def geturl(self):
            return self.url

    def open_metadata(opener, request, *args, **kwargs):
        name = request.full_url.removeprefix("https://api.github.com/repos/")
        assert name in fixture["names"]
        assert request.get_header("Authorization") == "Bearer " + fixture["token"]
        calls.append(name)
        if response["state"] == "unavailable":
            raise OSError("synthetic metadata outage")
        value = Response(json.dumps(fleet_visibility_payload(name, response["state"])).encode())
        value.url = request.full_url
        return value

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", open_metadata)
    return calls, response


def refresh(fixture):
    return module().refresh_visibility_receipt(
        Path(__file__).resolve().parent.parent, fixture["repo"].root, fixture["token"])


@pytest.mark.skipif(os.name != "posix", reason="Hosted receipt refresh requires POSIX permissions")
def test_refresh_covers_every_physical_effective_fetch_and_push_route(visibility_fixture, visibility_api):
    fixture = visibility_fixture
    refresh(fixture)
    receipt = json.loads(fixture["receipt"].read_text())
    assert set(receipt) == set(fixture["names"]) | {"_refreshed"}
    assert all(receipt[name] == "PRIVATE" for name in fixture["names"])
    assert sorted(visibility_api[0]) == sorted(fixture["names"])
    assert stat.S_IMODE(fixture["receipt"].stat().st_mode) == 0o600
    assert stat.S_IMODE(fixture["receipt"].parent.stat().st_mode) == 0o700


@pytest.mark.skipif(os.name != "posix", reason="Hosted receipt refresh requires POSIX permissions")
@pytest.mark.parametrize("state", ["PRIVATE", "PUBLIC"])
def test_fresh_metadata_atomically_replaces_stale_receipt(visibility_fixture, visibility_api, state):
    fixture = visibility_fixture
    fixture["receipt"].parent.mkdir()
    fixture["receipt"].write_text(json.dumps(fixture["stale"]))
    visibility_api[1]["state"] = state
    refresh(fixture)
    result = json.loads(fixture["receipt"].read_text())
    assert result[fixture["names"][0]] == state
    assert result["_refreshed"] != fixture["stale"]["_refreshed"]


@pytest.mark.skipif(os.name != "posix", reason="Hosted receipt refresh requires POSIX permissions")
@pytest.mark.parametrize("state", ["UNKNOWN", "unavailable"])
def test_unavailable_metadata_preserves_previous_receipt(visibility_fixture, visibility_api, state):
    fixture = visibility_fixture
    fixture["receipt"].parent.mkdir()
    before = json.dumps(fixture["stale"])
    fixture["receipt"].write_text(before)
    visibility_api[1]["state"] = state
    with pytest.raises(RuntimeError):
        refresh(fixture)
    assert fixture["receipt"].read_text() == before


@pytest.mark.parametrize("setting", ["empty-token", "not-actions", "unsupported-platform"])
def test_refresh_requires_explicit_supported_actions_context(visibility_fixture, visibility_api, monkeypatch, setting):
    fixture = visibility_fixture
    if setting == "empty-token":
        fixture["token"] = ""
    elif setting == "not-actions":
        monkeypatch.setenv("GITHUB_ACTIONS", "false")
    else:
        # A narrow module-local facade avoids changing pathlib's host platform.
        import types
        sync = module()
        monkeypatch.setattr(sync, "os", types.SimpleNamespace(name="nt", environ=os.environ))
        with pytest.raises(RuntimeError, match="POSIX"):
            sync.refresh_visibility_receipt(Path(__file__).parent.parent, fixture["repo"].root, fixture["token"])
        return
    with pytest.raises(RuntimeError):
        refresh(fixture)
    assert not fixture["receipt"].exists()
    assert not visibility_api[0]


@pytest.mark.skipif(os.name != "posix", reason="Alias denial runs in the supported Linux runtime")
@pytest.mark.parametrize("kind", ["worktree", "home", "directory", "file", "hardlink"])
def test_receipt_alias_or_worktree_location_is_rejected(visibility_fixture, visibility_api, monkeypatch, kind):
    fixture = visibility_fixture
    home = make_fleet_receipt_alias(fixture, kind)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    before = fixture["receipt"].read_bytes()
    with pytest.raises(RuntimeError):
        refresh(fixture)
    assert fixture["receipt"].read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="Hosted receipt refresh requires POSIX permissions")
def test_atomic_replace_failure_keeps_old_receipt_and_removes_temporary(visibility_fixture, visibility_api, monkeypatch):
    fixture = visibility_fixture
    fixture["receipt"].parent.mkdir()
    before = json.dumps(fixture["stale"])
    fixture["receipt"].write_text(before)

    def fail(*args, **kwargs):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        refresh(fixture)
    assert fixture["receipt"].read_text() == before
    assert list(fixture["receipt"].parent.iterdir()) == [fixture["receipt"]]


def test_refresh_cli_rejects_dispatch_before_accessing_credentials(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["fleet_sync.py", "dispatch", "--refresh-visibility"])
    monkeypatch.delenv("GH_TOKEN", raising=False)
    with pytest.raises(SystemExit) as error:
        module().main()
    assert error.value.code == 2


@pytest.mark.parametrize("opt_in", [False, True])
def test_update_cli_passes_only_explicit_refresh_opt_in(visibility_fixture, monkeypatch, opt_in):
    sync = module()
    observed = []
    monkeypatch.setenv("GH_TOKEN", visibility_fixture["token"])
    monkeypatch.setattr(sys, "argv", ["fleet_sync.py", "update"] + (["--refresh-visibility"] if opt_in else []))
    monkeypatch.setattr(sync, "update_consumer", lambda *args, **kwargs: observed.append(kwargs))
    sync.main()
    assert observed == [{"refresh_visibility": opt_in, "sources": {}}]


@pytest.mark.skipif(os.name != "posix", reason="Hosted receipt refresh requires POSIX permissions")
@pytest.mark.parametrize("route", ["absent", "unknown"])
def test_unproved_route_fails_before_metadata_or_receipt(visibility_fixture, visibility_api, route):
    fixture = visibility_fixture
    if route == "absent":
        fixture["repo"].git("remote", "remove", "origin")
    else:
        fixture["repo"].git("config", "--add", "remote.origin.pushurl", fleet_unknown_route())
    with pytest.raises(RuntimeError):
        refresh(fixture)
    assert not fixture["receipt"].exists()
    assert not visibility_api[0]


# ------------------------------------------------- private or custom upstreams (synthetic names only)
DECLARED = '{"example/upstream": {"workflow": "ci.yml", "branch": "master"}}'
SYNTHETIC_TOKEN = "synthetic-upstream-token-0123456789"


def test_declared_upstream_is_accepted_and_resolved_case_insensitively():
    sync = module()
    sources = sync.parse_sources(DECLARED)
    assert sources == {"example/upstream": {"workflow": "ci.yml", "branch": "master"}}
    assert sync.resolve_source("Example/Upstream", sources) == (
        "example/upstream", {"workflow": "ci.yml", "branch": "master"})
    assert sync.parse_sources("") == {} and sync.parse_sources("   ") == {}


@pytest.mark.parametrize("value", [
    "{",                                                                  # malformed JSON
    "[]",                                                                 # not an object
    '"example/upstream"',
    '{"example/upstream": {"workflow": "ci.yml"}}',                       # missing branch
    '{"example/upstream": {"workflow": "ci.yml", "branch": "main", "token": "x"}}',  # unknown key
    '{"example/upstream": ["ci.yml", "main"]}',
    '{"example/upstream": {"workflow": ".github/workflows/ci.yml", "branch": "main"}}',  # a path
    '{"example/upstream": {"workflow": "ci.txt", "branch": "main"}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": "a..b"}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": "-main"}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": "main.lock"}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": ""}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": 1}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": "refs/heads/master"}}',   # a full ref
    '{"example/upstream": {"workflow": "ci.yml", "branch": "refs/master"}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": "%s"}}' % ("c" * 40),     # a commit id
    '{"example/upstream": {"workflow": "ci.yml", "branch": "%s"}}' % ("0123456789ABCDEF" * 3)[:40],
    '{"example/upstream": {"workflow": "ci.yml", "branch": "%s"}}' % ("d" * 64),
    '{"https://github.com/example/upstream": {"workflow": "ci.yml", "branch": "main"}}',
    '{"example/upstream.git": {"workflow": "ci.yml", "branch": "main"}}',
    '{"example/..": {"workflow": "ci.yml", "branch": "main"}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": "main"},'
    ' "Example/Upstream": {"workflow": "ci.yml", "branch": "main"}}',   # case-folded duplicate
])
def test_malformed_declarations_are_rejected(value):
    with pytest.raises(ValueError):
        module().parse_sources(value)


@pytest.mark.parametrize("branch", ["master", "release/1.x", "refs", "heads/main", "c" * 39, "c" * 41,
                                    "feature/" + "c" * 40])
def test_short_branch_names_stay_valid(branch):
    assert module().valid_branch(branch)


@pytest.mark.parametrize("spec", [
    {"workflow": "other.yml", "branch": "main"},
    {"workflow": "pii-guard.yml", "branch": "develop"},
])
def test_builtin_kit_cannot_be_shadowed_by_a_declaration(spec):
    sync = module()
    with pytest.raises(ValueError, match="built-in"):
        sync.parse_sources(json.dumps({"daizedong/FLEET-GUARDS": spec}))
    for name in ("DaizeDong/fleet-guards", "daizedong/FLEET-GUARDS"):
        with pytest.raises(ValueError, match="built-in"):
            sync.verified_tip(name, "", SYNTHETIC_TOKEN, spec)


def test_restating_a_builtin_with_its_own_settings_is_harmless():
    sync = module()
    assert sync.parse_sources('{"DaizeDong/fleet-style": {"workflow": "style.yml", "branch": "main"}}') == {}


def test_declared_source_urls_match_https_and_ssh_forms():
    sync = module()
    sources = sync.parse_sources(DECLARED)
    for url in ("https://github.com/example/upstream.git", "https://github.com/Example/Upstream",
                "git@github.com:example/upstream.git"):
        assert sync.source_from_url(url, sources) == "example/upstream"
    assert sync.source_from_url("https://github.com/example/upstream.git") is None
    assert sync.source_from_url("https://example.com/example/upstream.git", sources) is None
    assert sync.source_from_url("https://github.com/example/upstream-extra.git", sources) is None


GITMODULES_DECLARED = '''[submodule "upstream"]
path = vendor/upstream
url = https://github.com/example/upstream.git
branch = %s
[submodule "guards"]
path = guards
url = https://github.com/DaizeDong/fleet-guards.git
'''


def test_declared_upstream_is_selected_only_on_its_declared_branch():
    sync = module()
    sources = sync.parse_sources(DECLARED)
    assert sync.select_modules(GITMODULES_DECLARED % "master", "example/upstream", sources) == [
        {"path": "vendor/upstream", "source": "example/upstream", "branch": "master"}]
    assert [m["source"] for m in sync.select_modules(GITMODULES_DECLARED % "master", "all", sources)] == [
        "example/upstream", "DaizeDong/fleet-guards"]
    # Undeclared, the same .gitmodules entry is ignored rather than followed.
    assert sync.select_modules(GITMODULES_DECLARED % "master", "example/upstream") == []


@pytest.mark.parametrize("contents", [
    GITMODULES_DECLARED % "main",
    GITMODULES_DECLARED.replace("branch = %s\n", ""),        # missing branch means main
])
def test_declared_upstream_with_mismatched_gitmodules_branch_is_rejected(contents):
    sync = module()
    with pytest.raises(ValueError, match="branch"):
        sync.select_modules(contents, "all", sync.parse_sources(DECLARED))


def test_builtin_kit_still_requires_main():
    sync = module()
    contents = '[submodule "g"]\npath = guards\nurl = https://github.com/DaizeDong/fleet-guards.git\nbranch = master\n'
    with pytest.raises(ValueError):
        sync.select_modules(contents, "all", sync.parse_sources(DECLARED))


def _green_runs(tip):
    return {"workflow_runs": [{"head_sha": tip, "event": "push", "status": "completed",
                               "conclusion": "success"}]}


def _endpoint(path):
    """("owner/repo", kind, rest) of a recorded API path, without its query."""
    parts = path.split("?")[0].split("/")
    assert parts[0] == "repos", path
    return "/".join(parts[1:3]), parts[3], "/".join(parts[4:])


def green_api(calls, tip):
    """Any repository: the branch asked for is at tip and its gate is green."""
    def api(path, token, **kwargs):
        calls.append(path)
        _repository, kind, rest = _endpoint(path)
        if kind == "branches":
            return {"name": rest, "commit": {"sha": tip}}
        assert kind == "actions", path
        return _green_runs(tip)
    return api


def branch_api(calls, tips):
    """tips maps "owner/repo" to (branch, commit); every gate is green.

    Like GitHub, the branch endpoint answers only for an existing branch; an unknown repository or
    endpoint fails the test instead of returning something plausible.
    """
    def api(path, token, **kwargs):
        calls.append(path)
        repository, kind, rest = _endpoint(path)
        branch, tip = tips[repository]
        if kind == "branches":
            if rest != branch:
                raise RuntimeError("GitHub API returned HTTP 404")
            return {"name": branch, "commit": {"sha": tip}}
        assert kind == "actions", path
        return _green_runs(tip)
    return api


def test_verified_tip_uses_declared_branch_and_workflow(monkeypatch):
    sync = module()
    calls = []
    tip = "c" * 40
    monkeypatch.setattr(sync, "api", green_api(calls, tip))
    spec = sync.parse_sources(DECLARED)["example/upstream"]
    assert sync.verified_tip("example/upstream", tip, SYNTHETIC_TOKEN, spec) == tip
    assert calls[0] == "repos/example/upstream/branches/master"
    assert calls[1].startswith("repos/example/upstream/actions/workflows/ci.yml/runs?")
    assert "branch=master" in calls[1] and "event=push" in calls[1]


@pytest.mark.parametrize("answer", [
    {"name": "main", "commit": {"sha": "c" * 40}},          # a renamed branch redirected elsewhere
    {"name": "master", "commit": {"sha": "c" * 39}},
    {"name": "master", "commit": {"sha": "-" + "c" * 39}},
    {"name": "master", "commit": {"sha": "C" * 40}},
    {"name": "master", "commit": None},
    {"name": "master"},
    {"commit": {"sha": "c" * 40}},
    None,
])
def test_tip_lookup_must_name_the_declared_branch_and_a_full_commit(monkeypatch, answer):
    sync = module()
    calls = []
    monkeypatch.setattr(sync, "api", lambda path, token, **k: calls.append(path) or answer)
    spec = sync.parse_sources(DECLARED)["example/upstream"]
    with pytest.raises(RuntimeError, match="declared branch"):
        sync.verified_tip("example/upstream", "", SYNTHETIC_TOKEN, spec)
    assert calls == ["repos/example/upstream/branches/master"]          # no gate lookup after it


def test_verified_tip_requires_a_declaration_for_a_non_builtin(monkeypatch):
    sync = module()
    calls = []
    monkeypatch.setattr(sync, "api", green_api(calls, "c" * 40))
    with pytest.raises(ValueError):
        sync.verified_tip("example/upstream", "", SYNTHETIC_TOKEN)
    assert not calls


def test_declared_upstream_obsolete_notification_is_a_noop(monkeypatch):
    sync = module()
    monkeypatch.setattr(sync, "api", lambda *a, **k: {"name": "master", "commit": {"sha": "b" * 40}})
    spec = sync.parse_sources(DECLARED)["example/upstream"]
    assert sync.verified_tip("example/upstream", "a" * 40, SYNTHETIC_TOKEN, spec) is None


def test_dispatch_source_resolution():
    sync = module()
    assert sync.dispatch_source("DaizeDong/fleet-style", "", "") == (
        "DaizeDong/fleet-style", {"workflow": "style.yml", "branch": "main"})
    assert sync.dispatch_source("example/upstream", "ci.yml", "master") == (
        "example/upstream", {"workflow": "ci.yml", "branch": "master"})
    for args in (("example/upstream", "", ""), ("example/upstream", "ci.yml", ""),
                 ("example/upstream", "", "master"), ("DaizeDong/fleet-guards", "other.yml", "main"),
                 ("example/upstream", "../ci.yml", "master")):
        with pytest.raises(ValueError):
            sync.dispatch_source(*args)


def test_dispatch_cli_verifies_a_custom_upstream_on_its_declared_gate(monkeypatch):
    sync = module()
    calls, sent = [], []
    tip = "d" * 40
    monkeypatch.setattr(sync, "api", green_api(calls, tip))
    monkeypatch.setattr(sync, "dispatch_targets", lambda *a: sent.append(a))
    monkeypatch.setattr(sys, "argv", ["fleet_sync.py", "dispatch"])
    for key, value in (("GH_TOKEN", SYNTHETIC_TOKEN), ("SOURCE_REPOSITORY", "example/upstream"),
                       ("SOURCE_SHA", tip), ("FLEET_SYNC_UPSTREAM_WORKFLOW", "ci.yml"),
                       ("FLEET_SYNC_UPSTREAM_BRANCH", "master"),
                       ("FLEET_SYNC_TARGETS", '[{"repository":"example/consumer","credential":"primary"}]'),
                       ("FLEET_SYNC_CREDENTIALS", '{"primary":"synthetic-token"}')):
        monkeypatch.setenv(key, value)
    sync.main()
    assert calls[0] == "repos/example/upstream/branches/master"
    assert "/workflows/ci.yml/" in calls[1]
    assert sent and sent[0][2:] == ("example/upstream", tip)


@pytest.mark.parametrize("source", ["", "all"])
def test_dispatch_event_without_a_named_upstream_is_not_a_full_sync(monkeypatch, source):
    sync = module()
    observed = []
    monkeypatch.setattr(sync, "update_consumer", lambda *a, **k: observed.append(a))
    monkeypatch.setattr(sys, "argv", ["fleet_sync.py", "update"])
    monkeypatch.setenv("GH_TOKEN", SYNTHETIC_TOKEN)
    monkeypatch.setenv("SOURCE_REPOSITORY", source)
    monkeypatch.setenv("FLEET_SYNC_EVENT", "repository_dispatch")
    with pytest.raises(ValueError):
        sync.main()
    assert not observed


def test_scheduled_run_without_payload_still_reconciles_all(monkeypatch):
    sync = module()
    observed = []
    monkeypatch.setattr(sync, "update_consumer", lambda *a, **k: observed.append((a, k)))
    monkeypatch.setattr(sys, "argv", ["fleet_sync.py", "update"])
    monkeypatch.setenv("GH_TOKEN", SYNTHETIC_TOKEN)
    monkeypatch.setenv("SOURCE_REPOSITORY", "")
    monkeypatch.setenv("FLEET_SYNC_EVENT", "schedule")
    monkeypatch.setenv("FLEET_SYNC_SOURCES", DECLARED)
    sync.main()
    assert observed[0][0][0] == "all"
    assert observed[0][1]["sources"] == {"example/upstream": {"workflow": "ci.yml", "branch": "master"}}


def test_update_cli_rejects_malformed_declaration_before_any_work(monkeypatch):
    sync = module()
    observed = []
    monkeypatch.setattr(sync, "update_consumer", lambda *a, **k: observed.append(a))
    monkeypatch.setattr(sys, "argv", ["fleet_sync.py", "update"])
    monkeypatch.setenv("GH_TOKEN", SYNTHETIC_TOKEN)
    monkeypatch.setenv("FLEET_SYNC_SOURCES", "{not json")
    with pytest.raises(ValueError, match="JSON"):
        sync.main()
    assert not observed


# ------------------------------------------------- the updater end to end, with recorded doubles
OLD_UPSTREAM, NEW_UPSTREAM = "a" * 40, "c" * 40
OLD_GUARDS, NEW_GUARDS = "1" * 40, "2" * 40
FORK_TIP = "f" * 40
ANCESTRY = {(OLD_UPSTREAM, NEW_UPSTREAM), (OLD_GUARDS, NEW_GUARDS)}
GITMODULES_GUARDS = '[submodule "guards"]\npath = guards\nurl = https://github.com/DaizeDong/fleet-guards.git\n'
FORK = '{"example/fork": {"workflow": "ci.yml", "branch": "master"}}'


class FakeGit:
    """Stands in for git and for the gate's interpreter in a consumer checkout.

    It records every call and keeps the state the updater depends on: the gitlinks in the index,
    the commit each submodule has checked out, which commit descends from which, and what is
    staged. A git call it does not model fails the test rather than succeeding quietly.
    """

    def __init__(self, root, index, ancestry):
        self.root = root
        self.original = dict(index)
        self.index = dict(index)
        self.heads = dict(index)
        self.ancestry = set(ancestry)
        self.calls = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, kwargs.get("env")))
        if argv[0] == sys.executable:
            return subprocess.CompletedProcess(argv, 0)
        assert argv[0] == "git", argv
        cwd, args = (argv[2], argv[3:]) if argv[1] == "-C" else (None, argv[1:])
        out = ""
        if args[:3] == ["ls-files", "--stage", "--"]:
            if args[3] in self.index:
                out = "160000 %s 0\t%s" % (self.index[args[3]], args[3])
            elif args[3].startswith(".githooks/"):
                out = "100755 %s 0\t%s" % ("e" * 40, args[3])
        elif args[:2] == ["merge-base", "--is-ancestor"]:
            if (args[2], args[3]) not in self.ancestry:
                raise subprocess.CalledProcessError(1, argv)
        elif args[:2] == ["checkout", "--detach"]:
            self.heads[cwd] = args[2]
        elif args[:2] == ["add", "--"]:
            self.index[args[2]] = self.heads[args[2]]
        elif args == ["diff", "--cached", "--name-only"]:
            out = "\n".join(path for path, sha in self.index.items() if sha != self.original.get(path))
        elif args == ["rev-parse", "--show-toplevel"]:
            out = str(self.root)
        elif not (args == ["status", "--porcelain"] or args[:3] == ["submodule", "update", "--init"]
                  or args[0] in ("fetch", "config", "commit", "push")):
            raise AssertionError("unmodelled git call: %r" % argv)
        return subprocess.CompletedProcess(argv, 0, out, None)

    def git(self, word, path=None):
        """Recorded git argv lists running subcommand word, optionally only those with -C path."""
        found = []
        for argv, _env in self.calls:
            if argv[0] == "git":
                cwd, args = (argv[2], argv[3:]) if argv[1] == "-C" else (None, argv[1:])
                if args[0] == word and (path is None or cwd == path):
                    found.append(argv)
        return found

    def gate(self):
        return [argv for argv, _env in self.calls if argv[0] == sys.executable]

    def networked(self):
        return [(argv, env) for argv, env in self.calls
                if argv[0] == "git" and ("fetch" in argv or "submodule" in argv)]


@pytest.fixture
def consumer(tmp_path, monkeypatch):
    """A consumer checkout with hook shims and a guard kit on disk; git and the API are doubles.

    Call consumer.setup(gitmodules, index, tips) to choose the .gitmodules text, the recorded
    gitlinks and each upstream's (branch, tip); it returns the FakeGit that records the run.
    """
    import types
    sync = module()
    monkeypatch.chdir(tmp_path)
    for key in ("GH_TOKEN", "GIT_CONFIG_COUNT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CONSUMER_BRANCH", "trunk")
    (tmp_path / ".githooks").mkdir()
    for name in ("pre-commit", "pre-push"):
        (tmp_path / ".githooks" / name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        (tmp_path / ".githooks" / name).chmod(0o755)
    (tmp_path / "guards" / "tools").mkdir(parents=True)
    for name in ("publication_guard.py", "data_boundary.py", "pii_guard.py"):
        (tmp_path / "guards" / "tools" / name).write_text("# synthetic\n", encoding="utf-8")
    state = types.SimpleNamespace(sync=sync, root=tmp_path, api_calls=[])

    def setup(gitmodules, index, tips, ancestry=ANCESTRY):
        (tmp_path / ".gitmodules").write_text(gitmodules, encoding="utf-8")
        fake = FakeGit(tmp_path, index, ancestry)
        monkeypatch.setattr(sync.subprocess, "run", fake)
        monkeypatch.setattr(sync, "api", branch_api(state.api_calls, tips))
        return fake

    state.setup = setup
    return state


def declared_consumer(consumer):
    """The synthetic example/upstream on master beside fleet-guards, both behind their tips."""
    return consumer.setup(GITMODULES_DECLARED % "master",
                          {"vendor/upstream": OLD_UPSTREAM, "guards": OLD_GUARDS},
                          {"example/upstream": ("master", NEW_UPSTREAM),
                           "DaizeDong/fleet-guards": ("main", NEW_GUARDS)})


def builtin_consumer(consumer):
    return consumer.setup(GITMODULES_GUARDS, {"guards": OLD_GUARDS},
                          {"DaizeDong/fleet-guards": ("main", NEW_GUARDS)})


def test_builtin_kit_update_follows_main_in_lookup_gate_and_fetch(consumer, capsys):
    fake = builtin_consumer(consumer)
    consumer.sync.update_consumer("DaizeDong/fleet-guards", "", SYNTHETIC_TOKEN)
    lookup, runs = consumer.api_calls
    assert lookup == "repos/DaizeDong/fleet-guards/branches/main"
    assert runs.startswith("repos/DaizeDong/fleet-guards/actions/workflows/pii-guard.yml/runs?")
    assert "branch=main" in runs and "head_sha=" + NEW_GUARDS in runs
    assert fake.git("fetch") == [["git", "-C", "guards", "fetch",
                                  "https://github.com/DaizeDong/fleet-guards.git", "refs/heads/main"]]
    assert "Updated submodules: 1" in capsys.readouterr().out


def test_ancestry_is_checked_with_the_recorded_gitlink_first(consumer, capsys):
    fake = builtin_consumer(consumer)
    consumer.sync.update_consumer("DaizeDong/fleet-guards", "", SYNTHETIC_TOKEN)
    assert fake.git("merge-base") == [["git", "-C", "guards", "merge-base", "--is-ancestor",
                                       OLD_GUARDS, NEW_GUARDS]]
    capsys.readouterr()


def test_a_tip_that_does_not_descend_from_the_gitlink_is_refused(consumer):
    fake = consumer.setup(GITMODULES_GUARDS, {"guards": OLD_GUARDS},
                          {"DaizeDong/fleet-guards": ("main", NEW_GUARDS)}, ancestry=set())
    with pytest.raises(subprocess.CalledProcessError):
        consumer.sync.update_consumer("DaizeDong/fleet-guards", "", SYNTHETIC_TOKEN)
    assert not fake.git("checkout") and not fake.git("commit") and not fake.gate()


def test_submodule_is_checked_out_and_staged_at_the_verified_tip(consumer, capsys):
    fake = builtin_consumer(consumer)
    consumer.sync.update_consumer("DaizeDong/fleet-guards", "", SYNTHETIC_TOKEN)
    assert fake.git("checkout") == [["git", "-C", "guards", "checkout", "--detach", NEW_GUARDS]]
    assert fake.git("add") == [["git", "add", "--", "guards"]]
    assert fake.index == {"guards": NEW_GUARDS}
    capsys.readouterr()


def test_changed_update_runs_gate_then_commits_and_pushes(consumer, capsys):
    fake = builtin_consumer(consumer)
    consumer.sync.update_consumer("DaizeDong/fleet-guards", "", SYNTHETIC_TOKEN)
    gate = [sys.executable, str(Path("guards") / "tools/publication_guard.py"), "pre-commit",
            "--repo", str(consumer.root)]
    assert fake.gate() == [gate]
    configured = [argv[2:] for argv in fake.git("config")]
    assert configured[0] == ["core.hooksPath", ".githooks"]
    assert ["user.email", "41898282+github-actions[bot]@users.noreply.github.com"] in configured
    assert fake.git("commit") == [["git", "commit", "-m", "chore: sync verified fleet submodules"]]
    assert fake.git("push") == [["git", "push", "origin", "HEAD:refs/heads/trunk"]]
    order = [argv for argv, _env in fake.calls]
    staged = order.index(["git", "diff", "--cached", "--name-only"])
    assert staged < order.index(gate) < order.index(fake.git("commit")[0]) < order.index(fake.git("push")[0])
    assert order[-1] == fake.git("push")[0]
    capsys.readouterr()


def test_all_run_advances_declared_master_upstream_and_builtin_kit(consumer, capsys):
    fake = declared_consumer(consumer)
    consumer.sync.update_consumer("all", "", SYNTHETIC_TOKEN, sources=consumer.sync.parse_sources(DECLARED))
    assert [_endpoint(path)[:2] for path in consumer.api_calls] == [
        ("example/upstream", "branches"), ("example/upstream", "actions"),
        ("DaizeDong/fleet-guards", "branches"), ("DaizeDong/fleet-guards", "actions")]
    assert fake.git("fetch") == [
        ["git", "-C", "vendor/upstream", "fetch", "https://github.com/example/upstream.git", "refs/heads/master"],
        ["git", "-C", "guards", "fetch", "https://github.com/DaizeDong/fleet-guards.git", "refs/heads/main"]]
    assert fake.git("checkout") == [["git", "-C", "vendor/upstream", "checkout", "--detach", NEW_UPSTREAM],
                                    ["git", "-C", "guards", "checkout", "--detach", NEW_GUARDS]]
    assert fake.index == {"vendor/upstream": NEW_UPSTREAM, "guards": NEW_GUARDS}
    assert len(fake.git("commit")) == 1 and len(fake.git("push")) == 1 and len(fake.gate()) == 1
    assert "Updated submodules: 2" in capsys.readouterr().out


@pytest.mark.parametrize("source", ["example/upstream", "DaizeDong/fleet-guards"])
def test_obsolete_notification_through_update_consumer_is_a_noop(consumer, capsys, source):
    fake = declared_consumer(consumer)
    consumer.sync.update_consumer(source, "b" * 40, SYNTHETIC_TOKEN,
                                  sources=consumer.sync.parse_sources(DECLARED))
    assert [_endpoint(path)[1] for path in consumer.api_calls] == ["branches"]   # no gate lookup
    assert not fake.networked() and not fake.git("checkout") and not fake.git("add")
    assert not fake.gate() and not fake.git("commit") and not fake.git("push")
    assert fake.index == fake.original
    out = capsys.readouterr().out
    assert "Obsolete notification" in out and "Updated submodules: 0" in out


def test_notification_for_the_current_tip_is_applied(consumer, capsys):
    fake = declared_consumer(consumer)
    consumer.sync.update_consumer("example/upstream", NEW_UPSTREAM, SYNTHETIC_TOKEN,
                                  sources=consumer.sync.parse_sources(DECLARED))
    assert fake.index == {"vendor/upstream": NEW_UPSTREAM, "guards": OLD_GUARDS}
    assert len(fake.git("push")) == 1
    capsys.readouterr()


def test_declared_master_upstream_notification_leaves_the_kit_alone(consumer, capsys):
    fake = declared_consumer(consumer)
    consumer.sync.update_consumer("example/upstream", "", SYNTHETIC_TOKEN,
                                  sources=consumer.sync.parse_sources(DECLARED))
    assert fake.git("fetch") == [["git", "-C", "vendor/upstream", "fetch",
                                  "https://github.com/example/upstream.git", "refs/heads/master"]]
    assert consumer.api_calls[0] == "repos/example/upstream/branches/master"
    # The kit is only read for the commit gate: never looked up, fetched, moved or staged.
    assert not any("fleet-guards" in path for path in consumer.api_calls)
    assert [argv[-1] for argv in fake.git("submodule")] == ["vendor/upstream"]
    assert not fake.git("fetch", "guards") and not fake.git("checkout", "guards")
    assert fake.index["guards"] == OLD_GUARDS and fake.git("add") == [["git", "add", "--", "vendor/upstream"]]
    capsys.readouterr()


def test_commit_gate_requires_the_kit_path_to_be_a_gitlink(consumer, capsys):
    fake = consumer.setup(GITMODULES_DECLARED % "master", {"vendor/upstream": OLD_UPSTREAM},
                          {"example/upstream": ("master", NEW_UPSTREAM)})
    with pytest.raises(RuntimeError, match="fleet-guards path is not a tracked gitlink"):
        consumer.sync.update_consumer("example/upstream", "", SYNTHETIC_TOKEN,
                                      sources=consumer.sync.parse_sources(DECLARED))
    assert not fake.gate() and not fake.git("commit") and not fake.git("push")
    capsys.readouterr()


def test_upstream_credential_never_reaches_argv_url_or_output(consumer, capsys):
    import base64
    fake = declared_consumer(consumer)
    consumer.sync.update_consumer("all", "", SYNTHETIC_TOKEN, sources=consumer.sync.parse_sources(DECLARED))
    encoded = base64.b64encode(("x-access-token:" + SYNTHETIC_TOKEN).encode()).decode()
    out = capsys.readouterr()
    for argv, _env in fake.calls:
        assert not any(SYNTHETIC_TOKEN in arg or encoded in arg for arg in argv)
    assert SYNTHETIC_TOKEN not in out.out + out.err and encoded not in out.out + out.err
    networked = fake.networked()
    assert len(networked) == 4                   # submodule update and fetch, for both upstreams
    for _argv, env in networked:
        assert SYNTHETIC_TOKEN not in json.dumps(env)        # only the header form, only in env
        count = int(env["GIT_CONFIG_COUNT"])
        assert [(env["GIT_CONFIG_KEY_%d" % i], env["GIT_CONFIG_VALUE_%d" % i]) for i in range(count)] == [
            ("http.extraheader", ""),
            ("http.https://github.com/.extraheader", ""),
            ("http.https://github.com/.extraheader", "AUTHORIZATION: basic " + encoded),
            ("url.https://github.com/.insteadOf", "git@github.com:")]
    # Local commands, the gate included, carry no credential at all.
    assert all(env is None for argv, env in fake.calls if (argv, env) not in networked)


def test_failed_fetch_error_text_does_not_contain_the_credential(consumer, monkeypatch):
    fake = declared_consumer(consumer)

    def failing(argv, **kwargs):
        if "fetch" in argv:
            raise subprocess.CalledProcessError(128, argv)
        return fake(argv, **kwargs)

    monkeypatch.setattr(consumer.sync.subprocess, "run", failing)
    with pytest.raises(subprocess.CalledProcessError) as error:
        consumer.sync.update_consumer("example/upstream", "", SYNTHETIC_TOKEN,
                                      sources=consumer.sync.parse_sources(DECLARED))
    assert SYNTHETIC_TOKEN not in str(error.value)
    assert "x-access-token" not in str(error.value)


def test_unknown_payload_source_is_rejected_before_any_git_or_api(consumer):
    fake = declared_consumer(consumer)
    with pytest.raises(ValueError, match="Unknown upstream"):
        consumer.sync.update_consumer("example/undeclared", "", SYNTHETIC_TOKEN,
                                      sources=consumer.sync.parse_sources(DECLARED))
    assert not fake.calls and not consumer.api_calls


# ------------------------------------------------- one path, one upstream; built-in kits stay built in
UNRELATED = '[submodule "%s"]\npath = %s\nurl = https://example.com/%s.git\n'


@pytest.mark.parametrize("contents", [
    UNRELATED % ("one", "vendor/lib", "one") + UNRELATED % ("two", "vendor/lib", "two"),
    GITMODULES_DECLARED % "master" + UNRELATED % ("copy", "vendor/upstream", "copy"),
    GITMODULES_DECLARED % "master" + UNRELATED % ("copy", "Vendor/Upstream", "copy"),
    GITMODULES_DECLARED % "master" + UNRELATED % ("inner", "vendor/upstream/inner", "inner"),
    GITMODULES_DECLARED % "master" + UNRELATED % ("outer", "vendor", "outer"),
    GITMODULES_DECLARED % "master" + '[submodule "again"]\npath = vendor/upstream/\n'
                                     'url = https://github.com/example/upstream.git\nbranch = master\n',
    GITMODULES_GUARDS + '[submodule "style"]\npath = guards\nurl = https://github.com/DaizeDong/fleet-style.git\n',
], ids=["unrelated", "declared-and-unrelated", "case", "nested", "enclosing", "declared-twice", "two-kits"])
@pytest.mark.parametrize("source", ["all", "example/upstream", "DaizeDong/fleet-style"])
def test_entries_sharing_or_nesting_a_path_are_rejected_regardless_of_source(contents, source):
    sync = module()
    with pytest.raises(ValueError, match="same or nested"):
        sync.select_modules(contents, source, sync.parse_sources(DECLARED))


FORK_ON = GITMODULES_GUARDS.replace("path = guards", "path = %s") + (
    '[submodule "fork"]\npath = %s\nurl = https://github.com/example/fork.git\nbranch = master\n')


@pytest.mark.parametrize("kit, fork", [("guards", "guards"), ("guards", "Guards"), ("guards", "guards/tools"),
                                       ("vendor/guards", "vendor")],
                         ids=["same", "case", "inside-kit", "around-kit"])
@pytest.mark.parametrize("source", ["all", "example/fork", "DaizeDong/fleet-guards"])
def test_declared_upstream_cannot_use_a_builtin_kit_path(kit, fork, source):
    sync = module()
    with pytest.raises(ValueError, match="built-in kit's submodule path"):
        sync.select_modules(FORK_ON % (kit, fork), source, sync.parse_sources(FORK))


@pytest.mark.parametrize("source", ["all", "example/fork"])
def test_fork_on_the_gate_path_never_reaches_checkout_or_gate(consumer, source):
    """The kit is at its tip and is skipped; the fork must not then be checked out in its place."""
    fake = consumer.setup(FORK_ON % ("guards", "guards"), {"guards": NEW_GUARDS},
                          {"DaizeDong/fleet-guards": ("main", NEW_GUARDS), "example/fork": ("master", FORK_TIP)},
                          ancestry={(NEW_GUARDS, FORK_TIP)})
    with pytest.raises(ValueError):
        consumer.sync.update_consumer(source, "", SYNTHETIC_TOKEN, sources=consumer.sync.parse_sources(FORK))
    assert not fake.networked() and not fake.git("checkout") and not fake.gate() and not fake.git("push")
    assert fake.index == {"guards": NEW_GUARDS}


@pytest.mark.parametrize("name", ["DaizeDong/fleet-guards", "daizedong/FLEET-GUARDS", "DaizeDong/Fleet-Style"])
def test_declared_upstream_with_a_builtin_url_is_refused(consumer, name):
    sync = consumer.sync
    fake = declared_consumer(consumer)
    for spec in ({"workflow": "ci.yml", "branch": "master"}, sync.builtin_spec(sync.builtin_name(name))):
        shadow = {name: spec}
        with pytest.raises(ValueError, match="built-in kit's URL"):
            sync.checked_sources(shadow)
        with pytest.raises(ValueError, match="built-in kit's URL"):
            sync.select_modules(GITMODULES_DECLARED % "master", "all", shadow)
        with pytest.raises(ValueError, match="built-in kit's URL"):
            sync.update_consumer("all", "", SYNTHETIC_TOKEN, sources=shadow)
    assert not fake.calls and not consumer.api_calls
    # A consumer restating a kit with its own settings never produces such an entry.
    assert sync.parse_sources(json.dumps({name: sync.builtin_spec(sync.builtin_name(name))})) == {}


# ------------------------------------------------- the credential, measured with real git
@pytest.fixture
def header_server():
    """A local HTTP server that records the path and Authorization headers of each request."""
    import http.server
    import threading
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get_all("Authorization") or []))
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d/" % server.server_port, seen
    server.shutdown()
    server.server_close()


def _isolated_git_env(tmp_path):
    """No system, global, proxy or prompt influence: only what the test configures reaches git."""
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith("GIT_") and not key.upper().endswith("_PROXY")}
    (tmp_path / "empty-global").write_text("", encoding="utf-8")
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(tmp_path / "empty-global"),
               NO_PROXY="*", no_proxy="*", GIT_TERMINAL_PROMPT="0")
    return env


def _basic(user_and_secret):
    import base64
    return "basic " + base64.b64encode(user_and_secret.encode()).decode()


@pytest.mark.parametrize("persisted, rescope, expected", [
    (("scoped",), True, "updater"), (("plain",), True, "updater"), (("scoped", "plain"), True, "updater"),
    (("plain", "scoped"), True, "updater"), (("narrower",), True, "narrower"), (("plain",), False, None),
])
def test_real_git_sends_at_most_one_authorization_header(tmp_path, header_server, persisted, rescope,
                                                         expected):
    """The updater's entries against real git and a local server that records what arrives.

    With rescope, the entries scoped to github.com are scoped to the local server instead, so it
    stands in for github.com. Without it, the server is any other host: the credential must not
    reach it, and neither may an unscoped persisted header. "scoped" is what actions/checkout
    persists, "plain" an unscoped header from any other source, and "narrower" a header persisted
    for one repository's URL, which outranks the updater's entries: git then sends it alone.
    """
    sync = module()
    base, seen = header_server
    env = _isolated_git_env(tmp_path)
    repo = tmp_path / "submodule"
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True, timeout=60, **_no_window(env=env))
    keys = {"scoped": "http.%s.extraheader" % base, "plain": "http.extraheader",
            "narrower": "http.%sexample/upstream.git.extraheader" % base}
    for name in persisted:
        subprocess.run(["git", "-C", str(repo), "config", "--add", keys[name],
                        "AUTHORIZATION: " + _basic("x-access-token:persisted-" + name)],
                       check=True, timeout=60, **_no_window(env=env))
    auth = sync.github_auth_env(SYNTHETIC_TOKEN, env)
    for index in range(int(auth["GIT_CONFIG_COUNT"]) if rescope else 0):
        key = "GIT_CONFIG_KEY_%d" % index
        auth[key] = auth[key].replace("http.https://github.com/.", "http.%s." % base)
    run = subprocess.run(["git", "-C", str(repo), "ls-remote", base + "example/upstream.git"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=60,
                         **_no_window(env=auth))
    want = {"updater": [_basic("x-access-token:" + SYNTHETIC_TOKEN)],
            "narrower": [_basic("x-access-token:persisted-narrower")], None: []}[expected]
    # Only git's own request counts: any other local connection to the port is not evidence.
    mine = [headers for path, headers in seen if path.startswith("/example/upstream.git/info/refs")]
    assert mine and mine[0] == want, (seen, run.returncode, run.stderr)


def test_real_git_rewrites_ssh_github_urls_for_the_credentialed_process(tmp_path):
    sync = module()
    env = _isolated_git_env(tmp_path)
    subprocess.run(["git", "init", "--quiet", str(tmp_path / "repo")], check=True, timeout=60,
                   **_no_window(env=env))
    shown = subprocess.run(["git", "-C", str(tmp_path / "repo"), "ls-remote", "--get-url",
                            "git@github.com:example/upstream.git"], check=True, text=True, timeout=60,
                           stdout=subprocess.PIPE, **_no_window(env=sync.github_auth_env(SYNTHETIC_TOKEN, env)))
    assert shown.stdout.strip() == "https://github.com/example/upstream.git"


def test_auth_env_appends_after_existing_entries_and_persists_nothing(tmp_path):
    sync = module()
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True, **_no_window())
    base = dict(os.environ, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.abbrev", GIT_CONFIG_VALUE_0="12")
    env = sync.github_auth_env(SYNTHETIC_TOKEN, base)
    assert env["GIT_CONFIG_KEY_0"] == "core.abbrev" and env["GIT_CONFIG_COUNT"] == "5"
    shown = subprocess.run(["git", "-C", str(tmp_path), "config", "--show-origin", "--get-all",
                            "http.https://github.com/.extraheader"], check=True, text=True,
                           stdout=subprocess.PIPE, **_no_window(env=env)).stdout
    assert "command line:" in shown and "AUTHORIZATION: basic" in shown
    assert "AUTHORIZATION" not in (tmp_path / ".git" / "config").read_text(encoding="utf-8")
    for bad in ("", "   ", None):
        with pytest.raises(RuntimeError):
            sync.github_auth_env(bad, base)
