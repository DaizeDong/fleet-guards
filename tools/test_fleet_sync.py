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
    monkeypatch.setattr(sync, "api", lambda *a, **k: {"sha": "b" * 40})
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
    '{"https://github.com/example/upstream": {"workflow": "ci.yml", "branch": "main"}}',
    '{"example/upstream.git": {"workflow": "ci.yml", "branch": "main"}}',
    '{"example/..": {"workflow": "ci.yml", "branch": "main"}}',
    '{"example/upstream": {"workflow": "ci.yml", "branch": "main"},'
    ' "Example/Upstream": {"workflow": "ci.yml", "branch": "main"}}',   # case-folded duplicate
])
def test_malformed_declarations_are_rejected(value):
    with pytest.raises(ValueError):
        module().parse_sources(value)


@pytest.mark.parametrize("spec", [
    {"workflow": "other.yml", "branch": "main"},
    {"workflow": "pii-guard.yml", "branch": "develop"},
])
def test_builtin_kit_cannot_be_shadowed_by_a_declaration(spec):
    sync = module()
    with pytest.raises(ValueError, match="built-in"):
        sync.parse_sources(json.dumps({"daizedong/FLEET-GUARDS": spec}))
    with pytest.raises(ValueError, match="built-in"):
        sync.verified_tip("DaizeDong/fleet-guards", "", SYNTHETIC_TOKEN, spec)


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


def green_api(calls, tip):
    def api(path, token, **kwargs):
        calls.append(path)
        if "/actions/workflows/" in path:
            return {"workflow_runs": [{"head_sha": tip, "event": "push", "status": "completed",
                                       "conclusion": "success"}]}
        return {"sha": tip}
    return api


def test_verified_tip_uses_declared_branch_and_workflow(monkeypatch):
    sync = module()
    calls = []
    tip = "c" * 40
    monkeypatch.setattr(sync, "api", green_api(calls, tip))
    spec = sync.parse_sources(DECLARED)["example/upstream"]
    assert sync.verified_tip("example/upstream", tip, SYNTHETIC_TOKEN, spec) == tip
    assert calls[0] == "repos/example/upstream/commits/master"
    assert calls[1].startswith("repos/example/upstream/actions/workflows/ci.yml/runs?")
    assert "branch=master" in calls[1] and "event=push" in calls[1]


def test_verified_tip_requires_a_declaration_for_a_non_builtin(monkeypatch):
    sync = module()
    calls = []
    monkeypatch.setattr(sync, "api", green_api(calls, "c" * 40))
    with pytest.raises(ValueError):
        sync.verified_tip("example/upstream", "", SYNTHETIC_TOKEN)
    assert not calls


def test_declared_upstream_obsolete_notification_is_a_noop(monkeypatch):
    sync = module()
    monkeypatch.setattr(sync, "api", lambda *a, **k: {"sha": "b" * 40})
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
    assert calls[0] == "repos/example/upstream/commits/master"
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


class _Stop(Exception):
    pass


@pytest.fixture
def recorded_consumer(tmp_path, monkeypatch):
    """A consumer whose git and GitHub API are recorded; stops right after the upstream fetch."""
    sync = module()
    (tmp_path / ".gitmodules").write_text(GITMODULES_DECLARED % "master", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
    old, new = "a" * 40, "c" * 40
    calls = []
    api_calls = []
    monkeypatch.setattr(sync, "api", green_api(api_calls, new))

    def run(argv, **kwargs):
        calls.append((list(argv), kwargs.get("env")))
        if argv[1:3] == ["status", "--porcelain"]:
            out = ""
        elif argv[1:3] == ["ls-files", "--stage"]:
            out = "160000 %s 0\t%s\n" % (old, argv[-1])
        elif "merge-base" in argv:
            raise _Stop()
        else:
            out = ""
        return subprocess.CompletedProcess(argv, 0, out, None)

    monkeypatch.setattr(sync.subprocess, "run", run)
    return sync, calls, api_calls


def test_declared_master_upstream_is_fetched_from_refs_heads_master(recorded_consumer, capsys):
    sync, calls, api_calls = recorded_consumer
    with pytest.raises(_Stop):
        sync.update_consumer("example/upstream", "", SYNTHETIC_TOKEN,
                             sources=sync.parse_sources(DECLARED))
    fetch = [argv for argv, _env in calls if "fetch" in argv]
    assert fetch == [["git", "-C", "vendor/upstream", "fetch", "https://github.com/example/upstream.git",
                      "refs/heads/master"]]
    assert api_calls[0] == "repos/example/upstream/commits/master"
    # The only fleet-guards module is never touched by an example/upstream notification.
    assert not any("guards" in argv for argv, _env in calls)
    capsys.readouterr()


def test_upstream_credential_never_reaches_argv_url_or_output(recorded_consumer, capsys):
    import base64
    sync, calls, _api_calls = recorded_consumer
    with pytest.raises(_Stop):
        sync.update_consumer("all", "", SYNTHETIC_TOKEN, sources=sync.parse_sources(DECLARED))
    encoded = base64.b64encode(("x-access-token:" + SYNTHETIC_TOKEN).encode()).decode()
    out = capsys.readouterr()
    for argv, _env in calls:
        assert not any(SYNTHETIC_TOKEN in arg or encoded in arg for arg in argv)
    assert SYNTHETIC_TOKEN not in out.out + out.err and encoded not in out.out + out.err
    networked = [env for argv, env in calls if "fetch" in argv or "submodule" in argv]
    assert len(networked) == 2
    for env in networked:
        assert SYNTHETIC_TOKEN not in json.dumps(env)        # only the header form, only in env
        count = int(env["GIT_CONFIG_COUNT"])
        pairs = [(env["GIT_CONFIG_KEY_%d" % i], env["GIT_CONFIG_VALUE_%d" % i]) for i in range(count)]
        assert pairs[0] == ("http.https://github.com/.extraheader", "")   # resets persisted headers
        assert pairs[1] == ("http.https://github.com/.extraheader", "AUTHORIZATION: basic " + encoded)
    # Local, non-network commands carry no credential at all.
    assert all(env is None for argv, env in calls if "fetch" not in argv and "submodule" not in argv)


def test_failed_fetch_error_text_does_not_contain_the_credential(recorded_consumer, monkeypatch):
    sync, calls, _api_calls = recorded_consumer

    def failing(argv, **kwargs):
        if "fetch" in argv:
            raise subprocess.CalledProcessError(128, argv)
        if argv[1:3] == ["ls-files", "--stage"]:
            return subprocess.CompletedProcess(argv, 0, "160000 %s 0\t%s\n" % ("a" * 40, argv[-1]), None)
        return subprocess.CompletedProcess(argv, 0, "", None)

    monkeypatch.setattr(sync.subprocess, "run", failing)
    with pytest.raises(subprocess.CalledProcessError) as error:
        sync.update_consumer("example/upstream", "", SYNTHETIC_TOKEN, sources=sync.parse_sources(DECLARED))
    assert SYNTHETIC_TOKEN not in str(error.value)
    assert "x-access-token" not in str(error.value)


def test_unknown_payload_source_is_rejected_before_any_git_or_api(recorded_consumer):
    sync, calls, api_calls = recorded_consumer
    with pytest.raises(ValueError, match="Unknown upstream"):
        sync.update_consumer("example/undeclared", "", SYNTHETIC_TOKEN, sources=sync.parse_sources(DECLARED))
    assert not calls and not api_calls


def test_auth_env_appends_after_existing_entries_and_persists_nothing(tmp_path):
    sync = module()
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True, **_no_window())
    base = dict(os.environ, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.abbrev", GIT_CONFIG_VALUE_0="12")
    env = sync.github_auth_env(SYNTHETIC_TOKEN, base)
    assert env["GIT_CONFIG_KEY_0"] == "core.abbrev" and env["GIT_CONFIG_COUNT"] == "4"
    shown = subprocess.run(["git", "-C", str(tmp_path), "config", "--show-origin", "--get-all",
                            "http.https://github.com/.extraheader"], check=True, text=True,
                           stdout=subprocess.PIPE, **_no_window(env=env)).stdout
    assert "command line:" in shown and "AUTHORIZATION: basic" in shown
    assert "AUTHORIZATION" not in (tmp_path / ".git" / "config").read_text(encoding="utf-8")
    for bad in ("", "   ", None):
        with pytest.raises(RuntimeError):
            sync.github_auth_env(bad, base)
