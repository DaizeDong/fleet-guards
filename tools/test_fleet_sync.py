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
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / ".githooks"
    directory.mkdir()
    for name in ("pre-commit", "pre-push"):
        path = directory / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        subprocess.run(["git", "add", "--chmod=+x", str(path)], check=True)
    return directory


def test_executable_tracked_hooks_are_accepted(hook_checkout):
    module().require_hooks()


def test_missing_hook_is_rejected(hook_checkout):
    (hook_checkout / "pre-push").unlink()
    with pytest.raises(RuntimeError, match="shim"):
        module().require_hooks()


def test_hook_without_executable_git_mode_is_rejected(hook_checkout):
    subprocess.run(["git", "update-index", "--chmod=-x", ".githooks/pre-commit"], check=True)
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
    assert observed == [{"refresh_visibility": opt_in}]


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
