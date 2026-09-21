"""Synchronization must fail visibly and only move the selected submodule."""
import importlib.util
from pathlib import Path

import pytest


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
