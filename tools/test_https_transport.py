"""HTTPS companion admission must prove transport before inspecting DATA."""
from datetime import datetime, timezone
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import data_boundary as boundary
from make_fixtures import https_transport_cases, write_visibility


@pytest.mark.parametrize("entrypoint", ["visibility", "companion"])
@pytest.mark.parametrize("layer", ["physical", "effective"])
@pytest.mark.parametrize("case", https_transport_cases(), ids=lambda case: case["id"])
def test_https_transport_precedes_private_admission(tmp_path, monkeypatch, capsys, case, layer, entrypoint):
    root = tmp_path / "synthetic-companion"
    root.mkdir()
    visibility = write_visibility(tmp_path / "visibility.json",
                                  {"example-owner/demo-config": "PRIVATE"}, datetime.now(timezone.utc).isoformat())
    environment = SimpleNamespace(**vars(os))
    environment.environ = dict(case["env"])
    monkeypatch.setattr(boundary, "os", environment)
    observed = []

    def synthetic_git(command, cwd, env=None, **kwargs):
        assert Path(cwd) == root
        assert not kwargs
        observed.append(command)
        if command == ["git", "rev-parse", "--show-toplevel"]:
            return str(root)
        if command == ["git", "rev-parse", "--absolute-git-dir"]:
            return str(root / ".git")
        if command == ["git", "config", "--null", "--list"]:
            config = [("remote.origin.url", "https://github.com/example-owner/demo-config.git")]
            if layer == "physical" or env.get("GIT_CONFIG_NOSYSTEM") != "1":
                config.extend(case["config"])
            return "".join(key + "\n" + value + "\0" for key, value in config)
        if command == ["git", "remote"]:
            return "origin\n"
        if command in (["git", "remote", "get-url", "--all", "origin"],
                        ["git", "remote", "get-url", "--push", "--all", "origin"]):
            return "https://github.com/example-owner/demo-config.git\n"
        if command in (["git", "status", "--porcelain", "--untracked-files=all", "-z"],
                        ["git", "ls-files", "-z"]):
            return ""
        pytest.fail("Unexpected synthetic Git operation")

    monkeypatch.setattr(boundary, "_run", synthetic_git)
    if entrypoint == "visibility":
        destinations, errors = boundary._companion_visibility(str(root), str(visibility))
        assert bool(errors) == case["blocked"]
        assert destinations == ([] if case["blocked"] else ["example-owner/demo-config"])
    else:
        result = boundary.check_companion(str(root), 10, str(visibility))
        assert result == (1 if case["blocked"] else 0)
        output = capsys.readouterr()
        assert ("PRIVATE verified" in output.out) is not case["blocked"]
        if case["blocked"]:
            assert "VISIBILITY BLOCKED" in output.err
            assert not any(command[1] in {"status", "ls-files"} for command in observed)


def test_https_policy_does_not_replace_ssh_proof(tmp_path, monkeypatch):
    visibility = write_visibility(tmp_path / "visibility.json",
                                  {"example-owner/demo-config": "PRIVATE"}, datetime.now(timezone.utc).isoformat())
    commands = []

    def synthetic_git(command, cwd, env=None):
        commands.append(command)
        if command == ["git", "remote"]:
            return "origin\n"
        if command == ["git", "config", "--null", "--list"]:
            return "http.sslverify\nfalse\0"
        if command[:3] == ["git", "remote", "get-url"]:
            return "git@github.com:example-owner/demo-config.git\n"
        pytest.fail("Unexpected synthetic SSH proof operation")

    monkeypatch.setattr(boundary, "_run", synthetic_git)
    monkeypatch.setattr(boundary, "_ssh_configuration_problem", lambda host="github.com": None)
    destinations, errors = boundary._companion_visibility_once(str(tmp_path), str(visibility), {})
    assert errors == []
    assert destinations == ["example-owner/demo-config"]
    assert commands
