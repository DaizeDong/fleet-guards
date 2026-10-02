"""SSH admission must preserve server authentication before approving private DATA."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

import data_boundary as boundary
from make_fixtures import ssh_trust_cases, write_ssh_trust_case, write_visibility


@pytest.mark.parametrize("entrypoint", ["policy", "companion"])
@pytest.mark.parametrize("case", ssh_trust_cases(), ids=lambda case: case["id"])
def test_ssh_trust_precedes_private_admission(tmp_path, monkeypatch, capsys, case, entrypoint):
    configurations = write_ssh_trust_case(tmp_path, case)
    monkeypatch.setattr(boundary, "_ssh_config_paths", lambda: configurations)
    if entrypoint == "policy":
        assert bool(boundary._ssh_configuration_problem()) == case["blocked"]
        return

    root = tmp_path / "synthetic-companion"
    root.mkdir()
    visibility = write_visibility(tmp_path / "visibility.json",
                                  {"example-owner/demo-config": "PRIVATE"},
                                  datetime.now(timezone.utc).isoformat())
    monkeypatch.setattr(boundary, "_companion_git_context", lambda destination: (str(root), {}, {}))
    commands = []

    def synthetic_git(command, cwd, env=None):
        assert Path(cwd) == root
        commands.append(command)
        if command == ["git", "config", "--null", "--list"]:
            return "remote.origin.url\ngit@github.com:example-owner/demo-config.git\0"
        if command == ["git", "remote"]:
            return "origin\n"
        if command in (["git", "remote", "get-url", "--all", "origin"],
                       ["git", "remote", "get-url", "--push", "--all", "origin"]):
            return "git@github.com:example-owner/demo-config.git\n"
        if command in (["git", "status", "--porcelain", "--untracked-files=all", "-z"],
                       ["git", "ls-files", "-z"]):
            return ""
        pytest.fail("Unexpected synthetic Git operation")

    monkeypatch.setattr(boundary, "_run", synthetic_git)
    assert boundary.check_companion(str(root), 10, str(visibility)) == (1 if case["blocked"] else 0)
    output = capsys.readouterr()
    assert ("PRIVATE verified" in output.out) is not case["blocked"]
    if case["blocked"]:
        assert "VISIBILITY BLOCKED" in output.err
        assert not any(command[1] in {"status", "ls-files"} for command in commands)
