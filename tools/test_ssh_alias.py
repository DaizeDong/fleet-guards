"""Generated alias admission controls; every subprocess boundary stays mocked."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import stat

import pytest

import data_boundary as boundary
from make_fixtures import ssh_alias_cases, ssh_alias_route_cases, write_ssh_alias_case, write_visibility, make_ssh_layout
from make_fixtures import ssh_parser_boundary_cases, write_git_ssh_selection_case
from make_fixtures import ssh_execution_environment_cases
from make_fixtures import git_ssh_launcher_cases


@pytest.mark.parametrize("case", ssh_alias_cases(), ids=lambda case: case["id"])
def test_alias_configuration_requires_each_plausible_chain(tmp_path, monkeypatch, case):
    paths, chains = write_ssh_alias_case(tmp_path / "generated", case)
    monkeypatch.setattr(boundary, "_ssh_config_paths", lambda: paths)
    monkeypatch.setattr(boundary, "_ssh_config_sources", lambda: {"paths": paths, "chains": chains})
    assert (boundary._ssh_configuration_problem(case["host"]) is None) is case["allowed"]


@pytest.mark.parametrize("client", ["system", "git"])
@pytest.mark.parametrize("same_home", [False, True])
def test_alias_discovery_binds_selected_system_and_deduplicates_homes(tmp_path, monkeypatch, client, same_home):
    import os
    import shutil
    layout = make_ssh_layout(tmp_path / "generated-layout")
    home = layout["account-home"]
    for key, value in (("HOME", home if same_home else layout["environment-home"]),
                       ("USERPROFILE", home if same_home else layout["userprofile"]),
                       ("SystemRoot", layout["windows"]), ("ProgramData", layout["program-data"])):
        monkeypatch.setenv(key, str(value))
    monkeypatch.setattr(boundary, "_ssh_profile_home", lambda: str(home))
    monkeypatch.setattr(os.path, "expanduser", lambda value: str(home if same_home else layout["expanded-home"]))
    system_client = str(layout["windows"] / "System32/OpenSSH/ssh.exe") if os.name == "nt" else "/usr/bin/ssh"
    selected = system_client if client == "system" else str(layout["git-installation"] / "usr/bin/ssh.exe")
    monkeypatch.setattr(shutil, "which", lambda command: selected if command == "ssh" else str(layout["git-installation"] / "cmd/git.exe"))
    result = boundary._ssh_config_sources()
    if client == "git" and os.name != "nt":
        assert result is None
        return
    expected_system = (str(layout["program-data"] / "ssh/ssh_config") if client == "system"
                       else str(layout["git-installation"] / "etc/ssh/ssh_config")) if os.name == "nt" else "/etc/ssh/ssh_config"
    assert {chain[1] for chain in result["chains"]} == {expected_system}
    assert len(result["chains"]) == (1 if same_home else 4)
    assert all(name in result["paths"] for chain in result["chains"] for name in chain)


@pytest.mark.parametrize("alias_kind", ["symlink", "reparse", "hardlink"])
def test_alias_configuration_topology_fails_before_payload(tmp_path, monkeypatch, alias_kind):
    case = next(case for case in ssh_alias_cases() if case["id"] == "alias-explicit")
    paths, chains = write_ssh_alias_case(tmp_path / "generated", case)
    monkeypatch.setattr(boundary, "_ssh_config_paths", lambda: paths)
    monkeypatch.setattr(boundary, "_ssh_config_sources", lambda: {"paths": paths, "chains": chains})
    original_stat, original_read = Path.lstat, Path.read_bytes
    def topology(path):
        if str(path) == paths[0]:
            return SimpleNamespace(st_mode=stat.S_IFLNK if alias_kind == "symlink" else stat.S_IFREG,
                                   st_nlink=2 if alias_kind == "hardlink" else 1,
                                   st_file_attributes=1024 if alias_kind == "reparse" else 0)
        return original_stat(path)
    def unread(path):
        assert str(path) != paths[0], "Rejected alias configuration payload was read"
        return original_read(path)
    monkeypatch.setattr(Path, "lstat", topology)
    monkeypatch.setattr(Path, "read_bytes", unread)
    assert "filesystem alias" in boundary._ssh_configuration_problem(case["host"])


@pytest.mark.parametrize("case", ssh_alias_route_cases(), ids=lambda case: case["id"])
def test_every_ssh_host_is_attested_for_fetch_and_push(tmp_path, monkeypatch, case):
    visibility = write_visibility(tmp_path / "visibility.json",
                                  {"example-owner/demo-config": case["visibility"]},
                                  datetime.now(timezone.utc).isoformat())
    checked, queries = [], []
    def attest(host):
        checked.append(host)
        return "synthetic blocked host" if host in case["blocked_hosts"] else None
    def query(command, cwd, env=None):
        queries.append(command)
        if command == ["git", "remote"]:
            return "origin"
        if command == ["git", "config", "--null", "--list"]:
            return ""
        if command[:3] == ["git", "remote", "get-url"]:
            return "\n".join(case["push"] if "--push" in command else case["fetch"])
        pytest.fail("Unexpected process request")
    monkeypatch.setattr(boundary, "_ssh_configuration_problem", attest)
    monkeypatch.setattr(boundary, "_run", query)
    proven, errors = boundary._companion_visibility_once(str(tmp_path), str(visibility), {})
    assert (not errors) is case["allowed"]
    assert checked == case["hosts"]
    assert len([command for command in queries if command[:3] == ["git", "remote", "get-url"]]) == 2
    if case["allowed"]:
        assert proven == ["example-owner/demo-config"]


@pytest.mark.parametrize("case", ssh_parser_boundary_cases(), ids=lambda case: case["id"])
def test_ssh_control_bytes_cannot_hide_active_directives(tmp_path, monkeypatch, case):
    paths, chains = write_ssh_alias_case(tmp_path / "generated", {
        "configs": [case["content"], None], "chains": [[0, 1]]})
    monkeypatch.setattr(boundary, "_ssh_config_paths", lambda: paths)
    monkeypatch.setattr(boundary, "_ssh_config_sources", lambda: {"paths": paths, "chains": chains})
    assert boundary._ssh_configuration_problem(case["host"]) is not None


@pytest.mark.parametrize("location,allowed", [("system", False), ("bundled", True), ("both", True), ("neither", False)])
@pytest.mark.parametrize("path_ssh", [True, False])
@pytest.mark.parametrize("launcher", git_ssh_launcher_cases())
def test_git_bundled_ssh_uses_its_own_system_configuration(tmp_path, monkeypatch, location, allowed, path_ssh, launcher):
    import os
    import shutil
    layout = write_git_ssh_selection_case(tmp_path / "generated-client", location, launcher)
    environment = SimpleNamespace(**vars(os))
    environment.name = "nt"
    monkeypatch.setattr(boundary, "os", environment)
    home = str(layout["account-home"])
    environment.environ = dict(HOME=home, USERPROFILE=home, SystemRoot=str(layout["windows"]),
                               ProgramData=str(layout["program-data"]))
    monkeypatch.setattr(boundary, "_ssh_profile_home", lambda: home)
    monkeypatch.setattr(os.path, "expanduser", lambda value: home)
    selected = {"ssh": str(layout["windows"] / "System32/OpenSSH/ssh.exe") if path_ssh else None,
                "git": str(layout["git-executable"])}
    monkeypatch.setattr(shutil, "which", lambda command: selected[command])
    sources = boundary._ssh_config_sources()
    assert {chain[1] for chain in sources["chains"]} == {str(layout["git-installation"] / "etc/ssh/ssh_config")}
    assert (boundary._ssh_configuration_problem("synthetic-alias") is None) is allowed


@pytest.mark.parametrize("case", ssh_execution_environment_cases())
def test_ssh_execution_environment_requires_default_tool_search(tmp_path, monkeypatch, case):
    visibility = write_visibility(tmp_path / "visibility.json", {"example-owner/demo-config": "PRIVATE"},
                                  datetime.now(timezone.utc).isoformat())
    def query(command, cwd, env=None):
        if command == ["git", "remote"]:
            return "origin"
        if command == ["git", "config", "--null", "--list"]:
            return ""
        if command[:3] == ["git", "remote", "get-url"]:
            return case["url"]
        pytest.fail("Unexpected process request")
    monkeypatch.setattr(boundary, "_run", query)
    monkeypatch.setattr(boundary, "_ssh_configuration_problem", lambda host: None)
    proven, errors = boundary._companion_visibility_once(str(tmp_path), str(visibility), case["env"])
    assert (not errors) is case["allowed"]
    assert bool(proven) is case["allowed"]
