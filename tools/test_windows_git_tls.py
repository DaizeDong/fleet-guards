"""Ordinary Git for Windows TLS defaults must not block PRIVATE companion proof."""
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace

import pytest

import data_boundary as boundary
from make_fixtures import _no_window
from make_fixtures import (write_visibility, write_windows_git_tls_fixture, windows_git_tls_cases,
                           make_native_git_tls_companion, make_native_git_tls_selector_case)
from make_fixtures import git_ssh_launcher_cases, invalid_windows_git_launchers


@pytest.mark.parametrize("case_id", range(15))
def test_windows_tls_defaults_and_overrides(tmp_path, monkeypatch, case_id):
    fixture = write_windows_git_tls_fixture(tmp_path)
    case = windows_git_tls_cases(fixture)[case_id]
    environment = SimpleNamespace(**vars(os))
    environment.name = "nt"
    monkeypatch.setattr(boundary, "os", environment)
    monkeypatch.setattr(shutil, "which", lambda command, **kwargs: str(fixture["executable"]))
    assert (boundary._https_configuration_problem(case["config"], case["env"]) is None) is case["allowed"], case["id"]


@pytest.mark.parametrize("kind", ["missing", "symlink", "reparse", "hardlink", "directory"])
def test_windows_package_trust_requires_regular_unaliased_bundle(tmp_path, monkeypatch, kind):
    fixture = write_windows_git_tls_fixture(tmp_path)
    environment = SimpleNamespace(**vars(os))
    environment.name = "nt"
    monkeypatch.setattr(boundary, "os", environment)
    monkeypatch.setattr(shutil, "which", lambda command, **kwargs: str(fixture["executable"]))
    original = Path.lstat
    def topology(path):
        if path == fixture["bundle"]:
            if kind == "missing":
                raise FileNotFoundError
            return SimpleNamespace(st_mode=stat.S_IFLNK if kind == "symlink" else
                                   stat.S_IFDIR if kind == "directory" else stat.S_IFREG,
                                   st_nlink=2 if kind == "hardlink" else 1,
                                   st_file_attributes=1024 if kind == "reparse" else 0)
        return original(path)
    monkeypatch.setattr(Path, "lstat", topology)
    assert boundary._https_configuration_problem(fixture["config"], {}) is not None


def test_windows_packaged_git_launcher_can_be_hardlinked(tmp_path, monkeypatch):
    fixture = write_windows_git_tls_fixture(tmp_path)
    environment = SimpleNamespace(**vars(os))
    environment.name = "nt"
    monkeypatch.setattr(boundary, "os", environment)
    monkeypatch.setattr(shutil, "which", lambda command, **kwargs: str(fixture["executable"]))
    original = Path.lstat
    def topology(path):
        if path == fixture["executable"]:
            return SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=2, st_file_attributes=0)
        return original(path)
    monkeypatch.setattr(Path, "lstat", topology)
    assert boundary._https_configuration_problem(fixture["config"], {}) is None


@pytest.mark.parametrize("launcher", git_ssh_launcher_cases())
def test_windows_bundle_discovery_uses_native_launcher_layout(tmp_path, monkeypatch, launcher):
    fixture = write_windows_git_tls_fixture(tmp_path, launcher)
    environment = SimpleNamespace(**vars(os))
    environment.name = "nt"
    monkeypatch.setattr(boundary, "os", environment)
    monkeypatch.setattr(shutil, "which", lambda command, **kwargs: str(fixture["executable"]))
    assert boundary._https_configuration_problem(fixture["config"], {}) is None


def test_windows_package_discovery_rejects_unknown_layouts(tmp_path):
    for path in invalid_windows_git_launchers(tmp_path):
        assert boundary._git_windows_installation(path) is None


@pytest.mark.skipif(os.name != "nt", reason="Git for Windows package defaults")
def test_native_companion_proof_retains_installed_git_configuration(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("tls")
    fixture = make_native_git_tls_companion(tmp_path / "companion")
    root = fixture["root"]
    visibility = write_visibility(tmp_path / "visibility.json", fixture["visibility"],
                                  datetime.now(timezone.utc).isoformat())
    before = dict(os.environ)
    proven, errors = boundary._companion_visibility(str(root), str(visibility))
    assert errors == [], errors
    assert proven == ["example-owner/demo-config"]
    assert dict(os.environ) == before
    subprocess.run(["git", "-C", str(root), *fixture["disabled_verification"]],
                   env=fixture["env"], capture_output=True, text=True, check=True, **_no_window())
    proven, errors = boundary._companion_visibility(str(root), str(visibility))
    assert errors and proven == []


def test_native_companion_setup_cannot_mutate_hook_caller(tmp_path_factory, monkeypatch):
    case = make_native_git_tls_selector_case(tmp_path_factory.mktemp("tls") / "hook")
    decoy = case["decoy"]
    before = (decoy.root / ".git/config").read_bytes()
    for key, value in case["selectors"].items():
        monkeypatch.setenv(key, value)
    fixture = make_native_git_tls_companion(case["destination"])
    assert (decoy.root / ".git/config").read_bytes() == before
    assert (fixture["root"] / ".git").is_dir()
    assert decoy.git("remote") == ""
    assert not set(case["selectors"]) & set(fixture["env"])
    subprocess.run(["git", "-C", str(fixture["root"]), *fixture["disabled_verification"]],
                   env=fixture["env"], capture_output=True, text=True, check=True, **_no_window())
    assert (decoy.root / ".git/config").read_bytes() == before
