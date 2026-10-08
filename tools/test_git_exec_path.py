"""Native hook helper paths must not weaken SSH or HTTPS transport admission."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

import data_boundary as boundary
import pii_guard as guard
from make_fixtures import (
    make_hook_helper_path_fixture, make_native_hook_exec_path_fixture,
    native_hook_transport_overrides,
)


@pytest.mark.parametrize("transport", ["ssh", "https"])
@pytest.mark.parametrize("selected", ["native", "custom"])
def test_real_git_hook_exec_path_admission(tmp_path, transport, selected):
    fixture = make_native_hook_exec_path_fixture(
        tmp_path, Path(__file__).resolve().parents[1], transport, guard._utcnow())
    invoker = fixture["invoker"]
    environment = dict(invoker.env)
    assert not any(key.upper() == "GIT_EXEC_PATH" for key in environment)
    if selected == "custom":
        environment["GIT_EXEC_PATH"] = str(fixture["custom"])
    invoker.git("commit", "--allow-empty", "-qm", "Synthetic native hook probe", env=environment)
    result = json.loads(fixture["report"].read_text(encoding="utf-8"))
    assert result["exec_path_present"] and result["environment_preserved"]
    assert result["allowed"] is (selected == "native"), result
    if result["allowed"]:
        assert result["repositories"] == ["example-owner/synthetic-private"]
    else:
        assert "UNKNOWN" in result["error"]


@pytest.mark.parametrize("transport,layer,key,value", native_hook_transport_overrides())
def test_native_hook_path_does_not_hide_other_overrides(tmp_path, transport, layer, key, value):
    fixture = make_native_hook_exec_path_fixture(
        tmp_path, Path(__file__).resolve().parents[1], transport, guard._utcnow())
    invoker = fixture["invoker"]
    environment = dict(invoker.env)
    if layer == "env":
        environment[key] = value
    else:
        fixture["companion"].git("config", key, value)
    invoker.git("commit", "--allow-empty", "-qm", "Synthetic transport override probe", env=environment)
    result = json.loads(fixture["report"].read_text(encoding="utf-8"))
    assert result["exec_path_present"] and result["environment_preserved"]
    assert result["allowed"] is False and "UNKNOWN" in result["error"]


@pytest.mark.parametrize("failure", [
    "none", "custom", "empty", "relative", "duplicate", "missing-directory",
    "missing-git", "launch", "timeout", "status", "empty-probe", "multiline-probe", "relative-probe",
    "different-identity", "identity-error",
])
def test_native_helper_probe_fails_closed(tmp_path, monkeypatch, failure):
    fixture = make_hook_helper_path_fixture(tmp_path, "canonical")
    environment = {"GIT_EXEC_PATH": str(fixture["actual"]), "PATH": str(fixture["executable"].parent)}
    if failure == "custom":
        environment["GIT_EXEC_PATH"] = str(tmp_path)
    elif failure in {"empty", "relative"}:
        environment["GIT_EXEC_PATH"] = "" if failure == "empty" else "synthetic-relative"
    elif failure == "duplicate":
        environment["git_exec_path"] = str(fixture["actual"])
    elif failure == "missing-directory":
        environment["GIT_EXEC_PATH"] = str(tmp_path / "missing")
    original = dict(environment)
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs:
                        None if failure == "missing-git" else str(fixture["executable"]))
    calls = []

    def probe(command, **kwargs):
        calls.append(command)
        assert command == [str(fixture["executable"]), "--exec-path"]
        assert not any(key.upper() == "GIT_EXEC_PATH" for key in kwargs["env"])
        assert kwargs["timeout"] == 5
        if failure == "launch":
            raise OSError("Synthetic launch failure")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 5)
        output = {"empty-probe": "", "multiline-probe": str(fixture["default"]) + "\nextra\n",
                  "relative-probe": "synthetic-relative"}.get(failure, str(fixture["default"]) + "\n")
        return subprocess.CompletedProcess(command, 1 if failure == "status" else 0, output, "")

    monkeypatch.setattr(boundary.subprocess, "run", probe)
    if failure == "different-identity":
        # Model distinct NTFS directory identities despite equal normalized spelling.
        monkeypatch.setattr(boundary.os.path, "samefile", lambda *paths: False)
    elif failure == "identity-error":
        def failed_identity(*paths):
            raise OSError("Synthetic directory identity failure")
        monkeypatch.setattr(boundary.os.path, "samefile", failed_identity)
    assert (boundary._git_exec_path_problem(environment) is None) is (failure == "none")
    assert environment == original
    assert bool(calls) is (failure not in {"empty", "relative", "duplicate", "missing-directory", "missing-git"})


@pytest.mark.parametrize("kind", ["helper", "default-parent", "executable-parent"])
def test_native_helper_probe_rejects_filesystem_aliases(tmp_path, monkeypatch, kind):
    fixture = make_hook_helper_path_fixture(tmp_path, kind)
    monkeypatch.setattr(shutil, "which", lambda *args, **kwargs: str(fixture["executable"]))
    monkeypatch.setattr(boundary.subprocess, "run", lambda command, **kwargs:
                        subprocess.CompletedProcess(command, 0, str(fixture["default"]), ""))
    assert boundary._git_exec_path_problem({"GIT_EXEC_PATH": str(fixture["actual"])}) is not None


def test_absent_helper_override_needs_no_probe(monkeypatch):
    monkeypatch.setattr(boundary.subprocess, "run", lambda *args, **kwargs: pytest.fail("Unexpected probe"))
    assert boundary._git_exec_path_problem({}) is None
