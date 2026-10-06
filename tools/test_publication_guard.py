"""Native policy controls use only generator-owned synthetic repositories."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

import data_boundary as boundary
import publication_guard as publication
from make_fixtures import _no_window
from make_fixtures import make_publication_fixture, publication_metadata_cases
from make_fixtures import publication_metadata_environment_cases, publication_invalid_metadata_targets
from make_fixtures import publication_changed_response_urls
from test_git_context import git_environment


SOURCE = Path(__file__).resolve().parent.parent


def invoke(fixture, phase, destination=None):
    repo = fixture["repo"]
    if phase == "ci":
        command = [sys.executable, str(fixture["kit"] / "tools/publication_guard.py"), phase]
    else:
        command = ["git", "hook", "run", phase]
        if phase == "pre-push":
            command += ["--", "origin", destination or fixture["url"]]
    return subprocess.run(command, cwd=repo.root, env=repo.env, input="",
                          capture_output=True, text=True, encoding="utf-8", **_no_window())


@pytest.mark.parametrize("phase", ["pre-commit", "pre-push", "ci"])
def test_verified_private_native_policy_permits_data_and_linkage(tmp_path, phase):
    fixture = make_publication_fixture(tmp_path, SOURCE, defect="data")
    result = invoke(fixture, phase)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "PRIVATE verified: example-owner/synthetic-tool" in output
    assert "PRIVATE structural checks passed" in output
    assert "pii_guard: clean" not in output


@pytest.mark.parametrize("state", ["PUBLIC", "UNKNOWN"])
@pytest.mark.parametrize("phase", ["pre-commit", "pre-push", "ci"])
def test_unproven_scope_keeps_full_public_scans(tmp_path, state, phase):
    fixture = make_publication_fixture(tmp_path, SOURCE, state=state)
    result = invoke(fixture, phase)
    assert result.returncode != 0
    assert "CROSS-REPO" in result.stdout + result.stderr
    assert "PRIVATE verified:" not in result.stdout + result.stderr


@pytest.mark.parametrize("refreshed", ["2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"])
def test_private_receipt_must_be_fresh(tmp_path, refreshed):
    fixture = make_publication_fixture(tmp_path, SOURCE, refreshed=refreshed)
    result = invoke(fixture, "pre-commit")
    assert result.returncode != 0
    assert "PRIVATE verified:" not in result.stdout + result.stderr


@pytest.mark.parametrize("defect", ["missing-manifest", "declaration", "fixture", "sealed"])
def test_private_scope_retains_structural_controls(tmp_path, defect):
    fixture = make_publication_fixture(tmp_path, SOURCE, defect=defect)
    result = invoke(fixture, "pre-commit")
    assert result.returncode != 0
    assert "PRIVATE verified:" in result.stdout + result.stderr
    assert "PRIVATE structural checks passed" not in result.stdout + result.stderr


def test_private_scope_preserves_identity_assertion(tmp_path):
    fixture = make_publication_fixture(tmp_path, SOURCE)
    fixture["repo"].git("config", "user.name", "Different Fixture")
    result = invoke(fixture, "pre-commit")
    assert result.returncode != 0
    assert "IDENTITY MISMATCH" in result.stdout + result.stderr
    assert "PRIVATE verified:" not in result.stdout + result.stderr


@pytest.mark.parametrize("route", ["configured-public", "explicit-unconfigured"])
def test_private_push_cannot_publish_through_unproved_routes(tmp_path, route):
    fixture = make_publication_fixture(tmp_path, SOURCE)
    if route == "configured-public":
        fixture["repo"].git("config", "remote.origin.pushurl", fixture["public_url"])
    result = invoke(fixture, "pre-push", fixture["public_url"])
    assert result.returncode != 0
    assert "CROSS-REPO" in result.stdout + result.stderr


def test_explicit_raw_scanners_remain_public_diagnostics(tmp_path):
    fixture = make_publication_fixture(tmp_path, SOURCE, defect="data")
    for scanner, options, finding in (("pii_guard.py", ["--tree"], "CROSS-REPO"),
                                      ("data_boundary.py", [], "DATA-TRACKED")):
        result = subprocess.run([sys.executable, str(fixture["kit"] / "tools" / scanner), *options],
                                cwd=fixture["repo"].root, env=fixture["repo"].env,
                                capture_output=True, text=True, **_no_window())
        assert result.returncode == 1
        assert finding in result.stdout + result.stderr


@pytest.mark.parametrize("state", ["PRIVATE", "PUBLIC", "UNKNOWN"])
def test_ci_metadata_uses_same_all_destination_proof(tmp_path, monkeypatch, state):
    fixture = make_publication_fixture(tmp_path, SOURCE, state="UNKNOWN")
    observed = []
    with git_environment(monkeypatch, dict(fixture["repo"].env,
                                          GITHUB_ACTIONS="true", GITHUB_TOKEN=fixture["token"])):
        def metadata(repository, token):
            observed.append((repository, token))
            return state
        monkeypatch.setattr(publication, "github_visibility", metadata)
        proof = publication.private_proof(boundary, str(fixture["repo"].root), "ci", "")
    assert (proof is not None) is (state == "PRIVATE")
    assert observed == [("example-owner/synthetic-tool", fixture["token"])]


def test_ci_missing_credential_cannot_use_private_local_receipt(tmp_path, monkeypatch):
    fixture = make_publication_fixture(tmp_path, SOURCE)
    with git_environment(monkeypatch, dict(fixture["repo"].env, GITHUB_ACTIONS="true")):
        assert publication.private_proof(boundary, str(fixture["repo"].root), "ci", "") is None


def test_ci_metadata_failure_stays_public(tmp_path, monkeypatch):
    fixture = make_publication_fixture(tmp_path, SOURCE)
    with git_environment(monkeypatch, dict(fixture["repo"].env,
                                          GITHUB_ACTIONS="true", GITHUB_TOKEN=fixture["token"])):
        def unavailable(repository, token):
            raise OSError("synthetic failure")
        monkeypatch.setattr(publication, "github_visibility", unavailable)
        assert publication.private_proof(boundary, str(fixture["repo"].root), "ci", "") is None


@pytest.mark.parametrize("repository,metadata,expected", publication_metadata_cases())
def test_ci_metadata_requires_matching_identity_and_private_state(monkeypatch, repository, metadata, expected):
    import io

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://api.github.com/repos/" + repository
            assert timeout == 15
            response = io.StringIO(json.dumps(metadata))
            response.geturl = lambda: request.full_url
            return response

    monkeypatch.setattr(publication.urllib.request, "build_opener", lambda *handlers: Opener())
    if expected is None:
        with pytest.raises(ValueError):
            publication.github_visibility(repository, "")
    else:
        assert publication.github_visibility(repository, "") == expected


def test_ci_metadata_never_follows_redirects():
    assert publication.NoRedirect().redirect_request(None, None, 302, "", {}, "") is None


@pytest.mark.parametrize("environment", publication_metadata_environment_cases())
def test_metadata_rejects_unproved_trust_before_credentials(monkeypatch, environment):
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(publication.urllib.request, "build_opener",
                        lambda *args: pytest.fail("metadata network client constructed"))
    repository, _metadata, _expected = publication_metadata_cases()[0]
    with pytest.raises(ValueError, match="environment is unproved"):
        publication.github_visibility(repository, "")


@pytest.mark.parametrize("repository", publication_invalid_metadata_targets())
def test_metadata_requires_exact_api_target_before_credentials(monkeypatch, repository):
    monkeypatch.setattr(publication.urllib.request, "build_opener",
                        lambda *args: pytest.fail("metadata network client constructed"))
    with pytest.raises(ValueError, match="canonical owner/name"):
        publication.github_visibility(repository, "")


@pytest.mark.parametrize("url", publication_changed_response_urls())
def test_metadata_rejects_changed_response_destination(monkeypatch, url):
    import io

    repository, metadata, _expected = publication_metadata_cases()[0]

    class Opener:
        def open(self, request, timeout):
            response = io.StringIO(json.dumps(metadata))
            response.geturl = lambda: url
            return response

    monkeypatch.setattr(publication.urllib.request, "build_opener", lambda *handlers: Opener())
    with pytest.raises(ValueError, match="response changed"):
        publication.github_visibility(repository, "")


@pytest.mark.parametrize("value", ["native", "unproved"])
@pytest.mark.parametrize("phase", ["pre-commit", "pre-push", "ci"])
def test_hook_only_normalizes_git_native_default(tmp_path, monkeypatch, value, phase):
    import os

    fixture = make_publication_fixture(tmp_path, SOURCE)
    environment = fixture["repo"].env
    native = subprocess.run(["git", "--exec-path"], env=environment, capture_output=True,
                            text=True, check=True, **_no_window()).stdout.strip()
    selected = native if value == "native" else fixture["unproved_exec"]
    with git_environment(monkeypatch, dict(environment, GIT_EXEC_PATH=selected)):
        with publication.native_hook_environment(phase):
            removed = "GIT_EXEC_PATH" not in os.environ
            assert removed is (value == "native" and phase != "ci")
        assert os.environ["GIT_EXEC_PATH"] == selected


def test_unresolved_git_cannot_normalize_helper_override(tmp_path, monkeypatch):
    import os

    fixture = make_publication_fixture(tmp_path, SOURCE)
    with git_environment(monkeypatch, dict(fixture["repo"].env, GIT_EXEC_PATH=fixture["unproved_exec"])):
        monkeypatch.setattr(publication.shutil, "which", lambda name: None)
        with publication.native_hook_environment("pre-commit"):
            assert os.environ["GIT_EXEC_PATH"] == fixture["unproved_exec"]


def test_checkout_authorization_header_is_private_compatible(tmp_path, monkeypatch):
    from make_fixtures import https_transport_cases

    fixture = make_publication_fixture(tmp_path, SOURCE)
    case = next(item for item in https_transport_cases() if item["id"] == "authorization-checkout")
    for key, value in case["config"]:
        fixture["repo"].git("config", "--add", key, value)
    with git_environment(monkeypatch, dict(fixture["repo"].env,
                                          GITHUB_ACTIONS="true", GITHUB_TOKEN=fixture["token"])):
        monkeypatch.setattr(publication, "github_visibility", lambda repository, token: "PRIVATE")
        assert publication.private_proof(boundary, str(fixture["repo"].root), "ci", "") is not None


def test_authorization_cannot_contain_nul():
    from make_fixtures import publication_nul_header

    assert boundary._https_configuration_problem([publication_nul_header()], {}) is not None


@pytest.mark.parametrize("state", ["missing", "empty"])
def test_native_hooks_require_scope_driver(tmp_path, state):
    fixture = make_publication_fixture(tmp_path, SOURCE)
    driver = fixture["kit"] / "tools/publication_guard.py"
    if state == "missing":
        driver.unlink()
    else:
        driver.write_bytes(b"")
    for phase in ("pre-commit", "pre-push"):
        result = invoke(fixture, phase)
        assert result.returncode != 0
        assert "publication_guard.py is missing or empty" in result.stdout + result.stderr


def test_private_scope_rejects_zero_tracked_input(tmp_path):
    fixture = make_publication_fixture(tmp_path, SOURCE)
    fixture["repo"].git("read-tree", "--empty")
    result = invoke(fixture, "pre-commit")
    assert result.returncode != 0
    assert "0 tracked files" in result.stdout + result.stderr


def test_private_scope_detects_configuration_change(tmp_path, monkeypatch):
    fixture = make_publication_fixture(tmp_path, SOURCE)
    original = boundary.prove_private_companion

    def changed(*args):
        proof = original(*args)
        fixture["repo"].git("config", "remote.origin.pushurl", fixture["public_url"])
        return proof

    with git_environment(monkeypatch, fixture["repo"].env):
        monkeypatch.setattr(boundary, "prove_private_companion", changed)
        assert publication.private_proof(boundary, str(fixture["repo"].root), "pre-commit", "") is None


def test_private_scope_rechecks_visibility_after_structural_checks(tmp_path, monkeypatch):
    from make_fixtures import write_visibility
    from pii_guard import _utcnow

    fixture = make_publication_fixture(tmp_path, SOURCE)
    original = boundary.main

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        write_visibility(fixture["receipt"], {"example-owner/synthetic-tool": "PUBLIC"}, _utcnow())
        return result

    with git_environment(monkeypatch, fixture["repo"].env):
        monkeypatch.setattr(boundary, "main", changed)
        monkeypatch.setattr(sys, "argv", [publication.__file__, "pre-commit", "--repo", str(fixture["repo"].root)])
        assert publication.main() == 2


@pytest.mark.parametrize("kind", ["canonical", "helper", "default-parent", "executable-parent"])
def test_native_helper_normalization_rejects_mutable_aliases(tmp_path, monkeypatch, kind):
    import os
    from make_fixtures import make_hook_helper_path_fixture

    fixture = make_hook_helper_path_fixture(tmp_path, kind)
    monkeypatch.setenv("GIT_EXEC_PATH", str(fixture["actual"]))
    monkeypatch.setattr(publication.shutil, "which", lambda name: str(fixture["executable"]))
    calls = []

    def query(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, str(fixture["default"]), "")

    monkeypatch.setattr(publication.subprocess, "run", query)
    with publication.native_hook_environment("pre-commit"):
        removed = "GIT_EXEC_PATH" not in os.environ
        assert removed is (kind == "canonical")
    assert os.environ["GIT_EXEC_PATH"] == str(fixture["actual"])
    assert bool(calls) is (kind != "executable-parent")
