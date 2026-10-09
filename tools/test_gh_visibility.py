"""A live visibility answer must not depend on which gh account happens to be ACTIVE.

WHY THIS FILE EXISTS. On 2026-10-09 another session ran `gh auth switch` to an account that cannot
see a private companion. Every consumer that confirmed its receipt with a plain `gh repo view`
then failed closed until someone switched back. query_github_visibility asks with the owner's
stored account, then every other stored account, then gh's own default, and refuses only when no
credential can see the repository.

Every test runs a synthetic `gh` from tools/make_fixtures.py on a private PATH. It records each
call and which synthetic credential it carried, so the tests can assert what was asked, with which
account, and that the active account was never changed or relied on.
"""
import os
from pathlib import Path
import subprocess

import pytest

import data_boundary as db
from make_fixtures import _no_window, gh_stub_calls, make_gh_cli_stub

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "example-owner/private-data"


def install(monkeypatch, stub):
    monkeypatch.setenv("PATH", str(stub["bin"]))
    for name in list(os.environ):
        if name.casefold() in {"gh_token", "github_token", "gh_enterprise_token",
                               "github_enterprise_token", "gh_host"}:
            monkeypatch.delenv(name)


def views(stub):
    return [call for call in gh_stub_calls(stub) if call["argv"][:2] == ["repo", "view"]]


def assert_no_token_leaked(stub, *texts):
    secrets = [*stub["tokens"].values(), *stub["ambient"].values()]
    for text in texts:
        for secret in secrets:
            assert secret not in text


def assert_active_account_untouched(stub):
    assert not [call for call in gh_stub_calls(stub) if call["argv"][:2] == ["auth", "switch"]]


def test_stub_reproduces_the_incident(tmp_path, monkeypatch):
    """Negative control: the old ambient query fails when the ACTIVE account cannot see the repo."""
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner", "other-account"], active="other-account",
                            sees={"example-owner": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    environment = dict(os.environ, GH_HOST="github.com")
    old = subprocess.run([str(stub["launcher"]), "repo", "view", REPOSITORY, "--json", "nameWithOwner,visibility"],
                         capture_output=True, text=True, env=environment, **_no_window())
    assert old.returncode != 0
    assert views(stub)[-1]["credential"] == "other-account"


def test_owner_account_answers_while_another_account_is_active(tmp_path, monkeypatch, capsys):
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner", "other-account"], active="other-account",
                            sees={"example-owner": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    assert db.query_github_visibility(REPOSITORY) == "PRIVATE"
    calls = gh_stub_calls(stub)
    assert calls[0]["argv"] == ["auth", "token", "--hostname", "github.com", "--user", "example-owner"]
    assert calls[0]["explicit"] is False
    assert [call["credential"] for call in views(stub)] == ["example-owner"]
    assert all(call["explicit"] and call["gh_host"] == "github.com" for call in views(stub))
    assert_active_account_untouched(stub)
    captured = capsys.readouterr()
    assert_no_token_leaked(stub, captured.out, captured.err)


def test_lowercase_owner_from_a_route_key_still_selects_the_owner(tmp_path, monkeypatch):
    """Publication routes are keyed in lower case; the stored login need not be."""
    stub = make_gh_cli_stub(tmp_path, accounts=["Example-Owner", "other-account"], active="other-account",
                            sees={"Example-Owner": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    assert db.query_github_visibility(REPOSITORY.lower()) == "PRIVATE"
    assert [call["credential"] for call in views(stub)] == ["Example-Owner"]


def test_any_stored_account_that_can_see_it_answers(tmp_path, monkeypatch):
    """An organization repository has no account named like its owner."""
    repository = "example-org/private-data"
    stub = make_gh_cli_stub(tmp_path, accounts=["first-account", "second-account"], active="first-account",
                            sees={"second-account": [repository]}, visibility={repository: "PRIVATE"})
    install(monkeypatch, stub)
    assert db.query_github_visibility(repository) == "PRIVATE"
    assert [call["credential"] for call in views(stub)] == ["first-account", "second-account"]
    assert_active_account_untouched(stub)


def test_an_unusable_owner_token_falls_through_to_other_accounts(tmp_path, monkeypatch):
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner", "member-account"], active="example-owner",
                            sees={"member-account": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"},
                            broken=["example-owner"], status_exit=1)
    install(monkeypatch, stub)
    assert db.query_github_visibility(REPOSITORY) == "PRIVATE"
    assert [call["credential"] for call in views(stub)] == ["member-account"]


def test_no_credential_can_see_it_still_refuses(tmp_path, monkeypatch, capsys):
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner", "other-account"], active="other-account",
                            sees={}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    with pytest.raises(db.GitError) as raised:
        db.query_github_visibility(REPOSITORY)
    message = str(raised.value)
    assert "no gh credential can see" in message
    for text in ("example-owner", "other-account", REPOSITORY):
        assert text not in message
    # Owner, the other stored account, then gh's default: every candidate was asked once.
    assert [call["credential"] for call in views(stub)] == ["example-owner", "other-account", "other-account"]
    assert [call["explicit"] for call in views(stub)] == [True, True, False]
    assert_active_account_untouched(stub)
    captured = capsys.readouterr()
    assert_no_token_leaked(stub, message, captured.out, captured.err)


def test_no_stored_account_at_all_refuses(tmp_path, monkeypatch):
    stub = make_gh_cli_stub(tmp_path, accounts=[], active="nobody", sees={}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    with pytest.raises(db.GitError):
        db.query_github_visibility(REPOSITORY)


def test_an_explicit_caller_token_is_the_last_candidate(tmp_path, monkeypatch):
    """CI passes GH_TOKEN; it is used, but never handed to the stored-account lookups."""
    stub = make_gh_cli_stub(tmp_path, accounts=[], active="nobody", ambient_tokens=["ci-token"],
                            sees={"ci-token": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    monkeypatch.setenv("GH_TOKEN", stub["ambient"]["ci-token"])
    assert db.query_github_visibility(REPOSITORY) == "PRIVATE"
    calls = gh_stub_calls(stub)
    assert all(not call["explicit"] for call in calls if call["argv"][0] == "auth")
    assert [call["credential"] for call in views(stub)] == ["ci-token"]


def test_a_public_answer_is_reported_as_public(tmp_path, monkeypatch):
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner"], active="example-owner",
                            sees={"example-owner": [REPOSITORY]}, visibility={REPOSITORY: "PUBLIC"})
    install(monkeypatch, stub)
    assert db.query_github_visibility(REPOSITORY) == "PUBLIC"


def test_an_answer_for_a_different_repository_is_not_an_answer(tmp_path, monkeypatch):
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner"], active="example-owner",
                            sees={"example-owner": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"},
                            renamed={REPOSITORY: "example-owner/renamed-data"})
    install(monkeypatch, stub)
    with pytest.raises(db.GitError):
        db.query_github_visibility(REPOSITORY)


@pytest.mark.parametrize("repository", ["", "example-owner", "example-owner/private-data/extra",
                                        "example-owner/..", "https://github.com/example-owner/private-data",
                                        "example owner/private-data", None])
def test_only_a_canonical_repository_is_queried(tmp_path, monkeypatch, repository):
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner"], active="example-owner",
                            sees={"example-owner": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    with pytest.raises(db.GitError):
        db.query_github_visibility(repository)
    assert gh_stub_calls(stub) == []


def test_missing_gh_refuses(tmp_path, monkeypatch):
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(db.GitError):
        db.query_github_visibility(REPOSITORY)


def test_package_runtime_exposes_the_same_query(tmp_path, monkeypatch):
    stub = make_gh_cli_stub(tmp_path, accounts=["example-owner", "other-account"], active="other-account",
                            sees={"example-owner": [REPOSITORY]}, visibility={REPOSITORY: "PRIVATE"})
    install(monkeypatch, stub)
    import importlib.util
    spec = importlib.util.spec_from_file_location("_gh_visibility_runtime", ROOT / "fleet_guards" / "runtime.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    assert runtime.query_github_visibility(REPOSITORY) == "PRIVATE"
    assert [call["credential"] for call in views(stub)] == ["example-owner"]
