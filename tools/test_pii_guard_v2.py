#!/usr/bin/env python3
# pii-guard:scanner-file -- this file must contain the shapes it detects; see SCANNER_MARKER
"""Tests for the v2 policy layer: token kinds, the jurisdiction matrix, derivability,
loader self-attestation, and the exemption exit.

READ THIS BEFORE ADDING A TEST HERE
-----------------------------------
Nearly every assertion below has a TWIN pointing the other way, and the twin is the point.
A test that only checks "the loader raises on a damaged file" is passed by a loader that
raises on everything; a test that only checks "linkage does not gate in history" is passed by
a guard that has stopped gating. So each relaxation is paired with the case that must still
block, and each fail-closed assertion is paired with a healthy input that must still pass.

Every identifier here is synthetic.
"""
import io
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pii_guard as g  # noqa: E402
from make_fixtures import _no_window
from make_fixtures import synthetic_token, write_policy, write_visibility, write_ci_suite
from make_fixtures import write_invalid_git_marker, write_stale_guard, structural_probe
from make_fixtures import write_encoded_record, write_count_policy
from make_fixtures import make_history_fixture, make_tree_ref_fixture
from make_fixtures import write_encoding_probe, reencode_record
from make_fixtures import make_identity_shape_fixture
from make_fixtures import make_sized_history_fixture
from make_fixtures import owner_collision_cases, owner_collision_policy_cases


@pytest.mark.parametrize("role", ["author", "committer"])
@pytest.mark.parametrize("domain_case", ["lower", "upper", "mixed"])
@pytest.mark.parametrize("numeric", [False, True])
def test_source8_identity_shape_domain_case(repo, tmp_path, role, domain_case, numeric):
    from pathlib import Path
    import shutil

    source = Path(GUARD).parent.parent
    kit = tmp_path / "identity-kit"
    (kit / "hooks").mkdir(parents=True)
    (kit / "tools").mkdir()
    for name in ("hooks/pre-commit", "tools/pii_guard.py", "tools/data_boundary.py", "tools/publication_guard.py"):
        shutil.copyfile(source / name, kit / name)
    (kit / "hooks/pre-commit").chmod(0o755)
    allowed = make_identity_shape_fixture(repo, tmp_path, role, domain_case, numeric)
    policy = write_policy(tmp_path / "identity-policy.json", synthetic_token("identity-shape"), g.CANARY_TOKEN)
    repo.env["PII_DENYLIST"] = str(policy)
    repo.git("config", "core.hooksPath", str(kit / "hooks"))
    repo.git("add", "--all")
    result = repo.git("commit", "-m", "synthetic identity hook control", allow_fail=True)
    output = result.stdout + result.stderr
    if allowed:
        assert result.returncode == 0, output
        assert "only the address-shape check ran" in output
        assert repo.git("rev-parse", "--verify", "HEAD").returncode == 0
    else:
        assert result.returncode != 0, output
        assert "IDENTITY MALFORMED" in output
        assert repo.git("rev-parse", "--verify", "HEAD", allow_fail=True).returncode != 0


def test_source7_self_exclusion_keeps_other_owner(tmp_path, monkeypatch):
    from make_fixtures import write_owner_scope_visibility
    vis = tmp_path / "owners.json"
    current, name = write_owner_scope_visibility(vis, g._utcnow())
    monkeypatch.setattr(g, "_repo_slug", lambda root: (current, current.split("/")[-1]))
    tokens = g.load_cross_repo_tokens(".", str(vis))
    assert len(tokens) == 1
    assert tokens[0].value.split("/", 1)[1] == name
    assert tokens[0].value.split("/", 1)[0] != current.split("/", 1)[0]
    assert tokens[0].kind == "linkage"


@pytest.mark.parametrize("case", owner_collision_cases(), ids=lambda case: case["id"])
def test_own_name_collision_keeps_foreign_attribution(tmp_path, monkeypatch, case):
    visibility = write_visibility(tmp_path / "owners.json", case["visibility"], g._utcnow())
    monkeypatch.setattr(g, "_repo_slug", lambda root: (case["self_key"], case["self_key"].split("/", 1)[1]))
    tokens = g.load_cross_repo_tokens(".", str(visibility))
    assert any(token.value == case["foreign"] and token.kind == "linkage" for token in tokens)
    findings = []
    g.scan_text(case["text"], "synthetic text", set(), g.Policy.of(tokens), findings, domain="tree")
    assert any(severity == "BLOCK" for _where, _label, _value, severity in findings) is case["blocked"]


@pytest.mark.parametrize("case", owner_collision_policy_cases(), ids=lambda case: case["id"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("domain", ["tree", "staged", "range", "history"])
def test_owner_collision_preserves_policy_jurisdiction(tmp_path, monkeypatch, case, reverse, domain):
    entries = dict(reversed(list(case["visibility"].items()))) if reverse else case["visibility"]
    visibility = write_visibility(tmp_path / "owners.json", entries, case["stamp"] or g._utcnow())
    monkeypatch.setattr(g, "_repo_slug", lambda root: (case["self_key"], case["self_key"].split("/", 1)[1]))
    tokens = g.load_cross_repo_tokens(".", str(visibility))
    if case["secret"]:
        tokens.append(g.Token(case["text"], "secret"))
    findings = []
    g.scan_text(case["text"], "synthetic text", set(), g.Policy.of(tokens), findings, domain=domain)
    expected = "DEBT" if domain == "history" and case["severity"] == "BLOCK" and not case["secret"] else case["severity"]
    assert {severity for _where, _label, _value, severity in findings} == {expected}


@pytest.mark.parametrize("reverse", [False, True])
def test_source7_duplicate_owner_severity_is_order_independent(tmp_path, monkeypatch, reverse):
    from make_fixtures import write_owner_scope_visibility
    vis = tmp_path / "owners.json"
    current, name = write_owner_scope_visibility(vis, g._utcnow(), duplicate=True, reverse=reverse)
    monkeypatch.setattr(g, "_repo_slug", lambda root: (current, current.split("/")[-1]))
    tokens = g.load_cross_repo_tokens(".", str(vis))
    assert [(token.value, token.kind) for token in tokens] == [(name, "linkage")]
    findings = []
    g.scan_text("example-owner-b/" + name, "synthetic text", set(), g.Policy.of(tokens), findings)
    assert any(severity == "BLOCK" for _where, _label, _value, severity in findings)


@pytest.mark.parametrize("domain", ["tree", "staged", "range", "history"])
@pytest.mark.parametrize("blocked", [False, True])
@pytest.mark.parametrize("suffix", [".png", ".example", ".test", ".invalid"])
def test_source7_binary_filename_identifiers(repo, domain, blocked, suffix):
    from make_fixtures import write_mailbox_filename
    relative, mailbox = write_mailbox_filename(repo.root, suffix=suffix, blocked=blocked)
    repo.git("add", "--", relative)
    if domain in ("range", "history"):
        repo.git("commit", "-qm", "synthetic filename")
    policy = g.Policy.of([])
    if domain == "tree":
        findings = g.scan_tree(repo.root, set(), policy)
    elif domain == "staged":
        findings = g.scan_staged(repo.root, set(), policy)
    elif domain == "range":
        findings = g.scan_range(repo.root, set(), policy, "HEAD")
    else:
        findings = g.scan_history(repo.root, set(), policy)
    path_findings = [item for item in findings if "(path)" in item[0]]
    assert any(label == "PERSONAL-MAILBOX" and value == mailbox and severity == "BLOCK"
               for _where, label, value, severity in path_findings) is blocked
    if not blocked:
        assert not path_findings



@pytest.mark.parametrize("suffix", [".png", ".example", ".test", ".invalid"])
@pytest.mark.parametrize("exemption", ["mailbox", "filename", "synthetic"])
def test_source7_filename_exact_and_synthetic_exemptions(tmp_path, suffix, exemption):
    from make_fixtures import write_mailbox_filename
    relative, mailbox = write_mailbox_filename(tmp_path, suffix=suffix, blocked=exemption != "synthetic")
    allow = {mailbox} if exemption == "mailbox" else {mailbox + suffix} if exemption == "filename" else set()
    for domain in ("tree", "staged", "range", "history"):
        findings = []
        g.scan_text(relative, "synthetic (path)", allow, g.Policy.of([]), findings,
                    domain=domain, path_text=True)
        assert not findings


@pytest.mark.parametrize("suffix", [".example", ".test", ".invalid"])
def test_source7_filename_synthetic_placeholder_preserved(tmp_path, suffix):
    from make_fixtures import write_mailbox_filename
    relative, _mailbox = write_mailbox_filename(tmp_path, suffix=suffix, placeholder=True)
    findings = []
    g.scan_text(relative, "synthetic (path)", set(), g.Policy.of([]), findings, path_text=True)
    assert not findings


@pytest.mark.parametrize("field,target", [
    ("annotation", "commit"), ("annotation", "tree"), ("annotation", "blob"),
    ("tagger_email", "commit"), ("tagger_name", "commit"),
    ("ref_name", "commit"), ("object_name", "commit"), ("nested_annotation", "commit"),
])
@pytest.mark.parametrize("blocked", [False, True])
def test_source7_tag_metadata_is_scanned(repo, field, target, blocked):
    from make_fixtures import make_tag_metadata_fixture
    fixture = make_tag_metadata_fixture(repo, field, target, blocked)
    findings = g.scan_history(repo.root, set(), g.Policy.of([g.Token(fixture["token"], "secret")]))
    assert any(value == fixture["expected"] and severity == "BLOCK"
               for _where, _label, value, severity in findings) is blocked
    if not blocked:
        assert not findings


@pytest.mark.parametrize("blocked", [False, True])
def test_source7_tag_cli_and_push_hook(repo, tmp_path, blocked):
    from pathlib import Path
    import shutil
    from make_fixtures import make_tag_metadata_fixture, write_empty_tool_classification
    write_empty_tool_classification(repo.root)
    fixture = make_tag_metadata_fixture(repo, "annotation", blocked=blocked)
    cli = _source4_cli(repo, tmp_path, fixture["token"], "--tree", "--history")
    assert cli.returncode == (1 if blocked else 0), cli.stdout + cli.stderr
    source = Path(GUARD).parent.parent
    kit = tmp_path / "hook-kit"
    for name in ("hooks/pre-push", "tools/pii_guard.py", "tools/data_boundary.py", "tools/publication_guard.py"):
        (kit / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, kit / name)
    policy = write_policy(tmp_path / "hook-policy.json", fixture["token"], g.CANARY_TOKEN)
    bash = (Path(shutil.which("git")).parent.parent / "bin/bash.exe"
            if os.name == "nt" else Path(shutil.which("bash")))
    result = subprocess.run([str(bash), "--noprofile", "--norc", str(kit / "hooks/pre-push")],
                            cwd=repo.root, env=dict(repo.env, PII_DENYLIST=str(policy)),
                            capture_output=True, text=True, encoding="utf-8", **_no_window())
    assert result.returncode == (1 if blocked else 0), result.stdout + result.stderr
    if blocked:
        assert "push BLOCKED by pii_guard" in result.stdout + result.stderr


def test_source7_oversize_tag_metadata_refuses_before_read(repo, monkeypatch):
    from make_fixtures import make_tag_metadata_fixture
    make_tag_metadata_fixture(repo, "annotation", blocked=False)
    monkeypatch.setattr(g, "MAX_BLOB_BYTES", 64)
    with pytest.raises(g.GitError, match="tag metadata exceeds"):
        g.scan_history(repo.root, set(), g.Policy.of([]))


@pytest.mark.parametrize("shape", ["file", "directory", "gitlink", "odd-name"])
@pytest.mark.parametrize("blocked", [False, True])
@pytest.mark.parametrize("with_commit", [False, True])
def test_source6_history_tree_ref_paths(repo, tmp_path, shape, blocked, with_commit):
    fixture = make_tree_ref_fixture(repo, shape, blocked, with_commit)
    listing = repo.git("ls-tree", "-r", "-t", "-z", fixture["trees"][0]).stdout
    names = {entry.split("\t", 1)[1] for entry in listing.split("\0") if entry}
    assert set(fixture["paths"]) <= names
    policy = g.Policy.of([g.Token(fixture["token"], "secret")])
    stats = g._blank_history_stats()
    findings = g.scan_history(repo.root, set(), policy, stats)
    assert stats["commits"] == int(with_commit)
    assert stats["blobs_scanned"] == 1 + int(with_commit)
    hits = [where for where, _, value, severity in findings
            if value == fixture["token"] and severity == "BLOCK"]
    assert bool(hits) is blocked, findings
    if blocked:
        assert any(where == "<blob> %s (path)" % path
                   for where in hits for path in fixture["paths"])
    result = _source4_cli(repo, tmp_path, fixture["token"], "--history")
    assert result.returncode == int(blocked), result.stdout + result.stderr


@pytest.mark.parametrize("with_commit", [False, True])
def test_source6_history_annotated_tree_ref(repo, tmp_path, with_commit):
    fixture = make_tree_ref_fixture(repo, "file", True, with_commit, annotated=True)
    findings = g.scan_history(repo.root, set(), g.Policy.of([fixture["token"]]))
    assert any(where == "<blob> %s (path)" % fixture["paths"][0]
               and value == fixture["token"] and severity == "BLOCK"
               for where, _, value, severity in findings), findings
    result = _source4_cli(repo, tmp_path, fixture["token"], "--history")
    assert result.returncode == 1, result.stdout + result.stderr


@pytest.mark.parametrize("blocked", [False, True])
def test_source6_history_tree_ref_without_blobs(repo, capsys, blocked):
    fixture = make_tree_ref_fixture(repo, "gitlink-only", blocked)
    stats = g._blank_history_stats()
    findings = g.scan_history(repo.root, set(), g.Policy.of([fixture["token"]]), stats)
    assert stats["commits"] == stats["blobs_total"] == 0
    assert bool(findings) is blocked, findings
    assert "examined nothing" not in capsys.readouterr().err


@pytest.mark.parametrize("ordinary_alias", [False, True])
@pytest.mark.parametrize("with_commit", [False, True])
def test_source6_history_tree_ref_aliases(repo, ordinary_alias, with_commit):
    fixture = make_tree_ref_fixture(repo, "aliases", ordinary_alias, with_commit)
    for tree in fixture["trees"]:
        assert fixture["blob"] in repo.git("ls-tree", "-r", "-z", tree).stdout
    findings = g.scan_history(repo.root, set(), g.Policy.of([]))
    if ordinary_alias:
        assert any(where == "<blob> notes.md" and severity == "BLOCK"
                   for where, _, _, severity in findings), findings
    else:
        assert findings == []


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-be-bom", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("variant", ["ascii", "mixed", "ambiguous"])
def test_source5_encoding_candidates_keep_identifiers(tmp_path, encoding, variant):
    path, tokens = write_encoding_probe(tmp_path, "notes.md", encoding, variant)
    text, detected = g._decode_best(path.read_bytes())
    assert text is not None, detected
    assert all(token in text for token in tokens), (detected, tokens)


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("relative", ["notes.md", "tools/pii_guard.py"])
@pytest.mark.parametrize("domain", ["tree", "history", "staged", "range"])
def test_source5_encoding_domains(repo, tmp_path, encoding, relative, domain):
    token = synthetic_token("encoded-domain")
    write_encoded_record(repo.root, relative, ["# café 中文 Ā baseline"], encoding)
    repo.commit("synthetic baseline")
    write_encoding_probe(repo.root, relative, encoding, "ascii", token=token)
    repo.git("add", "--", relative)
    if domain in {"history", "range"}:
        repo.git("commit", "-qm", "synthetic addition")
    if domain != "tree":
        write_encoded_record(repo.root, relative, ["# clean working copy"], encoding)
    if domain in {"staged", "range"}:
        _source4_incremental(repo, tmp_path, token, domain, True)
    else:
        policy = g.Policy.of([g.Token(token, "secret")])
        findings = getattr(g, "scan_" + domain)(repo.root, set(), policy)
        assert any(value == token and severity == "BLOCK" for _, _, value, severity in findings)
        result = _source4_cli(repo, tmp_path, token, "--" + domain)
        assert result.returncode == 1, result.stdout + result.stderr


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
@pytest.mark.parametrize("operation", ["unchanged", "removed", "reencoded"])
@pytest.mark.parametrize("domain", ["staged", "range"])
def test_source5_encoding_existing_content(repo, tmp_path, encoding, operation, domain):
    token = synthetic_token("encoded-existing-control")
    before = ["# café 中文 Ā", token]
    write_encoded_record(repo.root, "notes.md", before, "utf-8" if operation == "reencoded" else encoding)
    repo.commit("synthetic accepted content")
    after = ["# café 中文 Ā edited"] + ([] if operation == "removed" else [token])
    write_encoded_record(repo.root, "notes.md", after, encoding)
    repo.git("add", "notes.md")
    if domain == "range":
        repo.git("commit", "-qm", "synthetic edit")
    _source4_incremental(repo, tmp_path, token, domain, False)


@pytest.mark.parametrize("domain", ["staged", "range"])
def test_source5_encoding_ambiguous_existing_content(repo, tmp_path, domain):
    token = synthetic_token("other-byte-order")
    path, _ = write_encoding_probe(repo.root, "notes.md", "utf-16-be", "ambiguous")
    repo.commit("synthetic accepted ambiguous content")
    reencode_record(path, "utf-16-be", "utf-8")
    repo.git("add", "notes.md")
    if domain == "range":
        repo.git("commit", "-qm", "synthetic reencoding")
    _source4_incremental(repo, tmp_path, token, domain, False)


def test_source5_encoding_malformed_and_binary_controls(tmp_path):
    path, _ = write_encoding_probe(tmp_path, "notes.md", "utf-16-be-bom")
    assert g._decode_best(path.read_bytes()[:-1]) == (None, None)
    assert g._decode_best(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] * 200)) == (None, None)


@pytest.mark.parametrize("head_state", ["valid", "unborn-branch", "unborn-tag"])
@pytest.mark.parametrize("violation", ["clean", "blob", "message", "author"])
def test_source5_history_reachable_refs(repo, tmp_path, head_state, violation):
    token = make_history_fixture(repo, head_state, violation)
    stats = g._blank_history_stats()
    findings = g.scan_history(repo.root, set(), g.Policy.of([g.Token(token, "secret")]), stats)
    assert stats["commits"] == 1
    assert stats["blobs_total"] == stats["blobs_scanned"] == 1
    if violation == "clean":
        assert findings == []
    elif violation == "author":
        assert any(label == "AUTHOR-EMAIL" and value == "user1@example.com" and severity == "BLOCK"
                   for _, label, value, severity in findings), findings
    else:
        location = "<blob>" if violation == "blob" else "<commit message>"
        assert any(where.startswith(location) and value == token and severity == "BLOCK"
                   for where, _, value, severity in findings), findings
    result = _source4_cli(repo, tmp_path, token, "--history")
    assert result.returncode == (0 if violation == "clean" else 1), result.stdout + result.stderr
    assert "examined nothing" not in result.stdout + result.stderr
    if violation == "clean":
        assert "1 commit(s), 1 blob(s) scanned" in result.stdout + result.stderr


def test_source5_history_empty_is_reported(repo, tmp_path, capsys):
    token = make_history_fixture(repo, "empty")
    stats = g._blank_history_stats()
    assert g.scan_history(repo.root, set(), g.Policy.of([]), stats) == []
    assert stats == g._blank_history_stats()
    assert "examined nothing" in capsys.readouterr().err
    result = _source4_cli(repo, tmp_path, token, "--history")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 commit(s), 0 blob(s) scanned" in result.stdout + result.stderr
    assert "examined nothing" in result.stdout + result.stderr


def test_source5_history_blob_tag_without_commits(repo, tmp_path):
    token = make_history_fixture(repo, "blob-tag", "blob")
    stats = g._blank_history_stats()
    findings = g.scan_history(repo.root, set(), g.Policy.of([g.Token(token, "secret")]), stats)
    assert stats["commits"] == 0
    assert stats["blobs_total"] == stats["blobs_scanned"] == 1
    assert any(value == token and severity == "BLOCK" for _, _, value, severity in findings)
    result = _source4_cli(repo, tmp_path, token, "--history")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "examined nothing" not in result.stdout + result.stderr


def test_source5_history_broken_head_fails(repo, tmp_path):
    token = make_history_fixture(repo, "broken", "blob")
    with pytest.raises(g.GitError):
        g.scan_history(repo.root, set(), g.Policy.of([g.Token(token, "secret")]))
    result = _source4_cli(repo, tmp_path, token, "--history")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "SCAN FAILED" in result.stdout + result.stderr
    assert "clean (history)" not in result.stdout + result.stderr


@pytest.mark.parametrize("command", ["rev-list", "log", "cat-file"])
def test_source5_history_command_errors_are_not_empty(repo, monkeypatch, command):
    make_history_fixture(repo, "unborn-tag")
    original = subprocess.run
    def fail_command(args, *positional, **kwargs):
        if isinstance(args, list) and len(args) > 1 and args[1] == command:
            text = kwargs.get("text") or kwargs.get("encoding")
            return subprocess.CompletedProcess(args, 128, stdout="" if text else b"",
                                               stderr="synthetic command failure" if text else b"synthetic command failure")
        return original(args, *positional, **kwargs)
    monkeypatch.setattr(g.subprocess, "run", fail_command)
    with pytest.raises(g.GitError):
        g.scan_history(repo.root, set(), g.Policy.of([]))


def _source4_cli(repo, tmp_path, token, *args):
    policy = write_policy(tmp_path / "source4-policy.json", token, g.CANARY_TOKEN)
    return subprocess.run([sys.executable, GUARD, "--repo", repo.root, *args],
                          cwd=repo.root, env=dict(repo.env, PII_DENYLIST=str(policy)),
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          **_no_window())


def _source4_incremental(repo, tmp_path, token, domain, blocked, revision="HEAD^..HEAD"):
    policy = g.Policy.of([g.Token(token, "secret")])
    if domain == "staged":
        findings = g.scan_staged(repo.root, set(), policy)
        args = ["--staged"]
    else:
        findings = g.scan_range(repo.root, set(), policy, revision)
        args = ["--range", revision]
    assert any(value == token and severity == "BLOCK" for _, _, value, severity in findings) is blocked, findings
    result = _source4_cli(repo, tmp_path, token, *args)
    assert result.returncode == (1 if blocked else 0), result.stdout + result.stderr


def test_source4_staged_intent_to_add_is_not_a_staged_disclosure(repo, tmp_path):
    token = synthetic_token("intent-to-add")
    write_encoded_record(repo.root, "seed.md", ["synthetic seed"])
    repo.commit("synthetic seed")
    relative = token + ".md"
    write_encoded_record(repo.root, relative, ["synthetic unstaged content"])
    repo.git("add", "-N", "--", relative)
    assert repo.git("diff", "--cached", "--name-only").stdout == ""
    _source4_incremental(repo, tmp_path, token, "staged", False)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-16-be-bom", "utf-16-le", "cp1252"])
@pytest.mark.parametrize("relative", ["notes.md", "tools/pii_guard.py"])
@pytest.mark.parametrize("domain", ["staged", "range"])
def test_source4_encoded_incremental_addition(repo, tmp_path, encoding, relative, domain):
    token = synthetic_token("encoded-addition")
    write_encoded_record(repo.root, relative, ["# café baseline"], encoding)
    repo.commit("synthetic baseline")
    write_encoded_record(repo.root, relative, ["# café baseline", "# " + token], encoding)
    repo.git("add", "--", relative)
    write_encoded_record(repo.root, relative, ["# cleaned working copy"], encoding)
    if domain == "range":
        repo.git("commit", "-qm", "synthetic encoded addition")
    _source4_incremental(repo, tmp_path, token, domain, True)


@pytest.mark.parametrize("operation", ["unchanged", "removed", "reencoded"])
@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-be-bom"])
@pytest.mark.parametrize("domain", ["staged", "range"])
def test_source4_encoded_incremental_existing_controls(repo, tmp_path, operation, encoding, domain):
    token = synthetic_token("encoded-existing")
    before = [token, "# café accepted"]
    write_encoded_record(repo.root, "notes.md", before, "utf-8-sig" if operation == "reencoded" else encoding)
    repo.commit("synthetic accepted content")
    after = before if operation == "reencoded" else ([token, "# café edit"] if operation == "unchanged" else ["# removed"])
    write_encoded_record(repo.root, "notes.md", after, encoding)
    repo.git("add", "notes.md")
    if domain == "range":
        repo.git("commit", "-qm", "synthetic edit")
    _source4_incremental(repo, tmp_path, token, domain, False)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-be-bom"])
@pytest.mark.parametrize("inherited", [False, True])
def test_source4_encoded_merge_additions(repo, tmp_path, encoding, inherited):
    token = synthetic_token("merge-encoding")
    write_encoded_record(repo.root, "notes.md", ["# base"], encoding)
    repo.commit("synthetic base")
    repo.git("checkout", "-qb", "side")
    write_encoded_record(repo.root, "notes.md", ["# side", token] if inherited else ["# side"], encoding)
    repo.commit("synthetic side")
    repo.git("checkout", "-q", "master")
    write_encoded_record(repo.root, "notes.md", ["# main"], encoding)
    repo.commit("synthetic main")
    repo.git("merge", "side", "--no-commit", allow_fail=True)
    write_encoded_record(repo.root, "notes.md", ["# resolved", token], encoding)
    repo.commit("synthetic resolution")
    _source4_incremental(repo, tmp_path, token, "range", not inherited, "HEAD ^HEAD^1 ^HEAD^2")


@pytest.mark.parametrize("shape", ["file", "directory", "rename", "gitlink"])
@pytest.mark.parametrize("blocked", [False, True])
def test_source4_range_new_path_names(repo, tmp_path, shape, blocked):
    token = synthetic_token("path-name")
    write_encoded_record(repo.root, "seed.md", ["synthetic seed"])
    repo.commit("synthetic base")
    name = token if blocked else "synthetic-safe"
    relative = name + "/notes.md" if shape == "directory" else name + (".md" if shape != "gitlink" else "")
    if shape == "gitlink":
        oid = repo.git("rev-parse", "HEAD").stdout.strip()
        repo.git("update-index", "--add", "--cacheinfo", "160000", oid, relative)
    elif shape == "rename":
        repo.git("mv", "seed.md", relative)
    else:
        write_encoded_record(repo.root, relative, ["synthetic safe content"])
        repo.git("add", "--", relative)
    repo.git("commit", "-qm", "synthetic new path")
    _source4_incremental(repo, tmp_path, token, "range", blocked)


@pytest.mark.parametrize("operation", ["modified", "deleted", "gitlink-update"])
def test_source4_range_old_path_names_are_not_new(repo, tmp_path, operation):
    token = synthetic_token("existing-path")
    write_encoded_record(repo.root, "seed.md", ["synthetic seed"])
    repo.commit("synthetic seed")
    relative = token + ".md"
    if operation == "gitlink-update":
        oid = repo.git("rev-parse", "HEAD").stdout.strip()
        repo.git("update-index", "--add", "--cacheinfo", "160000", oid, relative)
    else:
        write_encoded_record(repo.root, relative, ["synthetic accepted path"])
        repo.git("add", "--", relative)
    repo.git("commit", "-qm", "synthetic accepted path")
    if operation == "gitlink-update":
        oid = repo.git("rev-parse", "HEAD").stdout.strip()
        repo.git("update-index", "--cacheinfo", "160000", oid, relative)
    elif operation == "deleted":
        repo.git("rm", "--", relative)
    else:
        write_encoded_record(repo.root, relative, ["synthetic safe edit"])
        repo.git("add", "--", relative)
    repo.git("commit", "-qm", "synthetic safe change")
    _source4_incremental(repo, tmp_path, token, "range", False)


@pytest.mark.parametrize("inherited", [False, True])
def test_source4_merge_new_path_scope(repo, tmp_path, inherited):
    token = synthetic_token("merge-path")
    relative = token + "/notes.md"
    write_encoded_record(repo.root, "seed.md", ["synthetic seed"])
    repo.commit("synthetic seed")
    repo.git("checkout", "-qb", "side")
    write_encoded_record(repo.root, relative if inherited else "side.md", ["synthetic side"])
    repo.commit("synthetic side")
    repo.git("checkout", "-q", "master")
    write_encoded_record(repo.root, "main.md", ["synthetic main"])
    repo.commit("synthetic main")
    repo.git("merge", "side", "--no-ff", "--no-commit")
    write_encoded_record(repo.root, relative, ["synthetic resolution"])
    repo.commit("synthetic merge")
    _source4_incremental(repo, tmp_path, token, "range", not inherited, "HEAD ^HEAD^1 ^HEAD^2")


@pytest.mark.parametrize("variant", ["missing", "null", "boolean", "string", "float", "mismatch"])
def test_source4_format2_count_is_mandatory(repo, tmp_path, variant):
    token = synthetic_token("policy-retained")
    path = write_count_policy(tmp_path / "count-policy.json", token, g.CANARY_TOKEN, variant)
    with pytest.raises(g.PolicyError, match="count"):
        g._parse_denylist(str(path))
    result = subprocess.run([sys.executable, GUARD, "--repo", repo.root, "--staged"],
                            env=dict(repo.env, PII_DENYLIST=str(path)), capture_output=True, text=True,
                            **_no_window())
    assert result.returncode != 0, result.stdout + result.stderr
    assert "count" in result.stdout + result.stderr


@pytest.mark.parametrize("variant", ["healthy", "legacy-list", "legacy-dict", "legacy-format1"])
def test_source4_policy_healthy_and_legacy_controls(tmp_path, variant):
    token = synthetic_token("policy-retained")
    path = write_count_policy(tmp_path / "count-policy.json", token, g.CANARY_TOKEN, variant)
    notes = []
    tokens = g._parse_denylist(str(path), notes=notes)
    assert any(item.value == token for item in tokens)
    assert bool(notes) is variant.startswith("legacy")


def test_source4_cli_tree_excludes_real_gitlink_but_explicit_files_scan(tmp_path):
    from test_data_boundary import native_submodule_layout, git
    parent, module = native_submodule_layout(tmp_path, "vendor/security")
    token = synthetic_token("child-content")
    write_encoded_record(module, "notes.md", [token])
    git(module, "add", "notes.md")
    policy = g.Policy.of([g.Token(token, "secret")])
    stats = {}
    assert g.scan_tree(str(parent), set(), policy, stats=stats) == []
    assert stats["unreadable"] == []
    explicit = g.scan_tree(str(parent), set(), policy, files=["vendor/security/notes.md"])
    child = g.scan_tree(str(module), set(), policy)
    for findings in (explicit, child):
        assert any(value == token and severity == "BLOCK" for _, _, value, severity in findings)
    policy_path = write_policy(tmp_path / "cli-policy.json", token, g.CANARY_TOKEN)
    for root, blocked in [(parent, False), (module, True)]:
        result = subprocess.run([sys.executable, GUARD, "--repo", str(root), "--tree"],
                                env=dict(os.environ, PII_DENYLIST=str(policy_path)), capture_output=True, text=True,
                                **_no_window())
        assert result.returncode == (1 if blocked else 0), result.stdout + result.stderr
        assert "NOT scanned" not in result.stdout + result.stderr


@pytest.mark.parametrize("directory", ["docs", "nested/docs"])
def test_source3_invalid_git_marker_cannot_hide_tracked_text(repo, directory):
    token = synthetic_token("invalid-marker")
    relative = directory + "/notes.txt"
    repo.write(relative, token + "\n")
    repo.commit("synthetic tracked text")
    write_invalid_git_marker(repo.root, directory)
    out = g.scan_tree(repo.root, set(), g.Policy.of([g.Token(token, "secret")]))
    assert any(value == token and severity == "BLOCK" for _, _, value, severity in out), out


@pytest.mark.parametrize("hook_name", ["pre-commit", "pre-push"])
@pytest.mark.parametrize("missing", ["pii_guard.py", "data_boundary.py", "both"])
def test_source3_native_hook_never_falls_back_to_consumer(repo, tmp_path, hook_name, missing):
    from pathlib import Path
    import shutil
    source = Path(GUARD).parent.parent
    kit = Path(repo.root) / "guards"
    (kit / "hooks").mkdir(parents=True)
    (kit / "tools").mkdir()
    shutil.copyfile(source / "hooks" / hook_name, kit / "hooks" / hook_name)
    shutil.copyfile(source / "tools/publication_guard.py", kit / "tools/publication_guard.py")
    for name in ["pii_guard.py", "data_boundary.py"]:
        if missing not in (name, "both"):
            shutil.copyfile(source / "tools" / name, kit / "tools" / name)
    repo.git("remote", "remove", "origin")
    repo.write(".dataclass.json", json.dumps({"data": [], "fixture": [], "_audited": "synthetic"}))
    repo.write("seed.md", "synthetic seed\n")
    repo.git("add", ".dataclass.json", "seed.md")
    repo.git("commit", "-qm", "synthetic baseline")
    for name in ["pii_guard.py", "data_boundary.py"]:
        write_stale_guard(repo.root, "tools/" + name)
    receipt = tmp_path / "stale-called.txt"
    env = dict(repo.env, FG_SYNTHETIC_RECEIPT=str(receipt))
    if os.name == "nt":
        bash = Path(shutil.which("git")).parent.parent / "bin/bash.exe"
    else:
        bash = Path(shutil.which("bash"))
    result = subprocess.run([str(bash), "--noprofile", "--norc", str(kit / "hooks" / hook_name)],
                            cwd=repo.root, env=env, capture_output=True, text=True, **_no_window())
    assert result.returncode != 0, result.stdout + result.stderr
    assert "missing" in (result.stdout + result.stderr).lower()
    assert not receipt.exists(), "The stale consumer scanner executed"


@pytest.mark.parametrize("relative", sorted(g.SCANNER_PATHS) + ["notes.md"])
def test_source3_range_keeps_private_tokens_in_scanner_files(repo, relative):
    token = synthetic_token("range-secret")
    policy = g.Policy.of([g.Token(token, "secret")])
    repo.write(relative, "# base\n")
    repo.commit("synthetic base")
    repo.write(relative, "# base\n# " + token + "\n")
    repo.commit("synthetic addition")
    out = g.scan_range(repo.root, set(), policy, "HEAD^..HEAD")
    assert any(value == token and severity == "BLOCK" for _, _, value, severity in out), out


@pytest.mark.parametrize("relative,blocked", [("tools/pii_guard.py", False), ("notes.md", True)])
def test_source3_range_structural_fixture_exemption_is_per_file(repo, relative, blocked):
    repo.write("seed.md", "synthetic seed\n")
    repo.commit()
    repo.write(relative, structural_probe())
    repo.commit("synthetic structural fixture")
    out = g.scan_range(repo.root, set(), g.Policy.of([]), "HEAD^..HEAD")
    assert bool(out) is blocked, out


def test_source3_range_does_not_scan_untouched_or_removed_private_lines(repo):
    token = synthetic_token("range-existing")
    policy = g.Policy.of([g.Token(token, "secret")])
    repo.write("tools/pii_guard.py", "# " + token + "\n# old\n")
    repo.commit("synthetic prior content")
    repo.write("tools/pii_guard.py", "# " + token + "\n# changed\n")
    repo.commit("synthetic harmless edit")
    assert g.scan_range(repo.root, set(), policy, "HEAD^..HEAD") == []
    repo.write("tools/pii_guard.py", "# cleaned\n")
    repo.commit("synthetic removal")
    assert g.scan_range(repo.root, set(), policy, "HEAD^..HEAD") == []


@pytest.mark.parametrize("relative", ["tools/pii_guard.py", "notes.md"])
@pytest.mark.parametrize("content,blocked", [("private", True), ("structural", False)])
def test_source3_merge_additions_keep_per_file_policy(repo, relative, content, blocked):
    token = synthetic_token("merge-added")
    repo.write(relative, "# base\n")
    repo.commit("synthetic base")
    repo.git("checkout", "-qb", "side")
    repo.write(relative, "# side\n")
    repo.commit("synthetic side")
    repo.git("checkout", "-q", "master")
    repo.write(relative, "# main\n")
    repo.commit("synthetic main")
    repo.git("merge", "side", "--no-commit", allow_fail=True)
    repo.write(relative, "# " + token + "\n" if content == "private" else structural_probe())
    repo.commit("synthetic resolution")
    out = g.scan_range(repo.root, set(), g.Policy.of([g.Token(token, "secret")]), "HEAD^1..HEAD")
    expected = blocked or (content == "structural" and relative == "notes.md")
    assert bool(out) is expected, out


def test_source3_documented_commit_message_shim_forwards_verdict(repo, tmp_path):
    from pathlib import Path
    import shutil
    from make_fixtures import write_commit_message_rule
    source = Path(GUARD).parent.parent
    doc = (source / "README.md").read_text(encoding="utf-8")
    script = doc.split("<!-- optional-commit-msg-shim -->", 1)[1].split("```sh\n", 1)[1].split("```", 1)[0]
    root = Path(repo.root)
    (root / ".githooks").mkdir()
    (root / ".githooks/commit-msg").write_text(script, encoding="utf-8")
    (root / ".githooks/commit-msg").chmod(0o755)
    (root / "guards/hooks").mkdir(parents=True)
    shutil.copyfile(source / "hooks/commit-msg", root / "guards/hooks/commit-msg")
    machine = tmp_path / "machine-hooks"
    write_commit_message_rule(machine)
    repo.git("config", "--global", "core.hooksPath", str(machine))
    repo.git("config", "core.hooksPath", ".githooks")
    receipt = tmp_path / "message-rule-called.txt"
    repo.env.update(FG_SYNTHETIC_RECEIPT=str(receipt), FG_SYNTHETIC_COMMIT_STATUS="0")
    repo.write("notes.md", "synthetic baseline\n")
    repo.commit("synthetic accepted message")
    before = repo.git("rev-parse", "HEAD").stdout
    repo.env["FG_SYNTHETIC_COMMIT_STATUS"] = "1"
    repo.write("notes.md", "synthetic change\n")
    repo.git("add", "notes.md")
    result = repo.git("commit", "-qm", "synthetic rejected message", allow_fail=True)
    assert result.returncode != 0
    assert repo.git("rev-parse", "HEAD").stdout == before
    assert receipt.read_text(encoding="utf-8").splitlines() == ["called", "called"]


def test_source2_future_visibility_cannot_downgrade_linkage(repo, tmp_path):
    vis = write_visibility(tmp_path / "future.json", {
        "example-owner/example-skill": "PUBLIC",
        "example-owner/example-skill-config": "PRIVATE",
    }, "2999-01-01T00:00:00Z")
    notes = []
    tokens = g.load_cross_repo_tokens(repo.root, str(vis), notes)
    assert [(t.value, t.kind) for t in tokens] == [("example-skill-config", "linkage")]
    assert "BLOCK" in sev_of("example-skill-config", g.Policy.of(tokens), "tree").values()
    assert any("future" in note.lower() for note in notes)


@pytest.mark.parametrize("relative", ["notes.md", "tools/pii_guard.py", "nested/[sample] résumé.md"])
def test_source2_staged_denylist_survives_clean_worktree(repo, relative):
    token = synthetic_token("staged-content")
    repo.write(relative, "# safe\n")
    repo.commit("synthetic baseline")
    repo.write(relative, "# " + token + "\n")
    repo.git("add", "--", relative)
    repo.write(relative, "# safe\n")
    out = g.scan_staged(repo.root, set(), g.Policy.of([g.Token(token, "secret")]))
    assert any(value == token and severity == "BLOCK" for _, _, value, severity in out), out


def test_source2_staged_added_plus_prefix_and_removal(repo):
    token = synthetic_token("plus-prefix")
    policy = g.Policy.of([g.Token(token, "secret")])
    repo.write("notes.md", "safe\n")
    repo.commit()
    repo.write("notes.md", "++" + token + "\n")
    repo.git("add", "notes.md")
    assert any(value == token for _, _, value, _ in g.scan_staged(repo.root, set(), policy))
    repo.git("commit", "-qm", "synthetic staged baseline")
    repo.write("notes.md", "safe\n")
    repo.git("add", "notes.md")
    assert g.scan_staged(repo.root, set(), policy) == []


def test_source2_staged_gitlink_needs_no_child_commit_object(repo):
    repo.write("seed.md", "synthetic seed\n")
    repo.commit()
    repo.git("update-index", "--add", "--cacheinfo", "160000", "1234567890abcdef1234567890abcdef12345678", "deps/kit")
    assert g.scan_staged(repo.root, set(), g.Policy.of([])) == []


def test_source2_history_paths_are_nul_delimited(repo):
    token = synthetic_token("nul-delimited-history")
    path = " leading\n" + token + "\tentry.txt"
    def pipe(*args, data):
        result = subprocess.run(["git", *args], cwd=repo.root, env=repo.env, input=data,
                                capture_output=True, text=True, encoding="utf-8", **_no_window())
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()
    blob = pipe("hash-object", "-w", "--stdin", data="harmless\n")
    tree = pipe("mktree", "-z", data="100644 blob %s\t%s\0" % (blob, path))
    commit = pipe("commit-tree", tree, data="synthetic path fixture\n")
    repo.git("update-ref", "HEAD", commit)
    out = g.scan_history(repo.root, set(), g.Policy.of([g.Token(token, "secret")]))
    assert any(path in where and value == token for where, _, value, _ in out), out


@pytest.mark.parametrize("relative", ["notes.md", "tools/pii_guard.py"])
def test_source2_native_hook_blocks_staged_bytes(repo, tmp_path, relative):
    from pathlib import Path
    import shutil
    source = Path(GUARD).parent.parent
    kit = tmp_path / "kit"
    (kit / "hooks").mkdir(parents=True)
    (kit / "tools").mkdir()
    for name in ("hooks/pre-commit", "tools/pii_guard.py", "tools/data_boundary.py", "tools/publication_guard.py"):
        shutil.copyfile(source / name, kit / name)
    (kit / "hooks/pre-commit").chmod(0o755)
    repo.git("remote", "remove", "origin")
    repo.git("config", "core.hooksPath", str(kit / "hooks"))
    token = synthetic_token("native-hook")
    policy = write_policy(tmp_path / "hook-policy.json", token, g.CANARY_TOKEN)
    repo.env["PII_DENYLIST"] = str(policy)
    repo.write(".dataclass.json", json.dumps({"data": [], "fixture": [], "_audited": "synthetic tool"}))
    repo.write(relative, "# safe\n")
    repo.commit("synthetic hook baseline")
    before = repo.git("rev-parse", "HEAD").stdout
    repo.write(relative, "# " + token + "\n")
    repo.git("add", "--", relative)
    repo.write(relative, "# safe\n")
    result = repo.git("commit", "-m", "synthetic blocked attempt", allow_fail=True)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "pre-commit BLOCKED by pii_guard" in result.stdout + result.stderr
    assert repo.git("rev-parse", "HEAD").stdout == before
    repo.write(relative, "# safe edited\n")
    repo.git("add", "--", relative)
    repo.git("commit", "-qm", "synthetic clean control")


def test_source2_history_names_include_deleted_aliases(repo):
    token = synthetic_token("historical-name")
    policy = g.Policy.of([g.Token(token, "secret")])
    paths = ["benign.md", "names/" + token + "/entry.md", "copies/" + token + ".txt"]
    for relative in paths:
        repo.write(relative, "same harmless body\n")
    repo.commit("synthetic aliases")
    repo.git("rm", "-r", "names", "copies")
    repo.git("commit", "-qm", "synthetic removal")
    assert g.scan_tree(repo.root, set(), policy) == []
    out = g.scan_history(repo.root, set(), policy)
    for relative in paths[1:]:
        assert any(relative in where and value == token and severity == "BLOCK"
                   for where, _, value, severity in out), out


def test_source2_history_aliases_keep_body_policy_and_deduplicate(repo, monkeypatch):
    for relative in ["tools/pii_guard.py", "plain.txt", "image.png"]:
        repo.write(relative, "harmless shared content\n")
    repo.commit("synthetic shared blob")
    original = g.scan_text
    body_calls = []
    def record(text, where, *args, **kwargs):
        if text == "harmless shared content\n":
            body_calls.append((where, kwargs.get("deny_only", False)))
        return original(text, where, *args, **kwargs)
    monkeypatch.setattr(g, "scan_text", record)
    stats = g._blank_history_stats()
    g.scan_history(repo.root, set(), g.Policy.of([]), stats)
    assert stats["blobs_total"] == stats["blobs_scanned"] == 1
    assert len(body_calls) == 1 and body_calls[0][1] is False, body_calls


@pytest.mark.parametrize("outcome", ["pass", "fail", "missing"])
def test_source2_ci_boundary_step_executes_and_propagates(tmp_path, outcome):
    from pathlib import Path
    import shutil
    action = Path(GUARD).parent.parent / "ci/pii-guard/action.yml"
    blocks = action.read_text(encoding="utf-8").split("    - name:")
    matches = [block for block in blocks if "test_data_boundary.py" in block]
    assert len(matches) == 1, "CI must unconditionally run the boundary regression suite"
    block = matches[0]
    body = block.split("      run: |\n", 1)[1]
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("        "):
            break
        lines.append(line[8:])
    consumer = tmp_path / "consumer"
    write_ci_suite(consumer, outcome)
    action_path = consumer / "guards/ci/pii-guard"
    action_path.mkdir(parents=True)
    if os.name == "nt":
        bash = Path(shutil.which("git")).parent.parent / "bin/bash.exe"
    else:
        bash = Path(shutil.which("bash"))
    assert bash.is_file(), "native Bash required to validate the CI run block"
    env = dict(os.environ, GITHUB_ACTION_PATH=action_path.as_posix())
    result = subprocess.run([str(bash), "--noprofile", "--norc", "-e", "-c", "\n".join(lines)],
                            cwd=consumer, env=env, capture_output=True, text=True, **_no_window())
    assert (result.returncode == 0) is (outcome == "pass"), result.stdout + result.stderr
    if outcome == "missing":
        assert "::error::" in result.stdout + result.stderr
    else:
        assert ("1 passed" if outcome == "pass" else "1 failed") in result.stdout + result.stderr


# ------------------------------------------------------------------ helpers
def write_denylist(tmp_path, tokens, fmt=2, count=None, canary=g.CANARY_TOKEN, extra=None):
    """A v2 denylist file. `tokens` is a list of (value, kind) or plain strings."""
    items = []
    for t in tokens:
        if isinstance(t, tuple):
            items.append({"value": t[0], "kind": t[1]})
        else:
            items.append({"value": t, "kind": "secret"})
    if canary and not any(i["value"] == canary for i in items):
        items.append({"value": canary, "kind": "secret"})
    doc = {"tokens": items}
    if fmt is not None:
        doc["format"] = fmt
    if canary:
        doc["canary"] = canary
    doc["count"] = len(items) if count is None else count
    if extra:
        doc.update(extra)
    # NOT named denylist.json: an assertion that looks for the word "denylist" in an error
    # message would then match the PATH in that message and pass no matter what the code did.
    p = tmp_path / "policy-fixture.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def _now_iso():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_vis(path, mapping, refreshed=None):
    """A visibility map fixture that models a HEALTHY machine unless told otherwise.

    The `_refreshed` stamp is not decoration: derivability only applies while the map is recent
    enough to be evidence, so a fixture without a stamp is a fixture of a broken machine. Tests
    that want the stale path say so explicitly by passing `refreshed`.
    """
    d = dict(mapping)
    d.setdefault("_refreshed", refreshed or _now_iso())
    path.write_text(json.dumps(d), encoding="utf-8")


def load(path, monkeypatch, root=None):
    monkeypatch.setenv("PII_DENYLIST", path)
    return g.load_policy(root)


def sev_of(text, pol, domain):
    out = []
    g.scan_text(text, "x", set(), pol, out, domain=domain)
    return {(k, v): s for _, k, v, s in out}


# ================================================================== derivability
def test_a_companion_of_a_PUBLIC_repo_is_derived_and_does_not_gate(tmp_path, monkeypatch):
    """The whole point of the second idea. `example-skill` is public and every public repo in
    this fleet documents the `<skill>-config` convention, so the companion name is something
    any reader can write down unaided. Enforcing it costs history rewrites and buys nothing."""
    vis = tmp_path / "vis.json"
    write_vis(vis, {
        "owner/example-skill": "PUBLIC",
        "owner/example-skill-config": "PRIVATE",
    })
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other-repo.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [t.value for t in toks] == ["example-skill-config"]
    assert toks[0].kind == "derived"


def test_a_companion_of_a_PRIVATE_repo_is_linkage_and_still_gates(tmp_path, monkeypatch):
    """The twin. Direction is load-bearing: if the parent is not public, nothing published
    points at this name, so it is not derivable from anything and keeps full force."""
    vis = tmp_path / "vis.json"
    write_vis(vis, {
        "owner/hidden-venture": "PRIVATE",
        "owner/hidden-venture-config": "PRIVATE",
    })
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other-repo.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [(t.value, t.kind) for t in toks] == [("hidden-venture-config", "linkage")]


def test_derivability_is_scoped_to_the_SAME_owner(tmp_path, monkeypatch):
    """A public repo under a different owner does not license our private name. The convention
    is per-account; borrowing another account's public name to excuse ours would be a hole."""
    vis = tmp_path / "vis.json"
    write_vis(vis, {
        "someone-else/example-skill": "PUBLIC",
        "owner/example-skill-config": "PRIVATE",
    })
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other-repo.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [(t.value, t.kind) for t in toks] == [("example-skill-config", "linkage")]


def test_a_private_repo_with_no_parent_at_all_is_linkage(tmp_path, monkeypatch):
    vis = tmp_path / "vis.json"
    write_vis(vis, {"owner/quiet-ledger-service": "PRIVATE"})
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other-repo.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [(t.value, t.kind) for t in toks] == [("quiet-ledger-service", "linkage")]


@pytest.mark.parametrize("suffix", list(g.CONVENTION_SUFFIXES))
def test_every_documented_suffix_derives(suffix, tmp_path, monkeypatch):
    vis = tmp_path / "vis.json"
    write_vis(vis, {
        "owner/example-skill": "PUBLIC",
        "owner/example-skill%s" % suffix: "PRIVATE",
    })
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other-repo.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    # some suffixes do not clear the distinctiveness filter on their own; when they are admitted
    # at all, they must be admitted as derived
    for t in toks:
        assert t.kind == "derived", (suffix, t.value, t.kind)


def test_an_undocumented_suffix_does_not_derive(tmp_path, monkeypatch):
    """Only the conventions we actually publish make a name derivable. `-backup` is not one of
    them, so nothing published points from the public name to this one."""
    vis = tmp_path / "vis.json"
    write_vis(vis, {
        "owner/example-skill": "PUBLIC",
        "owner/example-skill-backup-store": "PRIVATE",
    })
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other-repo.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [(t.value, t.kind) for t in toks] == [("example-skill-backup-store", "linkage")]


# ================================================================== the jurisdiction matrix
@pytest.mark.parametrize("domain", list(g.DOMAINS))
def test_secret_blocks_in_every_domain(domain):
    assert g.severity_for("secret", domain) == "BLOCK"


@pytest.mark.parametrize("domain", ["tree", "staged", "range"])
def test_linkage_blocks_in_live_domains(domain):
    """The relaxation is ONLY about the past. Adding a linkage token today is still a leak, and
    the fix is still one edit away, which is exactly why it should still be blocked."""
    assert g.severity_for("linkage", domain) == "BLOCK"


def test_linkage_is_debt_in_history_not_a_block():
    assert g.severity_for("linkage", "history") == "DEBT"


@pytest.mark.parametrize("domain", list(g.DOMAINS))
def test_derived_never_blocks_but_is_never_silent(domain):
    assert g.severity_for("derived", domain) == "WARN"


def test_an_unknown_kind_raises_rather_than_defaulting():
    """Defaulting an unknown kind to anything hides a version mismatch. Guessing 'secret' hides
    a guard that is newer than it thinks; guessing weaker hides a real token."""
    with pytest.raises(g.PolicyError):
        g.severity_for("banana", "tree")


def test_end_to_end_severity_of_a_linkage_hit(tmp_path, monkeypatch):
    pol = g.Policy()
    pol.tokens = [g.Token("hidden-venture-config", "linkage", source="cross-repo")]
    live = sev_of("we sync into hidden-venture-config", pol, "tree")
    past = sev_of("we sync into hidden-venture-config", pol, "history")
    assert list(live.values()) == ["BLOCK"]
    assert list(past.values()) == ["DEBT"]


def test_a_secret_hit_is_BLOCK_in_history_too():
    """The twin of the test above. Retroactive relief is a property of the KIND, not a general
    softening of history."""
    pol = g.Policy.of(["zzsecrettokenalpha"])
    past = sev_of("the zzsecrettokenalpha account", pol, "history")
    assert list(past.values()) == ["BLOCK"]


# ================================================================== loader self-attestation
def test_a_healthy_v2_file_loads_cleanly(tmp_path, monkeypatch):
    """THE NEGATIVE CONTROL FOR EVERY TEST BELOW. Without it, a loader that raised on all input
    would score a perfect fail-closed record."""
    p = write_denylist(tmp_path, [("zztokenone", "secret"), ("zztokentwo", "linkage")])
    pol = load(p, monkeypatch)
    # the canary is NOT among them: it is an attestation that the file arrived intact, not a
    # string to hunt for. Keeping it in the token set would make this very file a finding.
    assert sorted(t.value for t in pol.tokens) == ["zztokenone", "zztokentwo"]
    assert pol.denylist_present is True
    assert {t.kind for t in pol.tokens} == {"secret", "linkage"}


def test_missing_canary_raises(tmp_path, monkeypatch):
    p = write_denylist(tmp_path, ["zztokenone"])
    doc = json.loads(io.open(p, encoding="utf-8").read())
    doc["tokens"] = [t for t in doc["tokens"] if t["value"] != g.CANARY_TOKEN]
    doc["count"] = len(doc["tokens"])
    io.open(p, "w", encoding="utf-8").write(json.dumps(doc))
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_count_mismatch_raises(tmp_path, monkeypatch):
    """Deleting entries from a JSON array leaves valid JSON. This assertion is the only thing
    between a half-deleted policy and a green light."""
    p = write_denylist(tmp_path, ["zztokenone", "zztokentwo"], count=99)
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_truncated_json_raises(tmp_path, monkeypatch):
    p = write_denylist(tmp_path, ["zztokenone"])
    raw = io.open(p, encoding="utf-8").read()
    io.open(p, "w", encoding="utf-8").write(raw[:len(raw) // 2])
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_renamed_tokens_key_raises(tmp_path, monkeypatch):
    p = write_denylist(tmp_path, ["zztokenone"])
    doc = json.loads(io.open(p, encoding="utf-8").read())
    doc["denylist"] = doc.pop("tokens")
    io.open(p, "w", encoding="utf-8").write(json.dumps(doc))
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_utf16_encoded_file_raises(tmp_path, monkeypatch):
    p = write_denylist(tmp_path, ["zztokenone"])
    raw = io.open(p, encoding="utf-8").read()
    open(p, "wb").write(raw.encode("utf-16"))
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_empty_token_list_raises(tmp_path, monkeypatch):
    """An empty policy file and an absent one are different situations, and only one of them is
    reported honestly by saying nothing."""
    p = str(tmp_path / "empty.json")
    io.open(p, "w", encoding="utf-8").write(json.dumps({"format": 2, "tokens": [], "count": 0}))
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_a_future_format_raises_rather_than_silently_hardening(tmp_path, monkeypatch):
    p = write_denylist(tmp_path, ["zztokenone"], fmt=99)
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_an_unknown_kind_in_the_file_raises(tmp_path, monkeypatch):
    p = write_denylist(tmp_path, [("zztokenone", "secret")])
    doc = json.loads(io.open(p, encoding="utf-8").read())
    doc["tokens"][0]["kind"] = "totally-unknown"
    io.open(p, "w", encoding="utf-8").write(json.dumps(doc))
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_absent_file_is_a_legitimate_state_and_is_announced(tmp_path, monkeypatch):
    """CI has no such file and neither does a contributor. That must PASS, and it must say so:
    the difference between 'checked and clean' and 'this layer was not present' is the whole
    argument of this codebase."""
    monkeypatch.setenv("PII_DENYLIST", str(tmp_path / "nope.json"))
    pol = g.load_policy(None)
    assert pol.tokens == []
    assert pol.denylist_present is False


def test_v1_flat_list_still_loads(tmp_path, monkeypatch):
    """Back-compatibility is not politeness here. 18 repos carry a vendored copy of this file,
    and they are upgraded by a script that someone has to remember to run."""
    p = str(tmp_path / "v1.json")
    io.open(p, "w", encoding="utf-8").write(json.dumps({"tokens": ["zzalpha", "zzbeta"]}))
    pol = load(p, monkeypatch)
    assert sorted(t.value for t in pol.tokens) == ["zzalpha", "zzbeta"]
    assert all(t.kind == "secret" for t in pol.tokens)


def test_v1_bare_array_still_loads(tmp_path, monkeypatch):
    p = str(tmp_path / "v1b.json")
    io.open(p, "w", encoding="utf-8").write(json.dumps(["zzalpha"]))
    pol = load(p, monkeypatch)
    assert [t.value for t in pol.tokens] == ["zzalpha"]


# ================================================================== the matcher probe
def test_a_matcher_that_never_matches_is_caught(monkeypatch):
    """The failure mode this exists for: a comparison that silently answers 'no' to everything
    cannot be detected by observing that it answered 'no'. The machine-wide pre-commit hook
    learned this with its case-folding probe; this is the same move one layer down."""
    monkeypatch.setattr(g, "_deny_hit", lambda tok, low: False)
    with pytest.raises(g.PolicyError):
        g._probe_matcher()


def test_a_matcher_that_always_matches_is_also_caught(monkeypatch):
    monkeypatch.setattr(g, "_deny_hit", lambda tok, low: True)
    with pytest.raises(g.PolicyError):
        g._probe_matcher()


def test_the_real_matcher_passes_its_own_probe():
    g._probe_matcher()          # the negative control: it must not be a permanent alarm


# ================================================================== exemptions and the receipt
def _nonced(repo_key, entries):
    """Stamp each object entry with the nonce `grant` would have written.

    A fixture without one now models a HAND-WRITTEN exemption, which is a different thing and has
    its own test. Most of these fixtures mean to model a grant that went through the proper path.
    """
    out = []
    for e in entries:
        if isinstance(e, dict) and "nonce" not in e:
            e = dict(e, nonce=g._nonce_for(repo_key, e.get("token", "")))
        out.append(e)
    return out


def _exempt(tmp_path, monkeypatch, payload):
    home = tmp_path / "home"
    (home / ".pii-guard").mkdir(parents=True)
    payload = {k: (_nonced(k, v) if isinstance(v, list) else v) for k, v in payload.items()}
    (home / ".pii-guard" / "denylist-exempt.json").write_text(json.dumps(payload),
                                                              encoding="utf-8")
    monkeypatch.setattr(g.os.path, "expanduser",
                        lambda p: p.replace("~", str(home)) if p.startswith("~") else p)
    monkeypatch.setattr(g, "_repo_slug", lambda root: ("owner/scanned-repo", "scanned-repo"))
    notes = []
    return g.load_grants(".", notes), notes


def test_a_valid_history_only_grant_is_loaded(tmp_path, monkeypatch):
    grants, notes = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "hidden-venture-config", "scope": "history-only",
         "reason": "written before that repo existed"}]})
    assert len(grants) == 1 and grants[0].scope == "history-only"
    assert notes == []
def test_scope_all_needs_its_own_sentence(tmp_path, monkeypatch):
    grants, notes = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "zztok", "scope": "all", "reason": "x"}]})
    assert grants == []
    assert any("all_scope_reason" in n for n in notes)


def test_scope_all_is_accepted_when_justified(tmp_path, monkeypatch):
    grants, _ = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "zztok", "scope": "all", "reason": "x",
         "all_scope_reason": "the token is a common English word in this repo"}]})
    assert len(grants) == 1 and grants[0].scope == "all"


def test_a_block_keyed_on_a_bare_repo_name_is_reported_as_inert(tmp_path, monkeypatch):
    """The most likely way to be wrong here, and the one that used to be completely silent: the
    file looks right, applies to nothing, and nothing says so."""
    grants, notes = _exempt(tmp_path, monkeypatch, {"scanned-repo": [
        {"token": "zztok", "scope": "history-only", "reason": "x"}]})
    assert grants == []
    assert any("owner/name" in n for n in notes)


def test_the_receipt_counts_grants_that_never_fired(tmp_path, monkeypatch):
    grants, _ = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "a-token-nothing-will-hit", "scope": "history-only",
         "reason": "x"}]})
    pol = g.Policy()
    pol.grants = grants
    pol.tokens = [g.Token("zzother", "secret")]
    out = []
    g.scan_text("zzother appears here", "x", set(), pol, out, domain="tree")
    r = pol.receipt()
    assert r and "1 declared" in r and "0 suppressed" in r and "1 never fired" in r


def test_a_history_only_grant_relaxes_history_but_not_the_tree(tmp_path, monkeypatch):
    """The twin that keeps the exit honest. An exemption for the past is not an exemption for
    what you are writing right now."""
    grants, _ = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "zzaccepted", "scope": "history-only", "reason": "already disclosed"}]})
    pol = g.Policy()
    pol.grants = grants
    pol.tokens = [g.Token("zzaccepted", "secret")]
    assert list(sev_of("zzaccepted here", pol, "history").values()) == ["WARN"]
    pol2 = g.Policy()
    pol2.grants = list(grants)
    pol2.tokens = [g.Token("zzaccepted", "secret")]
    assert list(sev_of("zzaccepted here", pol2, "tree").values()) == ["BLOCK"]


# ================================================================== the nonce
def test_the_nonce_is_stable_and_repo_scoped():
    a = g._nonce_for("owner/repo-one", "zztok")
    b = g._nonce_for("owner/repo-two", "zztok")
    assert a == g._nonce_for("owner/repo-one", "zztok")     # stateless and reproducible
    assert a != b                                            # a slip for one repo is not a slip
    assert len(a) == 8
def test_an_empty_v1_file_raises_even_with_no_canary_to_check(tmp_path, monkeypatch):
    """The v2 file is also caught by the canary assertion, which MASKED this one: the empty-list
    check could be deleted entirely and the suite stayed green. A v1-format file has no canary,
    so only the empty check stands between it and a silently disabled layer."""
    p = str(tmp_path / "v1empty.json")
    io.open(p, "w", encoding="utf-8").write(json.dumps({"tokens": []}))
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_load_policy_ITSELF_refuses_when_the_matcher_is_broken(tmp_path, monkeypatch):
    """The probe had tests, but they all called _probe_matcher directly. Removing the CALL from
    load_policy therefore changed nothing observable: the probe existed and was never run."""
    p = write_denylist(tmp_path, ["zztokenone"])
    monkeypatch.setattr(g, "_deny_hit", lambda tok, low: False)
    monkeypatch.setenv("PII_DENYLIST", p)
    with pytest.raises(g.PolicyError):
        g.load_policy(None)


def test_malformed_json_raises_from_read_json_itself(tmp_path, monkeypatch):
    """Pinned at the lowest level, so a caller that grows its own try/except cannot re-open the
    fail-open by accident."""
    p = tmp_path / "bad.json"
    p.write_text("{ not json at all", encoding="utf-8")
    with pytest.raises(g.PolicyError):
        g._read_json(str(p))


def test_grant_for_respects_the_domain_boundary_on_its_own(tmp_path, monkeypatch):
    """scan_text re-checks the scope, which masked a grant_for that handed back a history-only
    grant in every domain. Two layers agreeing is fine; two layers where only one is tested is
    how the untested one rots."""
    pol = g.Policy()
    pol.grants = [g.Grant("zztok", "history-only", "x")]
    assert pol.grant_for("zztok", "history") is not None
    assert pol.grant_for("zztok", "tree") is None
    assert pol.grant_for("zztok", "staged") is None
    pol2 = g.Policy()
    pol2.grants = [g.Grant("zztok", "all", "x")]
    assert pol2.grant_for("zztok", "tree") is not None      # the twin: scope=all does reach live


def test_a_renamed_tokens_key_is_named_in_the_error(tmp_path, monkeypatch):
    """A second mutation survivor. Deleting the dedicated `tokens`-is-missing check left the
    generic type check to catch it, so the file still failed, but with a message that talked
    about types instead of naming the key that was actually wrong. The operator staring at a
    typo needs to be told which key they typed."""
    p = write_denylist(tmp_path, ["zztokenone"])
    doc = json.loads(io.open(p, encoding="utf-8").read())
    doc["tokenz"] = doc.pop("tokens")          # a typo, the realistic version of this mistake
    io.open(p, "w", encoding="utf-8").write(json.dumps(doc))
    with pytest.raises(g.PolicyError) as ei:
        load(p, monkeypatch)
    assert "tokenz" in str(ei.value), str(ei.value)


def test_the_receipt_counts_a_grant_that_DID_fire(tmp_path, monkeypatch):
    """The twin of the never-fired test, and another mutation survivor: with `used` never set,
    the receipt reported every grant as inert, which reads as an alarm and is pure noise. A
    counter is only meaningful if it can move in both directions."""
    grants, _ = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "zzaccepted", "scope": "history-only", "reason": "already disclosed"}]})
    pol = g.Policy()
    pol.grants = grants
    pol.tokens = [g.Token("zzaccepted", "secret")]
    out = []
    g.scan_text("zzaccepted appears here", "x", set(), pol, out, domain="history")
    r = pol.receipt()
    assert "1 declared" in r and "1 suppressed" in r and "0 never fired" in r


def test_the_canary_is_never_treated_as_a_token_to_search_for(tmp_path, monkeypatch):
    """pii_guard.py has to contain the canary string in order to check for it, and pii_guard.py
    is vendored into every public repo and scanned there. If the canary were policy, the guard
    would flag itself in eighteen places on the day the file was migrated."""
    p = write_denylist(tmp_path, ["zztokenone"])
    pol = load(p, monkeypatch)
    assert g.CANARY_TOKEN not in [t.value for t in pol.tokens]
    out = []
    g.scan_text("a line mentioning %s here" % g.CANARY_TOKEN, "x", set(), pol, out, domain="tree")
    assert out == []


# ================================================================== round 2: adversarial findings
# Everything below pins a defect that survived the first version of the redesign and was found by
# pointing attackers at it. Each was reproduced by hand before it was written down.

B = chr(92)


def _hits(text, allow=(), tokens=(), domain="tree"):
    out = []
    g.scan_text(text, "x", set(allow), g.Policy.of(tokens), out, domain=domain)
    return [(k, v) for _, k, v, _s in out]


def test_a_windows_home_path_with_DOUBLED_backslashes_is_caught():
    """Every JSON config and every non-raw source line writes it this way. The single-backslash
    form was caught and this one was missed, in the category the audit found leaking most."""
    kinds = {k for k, _ in _hits('{"home": "C:%sUsers%sjanedoe%swork"}' % (B + B, B + B, B + B))}
    assert "USER-PATH" in kinds


def test_the_single_backslash_form_still_works():
    assert "USER-PATH" in {k for k, _ in _hits("C:%sUsers%sjanedoe%sx" % (B, B, B))}


def test_a_generic_account_in_the_doubled_form_is_still_not_a_person():
    assert not _hits('{"home": "C:%sUsers%srunner%swork"}' % (B + B, B + B, B + B))


def test_zip_the_archive_format_is_not_a_postcode():
    assert not _hits("the zip archive is 45231 bytes")


def test_zip_the_postcode_still_fires():
    """The twin. Fixing the archive meaning must not cost the postal one."""
    assert "ZIP" in {k for k, _ in _hits("zip code 08540 for returns")}
    assert "ZIP" in {k for k, _ in _hits("ZIP 08540")}
    assert "ZIP" in {k for k, _ in _hits("ship to NJ 08540")}


def test_a_tensor_shape_is_not_a_phone_number():
    """This machine's pre-commit hook runs in every repo on it, including forks of training
    frameworks, so this false positive is a blocked commit in somebody else's project."""
    assert not _hits("conv kernel 512-256-1024 stack")
    assert not _hits("hidden dim 512-256-1024")


def test_a_phone_number_near_ml_words_still_fires_when_it_is_shaped_like_one():
    """Context yields only for the hyphen-only form. Parentheses, a +1, dots or spaces are shapes
    a tensor shape never takes, so they are never excused."""
    assert "PHONE" in {k for k, _ in _hits("kernel size, then call (201) 867-5309 for data")}
    assert "PHONE" in {k for k, _ in _hits("layer dims, tel +1 201-867-5309")}


def test_a_bare_hyphen_triple_with_no_dimension_word_is_still_a_finding():
    assert "PHONE" in {k for k, _ in _hits("reach me on 201-867-5309")}


def test_a_generic_pii_allow_entry_is_not_an_off_switch():
    """`.pii-allow` lives INSIDE the repo. An unanchored substring test made one common word an
    in-repo off switch for an entire class. Measured: both of these silenced everything."""
    path = "C:%sUsers%sjanedoe%ssecret.txt" % (B, B, B)
    assert "USER-PATH" in {k for k, _ in _hits(path, allow={"users"})}
    assert "USER-PATH" in {k for k, _ in _hits(path, allow={"a"})}


def test_a_specific_pii_allow_entry_still_exempts():
    """The twin that keeps the escape hatch open. Removing the hatch is not a fix."""
    assert not _hits('RUNNER = "~/.claude/scripts/self.ps1"',
                     allow={".claude/scripts/self.ps1"})
    # short, but a dotted directory name rather than an English word
    assert not _hits("config lives under ~/.claude/settings.json", allow={".claude"})


def test_scanner_exemption_is_keyed_on_PATH_not_basename():
    """`git mv secrets.md docs/pii_guard.py` used to buy a file, anywhere in the repo, that
    skipped every structural check."""
    assert g.is_scanner_path("tools/pii_guard.py")
    assert not g.is_scanner_path("docs/pii_guard.py")
    assert g.is_scanner_path(".pii-allow")          # and NOT mangled by lstrip("./")


def test_a_copy_elsewhere_proves_itself_with_the_marker():
    """skill-smith ships a copy of the guard as a template asset at a non-standard path. Identity,
    not location: a renamed secrets file cannot produce the marker."""
    assert g.is_scanner_content("assets/pii-guard/pii_guard.py", "# " + g.SCANNER_MARKER + "\n...")
    assert not g.is_scanner_content("docs/pii_guard.py", "contact jane.doe@gmail.com\n")


@pytest.mark.parametrize("enc", ["utf-16", "cp1252"])
def test_text_that_is_not_utf8_is_still_read(enc):
    """A UTF-16 file was invisible in every domain at once: the tree skipped it on a decode error
    and git marks it binary in diffs. Not UTF-8 is not not-text."""
    text, got = g._decode_best("contact jane.doe@gmail.com".encode(enc))
    assert text is not None and "jane.doe" in text, got


def test_genuinely_binary_content_is_refused_rather_than_force_decoded():
    """The twin. UTF-16 and cp1252 decode almost anything, so without a text check a PNG came back
    as `utf-16` and counted as EXAMINED, which is the opposite of the property being added."""
    png = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] * 200)
    assert g._decode_best(png) == (None, None)


def test_the_prefilter_returns_exactly_what_the_naive_loop_returns():
    """The prefilter is an optimisation, and an optimisation that changes answers is a bug with a
    benchmark attached. Alternation is leftmost-first, so if it were used to READ the matches
    instead of just to decide whether to look, a longer token would shadow a shorter one -- and if
    the longer were `derived` while the shorter were `secret`, that would silently downgrade a real
    finding."""
    toks = [g.Token("zzalpha", "secret"), g.Token("zzalphabeta", "derived"),
            g.Token("zz-9137", "secret"), g.Token("zzgamma", "linkage")]
    pol = g.Policy()
    pol.tokens = toks
    samples = ["nothing here at all", "zzalpha", "zzalphabeta", "a zzalpha and zzalphabeta",
               "zz-9137 inside", "xxzzalphaxx", "ZZALPHA upper", "", "zzgamma zzalpha zz-9137"]
    for text in samples:
        low = text.lower()
        naive = sorted(t.value for t in toks if g._deny_hit(t.value, low))
        out = []
        g.scan_text(text, "x", set(), pol, out, domain="tree")
        got = sorted(v.split(" (")[0] for _w, lab, v, _s in out if "DENYLIST" in lab)
        assert naive == got, (text, naive, got)


def test_a_derived_verdict_exhibits_its_witness(tmp_path, monkeypatch):
    """A declassification that cannot show its own derivation is an assertion. The witness names
    the public parent, so a reader can check the claim instead of trusting it."""
    vis = tmp_path / "vis.json"
    write_vis(vis, {"owner/example-skill": "PUBLIC",
                               "owner/example-skill-config": "PRIVATE"})
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    tok = g.load_cross_repo_tokens(".", vis_path=str(vis))[0]
    assert tok.kind == "derived"
    assert tok.witness and "example-skill" in tok.witness and "PUBLIC" in tok.witness


def test_a_linkage_token_has_no_witness_to_show():
    assert g.Token("hidden-venture-config", "linkage").witness is None


# ================================================================== round 2, part 2
# These pin behaviours that only the scenario corpus covered. The corpus is the better evidence
# (it drives the real CLI end to end) but it is far too slow to run under mutation testing, and a
# behaviour that only a slow suite protects is a behaviour the fast suite will silently break.
# Fourteen mutants survived until these existed.

import subprocess  # noqa: E402

GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pii_guard.py")


class Repo(object):
    """A throwaway git repo with an isolated config, so the machine's real hooks and identity
    rules never fire inside a test."""

    def __init__(self, root):
        self.root = str(root)
        self.cfg = os.path.join(self.root, "..", "gitconfig")
        with io.open(self.cfg, "w", encoding="utf-8") as f:
            f.write("[user]\n\tname = Fixture\n\temail = fixture@users.noreply.github.com\n"
                    "[init]\n\tdefaultBranch = master\n[core]\n\thooksPath = %s\n"
                    % os.path.join(self.root, "..", "nohooks").replace(chr(92), "/"))
        self.env = dict(os.environ)
        self.env["GIT_CONFIG_GLOBAL"] = self.cfg
        self.env["GIT_CONFIG_SYSTEM"] = os.path.join(self.root, "..", "nosys")
        self.git("init", "-q")
        self.git("remote", "add", "origin",
                 "https://github.com/exampleowner/scanned-repo.git")

    def git(self, *args, **kw):
        p = subprocess.run(["git"] + list(args), cwd=self.root, env=self.env,
                           capture_output=True, text=True, **_no_window())
        if p.returncode != 0 and not kw.get("allow_fail"):
            raise RuntimeError("git %s: %s" % (" ".join(args), p.stderr))
        return p

    def write(self, rel, text, mode="w"):
        p = os.path.join(self.root, rel)
        d = os.path.dirname(p)
        if d and not os.path.isdir(d):
            os.makedirs(d)
        if "b" in mode:
            open(p, "wb").write(text)
        else:
            io.open(p, "w", encoding="utf-8", newline="\n").write(text)

    def commit(self, msg="c"):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    return Repo(d)


def _labels(findings):
    return {lab for _w, lab, _v, _s in findings}


def test_a_real_address_in_a_FILE_NAME_is_a_finding(repo):
    """Only file CONTENT was ever scanned. A filename is as public as the bytes inside it."""
    repo.write("contacts/jane.doe@gmail.com.md", "nothing in here\n")
    repo.commit()
    out = g.scan_tree(repo.root, set(), g.Policy.of([]))
    # EMAIL rather than PERSONAL-MAILBOX, because the `.md` suffix makes the domain
    # `gmail.com.md` and the consumer-provider rule matches the exact domain. Either label is a
    # BLOCK, and pinning the label here would be pinning an accident of the file extension.
    assert out and all(sev == "BLOCK" for _w, _l, _v, sev in out), out
    # ...and with no extension in the way it is recognised as exactly what it is
    repo.write("contacts/jane.doe@gmail.com", "nothing in here\n")
    repo.commit()
    assert "PERSONAL-MAILBOX" in _labels(g.scan_tree(repo.root, set(), g.Policy.of([])))


def test_an_ordinary_filename_is_not_a_finding(repo):
    repo.write("docs/release-notes-2026.md", "ordinary\n")
    repo.commit()
    assert g.scan_tree(repo.root, set(), g.Policy.of([])) == []


def _merge_in_and_out(repo, token):
    repo.write("f.md", "base\n")
    repo.commit("base")
    repo.git("checkout", "-qb", "side")
    repo.write("f.md", "side\n")
    repo.commit("side")
    repo.git("checkout", "-q", "master")
    repo.write("f.md", "main\n")
    repo.commit("main")
    repo.git("merge", "side", "--no-commit", allow_fail=True)
    repo.write("f.md", "resolved with %s\n" % token)      # from neither parent
    repo.commit("merge one")
    repo.git("checkout", "-qb", "side2", "HEAD~1")
    repo.write("g.md", "other\n")
    repo.commit("side two")
    repo.git("checkout", "-q", "master")
    repo.git("merge", "side2", "--no-commit", allow_fail=True)
    repo.write("f.md", "resolved\n")                      # and out again
    repo.commit("merge two")


def test_content_that_exists_only_in_a_merge_is_still_found(repo):
    """`git log --all -p` prints nothing for a merge, so a conflict resolution is absent from the
    diff stream; a second merge removing it keeps it out of every ordinary commit's diff too. The
    blob is in the object store and will be pushed. Both earlier versions printed clean."""
    tok = "zzmergeonlytoken"
    _merge_in_and_out(repo, tok)
    assert tok not in repo.git("log", "--all", "-p").stdout        # the premise, checked
    out = g.scan_history(repo.root, set(), g.Policy.of([tok]))
    assert out, "the object graph walk missed a blob that is in the repository"


def test_an_ordinary_merge_does_not_become_a_finding(repo):
    """The twin: the object walk must not turn clean history into findings."""
    _merge_in_and_out(repo, "nothing private here")
    assert g.scan_history(repo.root, set(), g.Policy.of(["zzmergeonlytoken"])) == []


def test_a_merge_resolution_is_scanned_in_the_push_range(repo):
    tok = "zzmergerangetoken"
    repo.write("f.md", "base\n")
    repo.commit("base")
    repo.git("checkout", "-qb", "side")
    repo.write("f.md", "side\n")
    repo.commit("side")
    repo.git("checkout", "-q", "master")
    repo.write("f.md", "main\n")
    repo.commit("main")
    repo.git("merge", "side", "--no-commit", allow_fail=True)
    repo.write("f.md", "resolved with %s\n" % tok)
    repo.commit("merge")
    out = g.scan_range(repo.root, set(), g.Policy.of([tok]), "HEAD^1..HEAD")
    assert out, "the machine-wide pre-push gate is blind to conflict resolutions"


def test_an_oversize_blob_is_recorded_rather_than_silently_skipped(repo, monkeypatch):
    """A silent size cap is a hole with a performance justification attached."""
    monkeypatch.setattr(g, "MAX_BLOB_BYTES", 64)
    make_sized_history_fixture(repo, 4096)
    stats = g._blank_history_stats()
    with pytest.raises(g.ScanIncompleteError, match="history blob"):
        g.scan_history(repo.root, set(), g.Policy.of([]), stats=stats)
    assert stats["blobs_oversize"], "the cap left no trace"


@pytest.mark.parametrize("with_tree", [False, True])
def test_native_oversize_history_refuses_publication(repo, with_tree):
    make_sized_history_fixture(repo, g.MAX_BLOB_BYTES + 1)
    arguments = ["--history", "--tree"] if with_tree else ["--history"]
    status, output = _cli(repo, *arguments)
    assert status == 2, output
    assert "SCAN INCOMPLETE" in output
    assert "pii_guard: clean" not in output


def test_native_history_within_limit_still_detects_tokens(repo):
    from pathlib import Path

    token = make_sized_history_fixture(repo, 4096)
    policy = write_policy(Path(repo.root).parent / "sized-policy.json", token, g.CANARY_TOKEN)
    repo.env["PII_DENYLIST"] = str(policy)
    status, output = _cli(repo, "--history")
    assert status == 1, output
    assert "SCAN INCOMPLETE" not in output


def _cli(repo, *args):
    env = dict(repo.env)
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run([sys.executable, GUARD, "--repo", repo.root] + list(args),
                       cwd=repo.root, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", **_no_window())
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def test_a_run_that_skipped_something_does_not_call_itself_clean(repo, monkeypatch):
    """The distinction the whole codebase is about: checked and found nothing, versus did not
    look."""
    monkeypatch.delenv("PII_DENYLIST", raising=False)
    repo.env.pop("PII_DENYLIST", None)
    repo.write("keep.md", "ordinary\n")
    repo.write("blob.bin", bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] * 200), "wb")
    repo.commit()
    rc, out = _cli(repo, "--tree")
    assert rc == 0
    assert "pii_guard: clean" not in out, out


def test_a_clean_run_over_everything_DOES_call_itself_clean(repo, monkeypatch):
    """The twin. Without it, never printing the word would score perfectly."""
    monkeypatch.delenv("PII_DENYLIST", raising=False)
    repo.env.pop("PII_DENYLIST", None)
    repo.write("keep.md", "ordinary\n")
    repo.commit()
    rc, out = _cli(repo, "--tree")
    assert rc == 0 and "pii_guard: clean" in out, out


def _grant(repo, tmp_path, home_name, token, content):
    home = str(tmp_path / home_name)
    os.makedirs(os.path.join(home, ".pii-guard"), exist_ok=True)
    dl = os.path.join(home, "denylist.json")
    io.open(dl, "w", encoding="utf-8").write(json.dumps(
        {"format": 2, "canary": g.CANARY_TOKEN, "count": 2,
         "tokens": [{"value": token, "kind": "secret"},
                    {"value": g.CANARY_TOKEN, "kind": "secret"}]}))
    env = dict(repo.env)
    env["PII_DENYLIST"] = dl
    env["USERPROFILE"] = env["HOME"] = home
    repo.write("keep.md", content)
    repo.commit()
    nonce = g._nonce_for("exampleowner/scanned-repo", token)
    p = subprocess.run([sys.executable, GUARD, "grant", "--repo", repo.root,
                        "--token", token, "--reason", "testing", "--nonce", nonce],
                       cwd=repo.root, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", **_no_window())
    return p, home


def test_grant_refuses_when_the_token_produces_no_finding(repo, tmp_path):
    """The nonce is offline-computable, so it is a typo barrier and not proof. The proof is the
    scan: an exemption for a finding nobody has hit is a pre-emptive silence."""
    p, _home = _grant(repo, tmp_path, "home_a", "zzgranttesttoken", "nothing private here\n")
    assert p.returncode != 0
    assert "no finding" in (p.stdout + p.stderr)


def test_grant_accepts_when_the_token_really_is_live(repo, tmp_path):
    """The twin, and the one that keeps the exit reachable."""
    p, home = _grant(repo, tmp_path, "home_b", "zzgranttesttoken",
                     "we reference zzgranttesttoken here\n")
    assert p.returncode == 0, p.stdout + p.stderr
    # The exemption FILE is the record. There used to be a second append-only log beside it; it
    # lived in the same directory with the same owner, so the hand that can edit an exemption could
    # truncate it with one more open, and it stored only a digest of each token by design, so it
    # could never have rebuilt the exemptions either. A second copy sharing the whole attack
    # surface of the first is not redundancy.
    written = os.path.join(home, ".pii-guard", "denylist-exempt.json")
    assert os.path.exists(written)
    entry = json.load(io.open(written, encoding="utf-8"))["exampleowner/scanned-repo"][0]
    assert entry["token"] == "zzgranttesttoken"
    assert entry["reason"] and entry["granted_utc"] and entry["nonce"]
    assert not os.path.exists(os.path.join(home, ".pii-guard", "grant-log.jsonl"))


def test_a_derived_finding_prints_its_witness():
    pol = g.Policy()
    pol.tokens = [g.Token("example-skill-config", "derived", source="cross-repo",
                          witness="owner/example-skill is PUBLIC")]
    out = []
    g.scan_text("we write to example-skill-config", "x", set(), pol, out, domain="tree")
    assert out and "(from owner/example-skill is PUBLIC)" in out[0][2]


def test_a_short_repo_name_does_not_exempt_its_unrelated_siblings(tmp_path, monkeypatch):
    vis = tmp_path / "vis2.json"
    write_vis(vis, {"owner/ab": "PUBLIC", "owner/ab-config": "PRIVATE",
                               "owner/ab-hidden-thing": "PRIVATE"})
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/ab.git\n")
    vals = [t.value for t in g.load_cross_repo_tokens(".", vis_path=str(vis))]
    assert "ab-hidden-thing" in vals          # an unrelated private sibling
    assert "ab-config" not in vals            # the twin: this repo's OWN companion


def test_a_single_hyphen_data_companion_is_admitted(tmp_path, monkeypatch):
    vis = tmp_path / "vis3.json"
    write_vis(vis, {"owner/pubtool": "PUBLIC", "owner/pubtool-data": "PRIVATE"})
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [(t.value, t.kind) for t in toks] == [("pubtool-data", "derived")]


def test_an_unknown_visibility_state_is_reported(tmp_path, monkeypatch):
    vis = tmp_path / "vis4.json"
    write_vis(vis, {"owner/x-y-z": "ARCHIVED"})
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    notes = []
    g.load_cross_repo_tokens(".", vis_path=str(vis), notes=notes)
    assert any("visibility state" in n for n in notes)


def test_an_absent_visibility_map_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    notes = []
    g.load_cross_repo_tokens(".", vis_path=str(tmp_path / "nope.json"), notes=notes)
    assert any("no visibility map" in n for n in notes)


def test_a_legacy_shaped_policy_file_is_announced(tmp_path, monkeypatch):
    p = str(tmp_path / "legacy.json")
    io.open(p, "w", encoding="utf-8").write(json.dumps({"tokens": ["zzalpha"]}))
    monkeypatch.setenv("PII_DENYLIST", p)
    pol = g.load_policy(None)
    assert any("legacy format" in n for n in pol.notes), pol.notes


def test_a_canary_only_policy_file_is_refused(tmp_path, monkeypatch):
    p = str(tmp_path / "canaryonly.json")
    io.open(p, "w", encoding="utf-8").write(json.dumps(
        {"format": 2, "canary": g.CANARY_TOKEN, "count": 1,
         "tokens": [{"value": g.CANARY_TOKEN, "kind": "secret"}]}))
    with pytest.raises(g.PolicyError):
        load(p, monkeypatch)


def test_a_legacy_BARE_ARRAY_policy_file_is_also_announced(tmp_path, monkeypatch):
    """Two code paths reach the same warning and only one was tested, so the untested one could be
    deleted and the suite stayed green. A bare JSON array is the oldest shape of this file."""
    p = str(tmp_path / "legacy_array.json")
    io.open(p, "w", encoding="utf-8").write(json.dumps(["zzalpha", "zzbeta"]))
    monkeypatch.setenv("PII_DENYLIST", p)
    pol = g.load_policy(None)
    assert any("legacy format" in n for n in pol.notes), pol.notes


def test_a_tracked_path_with_a_leading_space_is_still_scanned(repo):
    """`git ls-files -z` makes the separator unambiguous, so trimming each entry is not just
    unnecessary, it corrupts paths that legitimately begin or end with whitespace. The file then
    fails to open and is recorded as unreadable -- honest, and still a miss.

    Found by the self-evolve proposer: `tracked_files` documented that stripping was wrong while
    `scan_tree` still stripped. A comment disagreeing with the code under it is precisely what an
    automated reader is good at noticing."""
    repo.write(" leading space.md", "contact jane.doe@gmail.com\n")
    repo.commit()
    stats = {}
    out = g.scan_tree(repo.root, set(), g.Policy.of([]), stats=stats)
    assert stats.get("scanned") == 1, stats
    assert not stats.get("unreadable"), stats
    assert "PERSONAL-MAILBOX" in _labels(out)


def _stage_edit(repo, rel):
    repo.write("seed.md", "seed\n")
    repo.commit("seed")
    repo.write(rel, "# fixture line mentioning jane.doe@gmail.com\n")
    repo.git("add", "-A")
    return g.scan_staged(repo.root, set(), g.Policy.of([]))


def test_editing_the_vendored_v2_test_file_is_not_blocked_by_its_own_fixtures(repo):
    """`test_pii_guard_v2.py` went into SCANNER_FILES and not into the diff-domain exclusion, so
    staging an edit to the vendored copy was blocked by the test's own synthetic mailbox. Verified
    2026-08-20 with a matched control. Found by the self-evolve proposer.

    The exclusion is now DERIVED from SCANNER_PATHS, so the two lists cannot drift again."""
    assert _stage_edit(repo, "tools/test_pii_guard_v2.py") == []


def test_the_other_two_scanner_files_are_still_exempt_in_the_diff_domains(repo):
    assert _stage_edit(repo, "tools/pii_guard.py") == []


def test_a_scanner_BASENAME_elsewhere_is_NOT_exempt_in_the_diff_domains(repo):
    """The exclusion used to be a `*basename` glob, so any file called pii_guard.py anywhere was
    dropped from the staged and range scans. Same shadow the tree domain had, same fix."""
    out = _stage_edit(repo, "docs/pii_guard.py")
    assert out and any(lab == "PERSONAL-MAILBOX" for _w, lab, _v, _s in out), out


@pytest.mark.parametrize("path,expect_finding", [
    ("~/.claude-plugin/plugin.json", False),        # the public manifest convention
    ("~/.claude-plugin", False),
    ("~/.claude-plugins-private/keys.json", True),  # NOT the convention, merely starts like it
    ("~/.claude/skills/example-skill", False),      # a shallow install dir, also a convention
    ("~/.claude/scripts/relay.py", True),           # a deep path into a private tool
])
def test_the_public_dotpath_convention_needs_a_word_boundary(path, expect_finding):
    """Without `\b` after `-plugin`, any dotdir whose name STARTS with `.claude-plugin` counted
    as the public manifest convention. Proposed by the self-evolve proposer."""
    got = "PRIVATE-PATH" in {k for k, _ in _hits('P = "%s"' % path)}
    assert got is expect_finding, (path, got)


# ================================================================== the map has an age
# `derived` is the one verdict here that RELAXES something, and its whole justification is a claim
# about the outside world: the parent repo is public, so this name discloses nothing. A claim has an
# age, and until 2026-08-20 nothing read the `_refreshed` stamp that sits in the map. A five-year-old
# map still granted the downgrade, silently. Same shape as everything this redesign removed, pointing
# the permissive way, introduced by the redesign.

def _aged(days):
    import datetime
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _typed(tmp_path, monkeypatch, refreshed, name="vis-age.json"):
    vis = tmp_path / name
    write_vis(vis, {"owner/example-skill": "PUBLIC",
                    "owner/example-skill-config": "PRIVATE"}, refreshed=refreshed)
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    notes = []
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis), notes=notes)
    return toks, notes


def test_a_fresh_map_grants_the_derived_downgrade(tmp_path, monkeypatch):
    """The control. Everything below is worthless if the healthy path stops working."""
    toks, notes = _typed(tmp_path, monkeypatch, _aged(0))
    assert [(t.value, t.kind) for t in toks] == [("example-skill-config", "derived")]
    assert not [n for n in notes if "old" in n]


def test_a_map_past_the_maximum_age_stops_voting_on_derivability(tmp_path, monkeypatch):
    """Strict is the safe direction, and it is also what this guard did before derivability
    existed: the name goes back to gating."""
    toks, notes = _typed(tmp_path, monkeypatch, _aged(45))
    assert [(t.value, t.kind) for t in toks] == [("example-skill-config", "linkage")]
    assert toks[0].witness is None          # no witness, because there is no claim to stand behind
    assert any("days old" in n for n in notes), notes


def test_a_map_with_no_refreshed_stamp_is_not_evidence(tmp_path, monkeypatch):
    """A map whose age cannot be established is treated as one that is too old. There is no third
    answer: `derived` needs a claim you can date."""
    vis = tmp_path / "vis-nostamp.json"
    vis.write_text(json.dumps({"owner/example-skill": "PUBLIC",
                               "owner/example-skill-config": "PRIVATE"}), encoding="utf-8")
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    notes = []
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis), notes=notes)
    assert [(t.value, t.kind) for t in toks] == [("example-skill-config", "linkage")]
    assert any("no _refreshed stamp" in n for n in notes), notes


def test_an_unparseable_stamp_is_treated_the_same_way(tmp_path, monkeypatch):
    toks, notes = _typed(tmp_path, monkeypatch, "last tuesday")
    assert [(t.value, t.kind) for t in toks] == [("example-skill-config", "linkage")]
    assert any("unparseable" in n for n in notes), notes


def test_a_day_old_map_is_MENTIONED_but_still_votes(tmp_path, monkeypatch):
    """The twin that stops this from becoming a gate that cries wolf. The refresher runs every four
    hours; a day-old map has missed several runs and that is worth saying, not worth gating."""
    toks, notes = _typed(tmp_path, monkeypatch, _aged(2))
    assert [(t.value, t.kind) for t in toks] == [("example-skill-config", "derived")]
    assert any("h old" in n for n in notes), notes


def test_staleness_does_not_touch_the_LINKAGE_verdicts(tmp_path, monkeypatch):
    """Only the downgrade depends on freshness. A stale map that still calls something private is
    erring toward gating, which costs an edit rather than a disclosure."""
    vis = tmp_path / "vis-linkage.json"
    write_vis(vis, {"owner/hidden-venture": "PRIVATE",
                    "owner/hidden-venture-config": "PRIVATE"}, refreshed=_aged(45))
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [(t.value, t.kind) for t in toks] == [("hidden-venture-config", "linkage")]


def test_freshness_comes_from_the_STAMP_and_never_from_the_file_mtime(tmp_path, monkeypatch):
    """visibility_of.py writes single keys back into this map on a cache miss, which bumps the
    mtime without re-verifying one single answer. A freshly touched file with an ancient stamp is
    exactly the case mtime gets wrong, and it is documented at length over there."""
    vis = tmp_path / "vis-mtime.json"
    write_vis(vis, {"owner/example-skill": "PUBLIC",
                    "owner/example-skill-config": "PRIVATE"}, refreshed=_aged(45))
    os.utime(str(vis), None)                       # touched just now, verdicts still 45 days old
    monkeypatch.setattr(g, "_run", lambda *a, **k: "git@github.com:owner/other.git\n")
    toks = g.load_cross_repo_tokens(".", vis_path=str(vis))
    assert [(t.value, t.kind) for t in toks] == [("example-skill-config", "linkage")]


# ================================================================== after the subtraction pass
# The exemption exit lost `exposure`, the append-only grant log and the `_token_digest` helper, and
# kept its `scope` axis. That last decision was not a judgement call in the end: an adversarial
# review built the version without it and showed that a `secret` already accepted in a repo's PAST
# could then be written fresh into a live file and pass. What follows pins the parts that survived
# and the parts that were added to replace what went.

def test_the_receipt_names_hand_written_exemptions(tmp_path, monkeypatch):
    """`grant` writes a nonce only after PROVING the token produces a finding in this repo, so an
    entry without a matching one was typed by hand and never went through that proof. It is still
    honoured, because refusing it would take away the exit, but it is not invisible.

    Reported in the RECEIPT rather than as its own warning line: it is a standing fact about a
    long-lived exemption, not an event, and a warning printed on every scan of that repo forever is
    the noise that trains people to stop reading the output."""
    grants, notes = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "zzhandwritten", "scope": "history-only", "reason": "typed in by hand",
         "nonce": "deadbeef"}]})
    assert len(grants) == 1 and grants[0].hand_written
    assert notes == []                       # not a separate warning
    pol = g.Policy()
    pol.grants = grants
    assert "written by hand" in pol.receipt()


def test_a_properly_granted_exemption_is_not_flagged(tmp_path, monkeypatch):
    """The twin. If everything were flagged the flag would mean nothing."""
    grants, _ = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "zzproven", "scope": "history-only", "reason": "went through grant"}]})
    assert len(grants) == 1 and not grants[0].hand_written
    pol = g.Policy()
    pol.grants = grants
    assert "written by hand" not in pol.receipt()


def test_a_history_grant_hit_in_a_live_domain_is_counted_and_named(tmp_path, monkeypatch):
    """The one form of this guard's reason for existing that a machine can observe: the token this
    repo accepted in its past turning up in content being written now. It is not a suppression, so
    it does not count as used, and it is not nothing, so it gets its own counter."""
    grants, _ = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": [
        {"token": "zzaccepted", "scope": "history-only", "reason": "already public"}]})
    pol = g.Policy()
    pol.grants = grants
    pol.tokens = [g.Token("zzaccepted", "secret")]
    out = []
    g.scan_text("zzaccepted appears here", "x", set(), pol, out, domain="tree")
    assert out and out[0][3] == "BLOCK"          # the live domain is NOT relaxed
    assert grants[0].live_collisions == 1
    assert not grants[0].used
    r = pol.receipt()
    assert "LIVE domain" in r and "0 suppressed" in r


def test_the_remediation_command_names_the_scope_that_would_help(repo, tmp_path):
    """It used to print `--scope history-only` unconditionally. Somebody blocked in the working
    tree was handed a command that `grant` accepts and that then does nothing at all: a compliant
    path that silently is not one, which is worse than none, because the person believes they took
    it."""
    home = str(tmp_path / "hint_home")
    os.makedirs(os.path.join(home, ".pii-guard"), exist_ok=True)
    dl = os.path.join(home, "denylist.json")
    io.open(dl, "w", encoding="utf-8").write(json.dumps(
        {"format": 2, "canary": g.CANARY_TOKEN, "count": 2,
         "tokens": [{"value": "zzhinttoken", "kind": "secret"},
                    {"value": g.CANARY_TOKEN, "kind": "secret"}]}))
    repo.env["PII_DENYLIST"] = dl
    repo.env["USERPROFILE"] = repo.env["HOME"] = home
    repo.write("live.md", "the zzhinttoken account\n")
    repo.commit()
    rc, out = _cli(repo, "--tree")
    assert rc == 1
    assert "--scope all" in out, out          # blocked in the tree, so `all` is what would help
    assert "--all-scope-reason" in out        # ...and it costs the extra sentence


def test_the_removed_surface_is_really_gone():
    """A subtraction that leaves the names behind has not subtracted anything."""
    for gone in ("EXPOSURES", "SEVERITIES", "_token_digest",
                 "load_private_denylist", "_cross_repo_tokens_typed"):
        assert not hasattr(g, gone), gone
    assert "associative" not in g.KINDS
    assert set(g.KINDS) == {"secret", "linkage", "derived"}


def test_a_bare_string_exemption_loads_at_the_SAFE_scope(tmp_path, monkeypatch):
    """A bare string is the oldest shape this file ever had, from before it had a shape at all. It
    used to become `scope=all`, so the least considered entries silently received the widest
    exemption the system can express. The default now points the other way; the one real legacy
    entry on this machine was migrated to an explicit object first, so nothing depends on the old
    behaviour."""
    grants, notes = _exempt(tmp_path, monkeypatch,
                            {"owner/scanned-repo": ["zzlegacytoken"]})
    assert len(grants) == 1
    assert grants[0].scope == "history-only"
    assert any("history-only" in n for n in notes), notes


def test_a_bare_string_exemption_does_not_reach_live_content(tmp_path, monkeypatch):
    """The twin, stated as behaviour rather than as a field value."""
    grants, _ = _exempt(tmp_path, monkeypatch, {"owner/scanned-repo": ["zzlegacytoken"]})
    pol = g.Policy()
    pol.grants = grants
    pol.tokens = [g.Token("zzlegacytoken", "secret")]
    assert list(sev_of("zzlegacytoken here", pol, "history").values()) == ["WARN"]
    pol2 = g.Policy()
    pol2.grants = list(grants)
    pol2.tokens = [g.Token("zzlegacytoken", "secret")]
    assert list(sev_of("zzlegacytoken here", pol2, "tree").values()) == ["BLOCK"]
