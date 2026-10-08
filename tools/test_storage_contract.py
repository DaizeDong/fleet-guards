"""Synthetic native Git checks for source-owned, read-only write admission."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess

import pytest

import data_boundary as boundary
import pii_guard
import storage_contract as storage
from make_fixtures import (
    _no_window, GitContextFixture, make_storage_contract_fixture, make_storage_short_name_fixture,
    storage_literal_path_cases,
)
from test_git_context import git_environment


@pytest.fixture
def layout(tmp_path, monkeypatch):
    fixture = make_storage_contract_fixture(tmp_path, pii_guard._utcnow())
    with git_environment(monkeypatch, fixture["companion"].env):
        yield fixture


def save_contract(layout):
    (layout["source"].root / "storage.contract.json").write_text(
        json.dumps(layout["contract"]), encoding="utf-8")


def authorize(layout, relative="reports/status.json", **kwargs):
    return storage.authorize_artifact_write(
        layout["source"].root, layout["companion"].root, relative,
        visibility_map=layout["receipt"], **kwargs)


def test_admits_absent_declared_leaf_without_creating_or_modifying_files(layout):
    before = layout["companion"].git("status", "--porcelain", "--untracked-files=all")
    admission = authorize(layout, artifact_id="status")
    assert admission.path == layout["companion"].root / "reports/status.json"
    assert admission.artifact_id == "status"
    assert admission.proof.repositories == ("example-owner/synthetic-private",)
    assert len(admission.contract_sha256) == 64
    assert not admission.path.parent.exists()
    assert layout["companion"].git("status", "--porcelain", "--untracked-files=all") == before
    with pytest.raises(AttributeError):
        admission.artifact_id = "cache"


@pytest.mark.parametrize("relative", storage_literal_path_cases()["literal_paths"])
def test_concrete_brackets_remain_literal_versionable_files(layout, relative):
    admission = authorize(layout, relative, artifact_id="runs")
    assert admission.path == layout["companion"].root / relative
    assert admission.proof.repositories == ("example-owner/synthetic-private",)
    assert not admission.path.exists()
    admission.path.parent.mkdir(parents=True)
    admitted = authorize(layout, relative, artifact_id="runs")
    payload = storage_literal_path_cases()["payload"]
    with admitted.path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
    layout["companion"].git("--literal-pathspecs", "add", "--", relative)
    layout["companion"].git("commit", "-qm", "synthetic bracketed artifact")
    assert layout["companion"].git("show", "HEAD:" + relative) == payload.strip()
    assert admitted.path.read_text(encoding="utf-8") == payload


@pytest.mark.parametrize("relative", storage_literal_path_cases()["wildcard_paths"])
def test_concrete_wildcards_still_fail_before_output_creation(layout, relative):
    with pytest.raises(ValueError, match="glob"):
        authorize(layout, relative, artifact_id="runs")
    assert not (layout["companion"].root / "data").exists()


@pytest.mark.parametrize("path,pattern,want", storage_literal_path_cases()["pattern_cases"])
def test_square_bracket_pattern_classes_keep_existing_glob_semantics(path, pattern, want):
    assert storage.relative_path(pattern, pattern=True) == pattern
    assert storage.matches(path, pattern) is want


@pytest.mark.parametrize("relative", ["unknown.json", "reports/status.pyc"])
def test_undeclared_path_is_not_admitted_by_private_identity(layout, relative):
    with pytest.raises(ValueError, match="owner|undeclared"):
        authorize(layout, relative)


def test_ambiguous_path_and_wrong_producer_artifact_are_refused(layout):
    with pytest.raises(ValueError, match="artifact"):
        authorize(layout, artifact_id="cache")
    row = copy.deepcopy(layout["contract"]["artifacts"][0])
    row["artifact_id"] = "second-producer"
    layout["contract"]["artifacts"].append(row)
    save_contract(layout)
    with pytest.raises(ValueError, match="owner|ambiguous"):
        authorize(layout)


@pytest.mark.parametrize("relative", ["../escape", "/absolute", "C:/escape", "data\\escape",
                                     "NUL.json", "cache/file:stream", "cache/trailing.",
                                     "cache/trailing ", ".git/config", "**"])
def test_noncanonical_paths_are_refused_before_writing(layout, relative):
    with pytest.raises(ValueError):
        authorize(layout, relative)


@pytest.mark.parametrize("name", ["CON .txt", "COM¹.txt", "LPT².json", "CONIN$", "CONOUT$"])
def test_windows_device_aliases_are_rejected_without_opening_them(name):
    with pytest.raises(ValueError, match="reserved"):
        storage.relative_path("reports/" + name)


@pytest.mark.parametrize("persistence", [None, "versioned"])
def test_rebuildable_is_still_versioned_and_ignored_absent_leaf_is_refused(layout, persistence):
    if persistence:
        layout["contract"]["artifacts"][1]["persistence"] = persistence
        save_contract(layout)
    with pytest.raises(ValueError, match="ignored"):
        authorize(layout, "cache/result.tmp")
    assert not (layout["companion"].root / "cache").exists()


def test_transient_permission_is_source_owned_and_requires_reason(layout):
    row = layout["contract"]["artifacts"][1]
    row["persistence"] = "transient"
    save_contract(layout)
    with pytest.raises(ValueError, match="transient"):
        authorize(layout, "cache/result.tmp")
    row["transient_reason"] = "Disposable file reconstructed by the producer on each invocation"
    save_contract(layout)
    assert authorize(layout, "cache/result.tmp").artifact_id == "cache"
    assert not (layout["companion"].root / "cache").exists()


@pytest.mark.parametrize("persistence", ["unknown", False, {}, None])
def test_invalid_explicit_persistence_fails_closed(layout, persistence):
    layout["contract"]["artifacts"][1]["persistence"] = persistence
    save_contract(layout)
    with pytest.raises(ValueError, match="persistence"):
        storage.validate_contract(layout["source"].root)


def test_core_recovery_dependency_can_have_explicit_transient_persistence(layout):
    row = layout["contract"]["artifacts"][0]
    row.update(persistence="transient", transient_reason="Synthetic disposable reason")
    save_contract(layout)
    assert authorize(layout).artifact_id == "status"


def test_retired_artifact_cannot_receive_writes(layout):
    row = layout["contract"]["artifacts"][0]
    row["retention_rule"]["class"] = "retired"
    save_contract(layout)
    with pytest.raises(ValueError, match="retired"):
        authorize(layout)


def test_absent_directory_preserves_directory_only_ignore_rules(layout):
    with pytest.raises(ValueError, match="ignored"):
        authorize(layout, "ignored-directory", directory=True)
    assert not (layout["companion"].root / "ignored-directory").exists()


@pytest.mark.parametrize("route", ["synthetic-public", "synthetic-unknown"])
@pytest.mark.parametrize("key", ["remote.origin.pushurl", "remote.origin.url"])
def test_fetch_and_push_must_both_be_private(layout, route, key):
    layout["companion"].git("config", key, "https://github.com/example-owner/" + route + ".git")
    with pytest.raises(boundary.GitError, match="PRIVATE"):
        authorize(layout)


def test_companion_root_cannot_name_a_subdirectory(layout):
    child = layout["companion"].root / "data"
    child.mkdir()
    with pytest.raises(ValueError, match="exact.*root"):
        storage.authorize_artifact_write(
            layout["source"].root, child, "reports/status.json", visibility_map=layout["receipt"])


@pytest.mark.parametrize("source_location", ["same", "inside", "outside-parent"])
def test_separate_layout_rejects_overlapping_source_and_companion(layout, source_location):
    source = {"same": layout["companion"].root,
              "inside": layout["companion"].root / "source",
              "outside-parent": layout["companion"].root.parent}[source_location]
    source.mkdir(exist_ok=True)
    (source / "storage.contract.json").write_text(json.dumps(layout["contract"]), encoding="utf-8")
    with pytest.raises(ValueError, match="separate"):
        storage.authorize_artifact_write(source, layout["companion"].root,
                                         "reports/status.json", visibility_map=layout["receipt"])


def test_combined_layout_is_private_and_only_declared_data_roots_are_writable(layout):
    layout["contract"].update(layout="combined_private_repo", data_roots=["reports"])
    layout["contract"]["artifacts"] = layout["contract"]["artifacts"][:1]
    source = layout["companion"].root
    (source / "storage.contract.json").write_text(json.dumps(layout["contract"]), encoding="utf-8")
    result = storage.authorize_artifact_write(source, source, "reports/status.json",
                                              visibility_map=layout["receipt"])
    assert result.path == source / "reports/status.json"
    with pytest.raises(ValueError, match="data_roots"):
        storage.authorize_artifact_write(source, source, "settings.json", visibility_map=layout["receipt"])


def test_linked_worktree_root_gitfile_is_legitimate(layout, tmp_path):
    linked = tmp_path / "linked"
    layout["companion"].git("worktree", "add", "--detach", str(linked))
    result = storage.authorize_artifact_write(
        layout["source"].root, linked, "reports/status.json", visibility_map=layout["receipt"])
    assert result.path == linked / "reports/status.json"
    assert (linked / ".git").is_file()


def test_nested_repository_is_not_admitted_by_parent_proof(layout):
    GitContextFixture(layout["companion"].root / "reports", layout["configuration"])
    with pytest.raises(ValueError, match="nested"):
        authorize(layout)


def test_unreadable_nested_git_marker_is_not_treated_as_absent(layout, monkeypatch):
    parent = layout["companion"].root / "reports"
    parent.mkdir()
    original = Path.lstat
    def unreadable(path, *args, **kwargs):
        if path == parent / ".git":
            raise PermissionError("synthetic inaccessible metadata")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", unreadable)
    with pytest.raises(PermissionError):
        authorize(layout)


@pytest.mark.parametrize("kind", ["junction", "hardlink"])
def test_filesystem_aliases_are_refused(layout, tmp_path, kind):
    parent = layout["companion"].root / "reports"
    if kind == "junction":
        outside = tmp_path / "outside"
        outside.mkdir()
        if os.name == "nt":
            result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(parent), str(outside)],
                                    capture_output=True, **_no_window())
            assert result.returncode == 0
        else:
            parent.symlink_to(outside, target_is_directory=True)
    else:
        parent.mkdir()
        target = parent / "status.json"
        target.write_text("{}", encoding="utf-8")
        os.link(target, tmp_path / "alias.json")
    with pytest.raises(ValueError, match="link|junction"):
        authorize(layout)


@pytest.mark.skipif(os.name != "nt", reason="Native Windows filesystem alias regression")
@pytest.mark.parametrize("kind", ["gitfile", "artifact"])
def test_ntfs_short_names_cannot_bypass_metadata_or_artifact_ownership(layout, kind):
    root, target, relative = make_storage_short_name_fixture(layout, kind)
    if Path(relative).name == target.name:
        pytest.skip("The synthetic volume does not generate NTFS short names")
    row = copy.deepcopy(layout["contract"]["artifacts"][0])
    row.update(artifact_id="alias", path_pattern=relative)
    layout["contract"]["artifacts"].append(row)
    save_contract(layout)
    with pytest.raises(ValueError, match="alias|canonical"):
        storage.authorize_artifact_write(layout["source"].root, root, relative,
                                         visibility_map=layout["receipt"])


@pytest.mark.skipif(os.name != "nt", reason="Windows case-insensitive filesystem policy")
def test_different_case_declarations_cannot_hide_retired_owner(layout):
    row = copy.deepcopy(layout["contract"]["artifacts"][0])
    row.update(artifact_id="retired-status", path_pattern="reports/status.JSON")
    row["retention_rule"]["class"] = "retired"
    layout["contract"]["artifacts"].append(row)
    save_contract(layout)
    with pytest.raises(ValueError, match="owner|ambiguous"):
        authorize(layout)


def test_unborn_private_repository_is_not_versioned_storage(layout):
    layout["companion"].git("update-ref", "-d", "refs/heads/main")
    with pytest.raises(boundary.GitError):
        authorize(layout)


@pytest.mark.parametrize("failure", ["status", "launch"])
def test_git_ignore_errors_are_never_admission(layout, monkeypatch, failure):
    original = boundary.subprocess.run
    def failed(command, *args, **kwargs):
        if command[1] == "check-ignore":
            if failure == "launch":
                raise OSError("synthetic execution failure")
            return subprocess.CompletedProcess(command, 128, "", "synthetic failure")
        return original(command, *args, **kwargs)
    monkeypatch.setattr(boundary.subprocess, "run", failed)
    with pytest.raises(boundary.GitError):
        authorize(layout)


@pytest.mark.parametrize("change", ["contract", "ignore", "routing"])
def test_changes_during_proof_do_not_receive_stale_admission(layout, monkeypatch, change):
    original = boundary.prove_private_companion
    count = 0
    def changing(*args, **kwargs):
        nonlocal count
        proof = original(*args, **kwargs)
        count += 1
        if count == 2:
            if change == "contract":
                layout["contract"]["artifacts"][0]["path_pattern"] = "reports/replaced.json"
                save_contract(layout)
            elif change == "ignore":
                (layout["companion"].root / ".gitignore").write_text("reports/\n", encoding="utf-8")
            else:
                layout["companion"].git("config", "remote.origin.pushurl",
                                        "https://github.com/example-owner/synthetic-public.git")
        return proof
    monkeypatch.setattr(boundary, "prove_private_companion", changing)
    with pytest.raises((ValueError, boundary.GitError)):
        authorize(layout)


@pytest.mark.parametrize("path,pattern,want", [
    ("data/run/item.json", "data/*/*.json", True),
    ("data/run/nested/item.json", "data/*/*.json", False),
    ("data/item.json", "data/**/item.json", True),
    ("data/run/nested/item.json", "data/**/item.json", True),
])
def test_shared_matcher_preserves_segment_glob_semantics(path, pattern, want):
    assert storage.matches(path, pattern) is want


@pytest.mark.parametrize("pattern", ["**/**", "*/**", "**/?*", "***"])
def test_alternate_root_catchall_spellings_do_not_authorize_unbounded_storage(layout, pattern):
    layout["contract"]["artifacts"][0]["path_pattern"] = pattern
    save_contract(layout)
    with pytest.raises(ValueError, match="catch-all"):
        storage.validate_contract(layout["source"].root)


def test_path_loader_uses_its_pinned_boundary_module_without_sys_path_changes(layout):
    spec = importlib.util.spec_from_file_location("synthetic_storage_loader", Path(storage.__file__))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = module.authorize_artifact_write(layout["source"].root, layout["companion"].root,
                                             "reports/status.json", visibility_map=layout["receipt"])
    assert result.artifact_id == "status"
