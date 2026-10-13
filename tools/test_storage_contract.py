"""Synthetic checks for the source-owned storage contract: paths, patterns and validation."""
import json

import pytest

import pii_guard
import storage_contract as storage
from make_fixtures import make_storage_contract_fixture, storage_literal_path_cases
from test_git_context import git_environment


@pytest.fixture
def layout(tmp_path, monkeypatch):
    fixture = make_storage_contract_fixture(tmp_path, pii_guard._utcnow())
    with git_environment(monkeypatch, fixture["companion"].env):
        yield fixture


def save_contract(layout):
    (layout["source"].root / "storage.contract.json").write_text(
        json.dumps(layout["contract"]), encoding="utf-8")


@pytest.mark.parametrize("path,pattern,want", storage_literal_path_cases()["pattern_cases"])
def test_square_bracket_pattern_classes_keep_existing_glob_semantics(path, pattern, want):
    assert storage.relative_path(pattern, pattern=True) == pattern
    assert storage.matches(path, pattern) is want


@pytest.mark.parametrize("relative", ["../escape", "/absolute", "C:/escape", "data\\escape",
                                     "NUL.json", "cache/file:stream", "cache/trailing.",
                                     "cache/trailing ", ".git/config", "**"])
def test_noncanonical_paths_are_refused(relative):
    with pytest.raises(ValueError):
        storage.relative_path(relative)


@pytest.mark.parametrize("name", ["CON .txt", "COM¹.txt", "LPT².json", "CONIN$", "CONOUT$"])
def test_windows_device_aliases_are_rejected_without_opening_them(name):
    with pytest.raises(ValueError, match="reserved"):
        storage.relative_path("reports/" + name)


@pytest.mark.parametrize("persistence", ["unknown", False, {}, None])
def test_invalid_explicit_persistence_fails_closed(layout, persistence):
    layout["contract"]["artifacts"][1]["persistence"] = persistence
    save_contract(layout)
    with pytest.raises(ValueError, match="persistence"):
        storage.validate_contract(layout["source"].root)


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

