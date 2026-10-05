"""Shared package contracts use generated inputs and disposable local files."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))
from make_fixtures import package_api_cases

CASES = package_api_cases()


def api(name):
    assert (ROOT / "fleet_guards" / (name + ".py")).is_file(), "shared package source is missing"
    module = importlib.import_module("fleet_guards." + name)
    assert Path(module.__file__).resolve().parent == ROOT / "fleet_guards"
    return module


def test_package_build_metadata_exists():
    assert (ROOT / "pyproject.toml").is_file(), "source cannot build its shared package"


@pytest.mark.parametrize("text,rule", CASES["shapes"])
def test_credential_shapes_return_metadata_only(text, rule):
    result = api("secrets").scan(text)
    assert result["state"] == "findings"
    assert rule in {item["rule_id"] for item in result["findings"]}
    for item in result["findings"]:
        assert set(item) == {"rule_id", "span", "severity", "confidence"}
        start, end = item["span"]
        assert 0 <= start < end <= len(text)
    assert text not in json.dumps(result)


@pytest.mark.parametrize("text", CASES["benign"])
def test_benign_text_and_complete_templates(text):
    assert api("secrets").scan(text)["state"] == "clean"


@pytest.mark.parametrize("text", CASES["partial_templates"])
def test_partial_templates_are_not_exempt(text):
    assert api("secrets").scan(text)["state"] == "findings"


def test_support_policy_keeps_entropy_and_canary_controls():
    scanner = api("secrets")
    for text in CASES["strict"]:
        assert scanner.scan(text, "support-egress-v1")["state"] == "findings"


@pytest.mark.parametrize("budgets", CASES["invalid_budgets"])
def test_invalid_scan_budgets_fail_closed(budgets):
    assert api("secrets").scan(CASES["safe"], **budgets)["state"] == "scan_failed"


def test_large_explicit_scan_budget_never_truncates():
    scanner = api("secrets")
    text = CASES["large_prefix"] + CASES["shapes"][0][0]
    assert scanner.scan(text)["error_code"] == "input_limit"
    result = scanner.scan(text, max_text_chars=16 * 1024 * 1024, seconds=30)
    assert result["state"] == "findings"
    assert result["findings"][0]["span"][0] >= len(CASES["large_prefix"])


def test_scanner_failures_do_not_clear_input(monkeypatch):
    scanner = api("secrets")
    assert scanner.scan(CASES["safe"], policy="unknown")["state"] == "scan_failed"
    assert scanner.scan(None)["state"] == "scan_failed"
    monkeypatch.setattr(scanner, "MAX_FINDINGS", 1)
    assert scanner.scan(" ".join([CASES["shapes"][0][0]] * 2))["state"] == "scan_failed"
    def unavailable():
        raise RuntimeError(CASES["safe"])
    monkeypatch.setattr(scanner.time, "monotonic", unavailable)
    result = scanner.scan(CASES["safe"])
    assert result["state"] == "scan_failed"
    assert CASES["safe"] not in json.dumps(result)


@pytest.mark.parametrize("data,code,state", CASES["cli"])
def test_cli_status_and_json(data, code, state):
    api("secrets")
    result = subprocess.run([sys.executable, "-m", "fleet_guards", "scan"],
                            cwd=ROOT, input=data, capture_output=True, timeout=15)
    assert result.returncode == code
    assert json.loads(result.stdout)["state"] == state
    assert not result.stderr


def test_atomic_write_bounded_read_and_identity(tmp_path):
    fs = api("filesystem")
    target = tmp_path / "nested" / "value"
    first, second = CASES["payloads"]
    fs.atomic_replace(target, first)
    assert fs.read_bounded(target, len(first)) == first
    assert fs.create_no_replace(target, second) is False
    with pytest.raises(fs.FileTooLargeError):
        fs.read_bounded(target, len(first) - 1)
    fs.atomic_replace(target, second)
    assert fs.read_bounded(target, len(second)) == second
    created = tmp_path / "created"
    observed = fs.create_no_replace_with_identity(created, first)
    assert observed == fs.identity(created)
    assert fs.create_no_replace_with_identity(created, second) is None
    assert created.read_bytes() == first


def test_concurrent_creators_keep_one_complete_winner(tmp_path):
    fs = api("filesystem")
    target = tmp_path / "value"
    barrier = threading.Barrier(4)
    def publish(payload):
        barrier.wait(timeout=10)
        return fs.create_no_replace(target, payload), payload
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(publish, CASES["concurrent_payloads"]))
    winners = [payload for won, payload in results if won]
    assert len(winners) == 1
    assert target.read_bytes() == winners[0]
    assert list(tmp_path.iterdir()) == [target]


def test_publication_identity_does_not_adopt_equal_byte_replacement(tmp_path, monkeypatch):
    fs = api("filesystem")
    target = tmp_path / "value"
    observed = {}
    synchronize = fs._sync_directory
    def replace_after_publication(parent):
        observed["published"] = fs.identity(target)
        replacement = parent / "replacement"
        replacement.write_bytes(target.read_bytes())
        os.replace(replacement, target)
        observed["replacement"] = fs.identity(target)
        synchronize(parent)
    monkeypatch.setattr(fs, "_sync_directory", replace_after_publication)
    created = fs.create_no_replace_with_identity(target, CASES["payloads"][0])
    assert created == observed["published"] != observed["replacement"]
    assert fs.identity(target) == observed["replacement"]
    assert list(tmp_path.iterdir()) == [target]


def test_unavailable_identity_prevents_publication(tmp_path, monkeypatch):
    fs = api("filesystem")
    def unavailable(info):
        raise OSError("synthetic missing identity")
    monkeypatch.setattr(fs, "_stat_identity", unavailable)
    with pytest.raises(OSError):
        fs.create_no_replace_with_identity(tmp_path / "value", CASES["payloads"][0])
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Windows native handle contract")
def test_identity_delete_preserves_equal_byte_foreign_file(tmp_path):
    fs = api("filesystem")
    target = tmp_path / "value"
    payload = CASES["payloads"][0]
    target.write_bytes(payload)
    owned = fs.identity(target)
    target.rename(tmp_path / "original")
    target.write_bytes(payload)
    assert fs.identity(target) != owned
    assert fs.delete_if_identity_matches(target, owned) is False
    assert target.read_bytes() == payload


@pytest.mark.parametrize("name", CASES["unsafe_paths"])
def test_unsafe_paths_never_publish(tmp_path, name):
    fs = api("filesystem")
    with pytest.raises(fs.UnsafePathError):
        fs.atomic_replace(tmp_path / name, CASES["payloads"][0])
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("operation", ["atomic_replace", "create_no_replace"])
def test_fsync_failure_keeps_old_bytes_and_cleans_stage(tmp_path, monkeypatch, operation):
    fs = api("filesystem")
    target = tmp_path / "value"
    first, second = CASES["payloads"]
    if operation == "atomic_replace":
        target.write_bytes(first)
    def unavailable(*args):
        raise OSError("synthetic fsync failure")
    monkeypatch.setattr(fs.os, "fsync", unavailable)
    with pytest.raises(OSError):
        getattr(fs, operation)(target, second)
    assert target.read_bytes() == first if target.exists() else operation == "create_no_replace"
    assert not list(tmp_path.glob(".fleet-guards-*"))


def test_reparse_component_is_refused(tmp_path, monkeypatch):
    from types import SimpleNamespace
    fs = api("filesystem")
    target = tmp_path / "value"
    target.write_bytes(CASES["payloads"][0])
    original = Path.lstat
    def metadata(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == tmp_path:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info
    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(fs.UnsafePathError):
        fs.read_bounded(target, 100)
    with pytest.raises(fs.UnsafePathError):
        fs.atomic_replace(target, CASES["payloads"][1])


def test_observed_change_during_read_is_refused(tmp_path, monkeypatch):
    from types import SimpleNamespace
    fs = api("filesystem")
    target = tmp_path / "value"
    target.write_bytes(CASES["payloads"][0])
    original = fs.os.fstat
    calls = 0
    def metadata(fd):
        nonlocal calls
        calls += 1
        info = original(fd)
        if calls == 2:
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                                   st_size=info.st_size, st_mtime_ns=info.st_mtime_ns + 1)
        return info
    monkeypatch.setattr(fs.os, "fstat", metadata)
    with pytest.raises(fs.UnsafePathError):
        fs.read_bounded(target, 100)


def test_native_exclusion_and_detach_preserve_conflicts(tmp_path):
    fs = api("filesystem")
    target, retained = tmp_path / "value", tmp_path / "retained"
    first, second = CASES["payloads"]
    target.write_bytes(first)
    observed = fs.identity(target)
    assert fs.detach_if_matches(target, second, observed, retained) is False
    assert target.read_bytes() == first
    if os.name != "nt":
        with pytest.raises(OSError):
            with fs.exclude_file_writes([target]):
                pytest.fail("unsupported exclusion must not yield")
        return
    with fs.exclude_file_writes([target]) as identities:
        assert identities[target] == observed
        with pytest.raises(OSError):
            target.write_bytes(second)
    assert fs.detach_if_matches(target, first, observed, retained) is True
    assert not target.exists() and retained.read_bytes() == first
    assert fs.delete_if_identity_matches(retained, observed) is True
    assert not retained.exists()
