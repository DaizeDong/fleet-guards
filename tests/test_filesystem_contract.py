"""Exercise real scratch files; inject only OS errors and reparse metadata."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import threading
from types import SimpleNamespace

import pytest


def filesystem():
    assert importlib.util.find_spec("fleet_guards") is not None, "shared package is missing"
    from fleet_guards import filesystem as fs
    return fs


def test_atomic_replace_round_trip_and_private_mode(tmp_path):
    fs = filesystem()
    path = tmp_path / "nested" / "value"
    assert fs.atomic_replace(path, "synthetic \u03bb") is None
    assert fs.read_bounded(path, 100) == "synthetic \u03bb".encode()
    fs.atomic_replace(path, b"replacement", mode=0o640)
    assert path.read_bytes() == b"replacement"
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_no_replace_preserves_existing_bytes(tmp_path):
    fs = filesystem()
    path = tmp_path / "value"
    assert fs.create_no_replace(path, b"first") is True
    assert fs.create_no_replace(path, b"second") is False
    assert path.read_bytes() == b"first"
    assert list(tmp_path.iterdir()) == [path]


def test_concurrent_create_has_exactly_one_complete_winner(tmp_path):
    fs = filesystem()
    barrier = threading.Barrier(8)
    path = tmp_path / "value"
    def publish(index):
        data = bytes([65 + index]) * 10000
        barrier.wait(timeout=10)
        return fs.create_no_replace(path, data), data
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(publish, range(8)))
    winners = [data for won, data in results if won]
    assert len(winners) == 1
    assert path.read_bytes() == winners[0]
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("operation", ["atomic_replace", "create_no_replace"])
def test_file_flush_failure_publishes_nothing_and_cleans_stage(tmp_path, monkeypatch, operation):
    fs = filesystem()
    path = tmp_path / "value"
    if operation == "atomic_replace":
        path.write_bytes(b"original")
    def fail(*args):
        raise OSError("synthetic fsync failure")
    monkeypatch.setattr(fs.os, "fsync", fail)
    with pytest.raises(OSError):
        getattr(fs, operation)(path, b"replacement")
    assert path.read_bytes() == b"original" if path.exists() else operation == "create_no_replace"
    assert sorted(p.name for p in tmp_path.iterdir()) == (["value"] if operation == "atomic_replace" else [])


def test_failed_replace_preserves_previous_file_and_cleans_stage(tmp_path, monkeypatch):
    fs = filesystem()
    path = tmp_path / "value"
    path.write_bytes(b"original")
    def fail(*args):
        raise OSError("synthetic replace failure")
    monkeypatch.setattr(fs.os, "replace", fail)
    with pytest.raises(OSError):
        fs.atomic_replace(path, b"replacement")
    assert path.read_bytes() == b"original"
    assert list(tmp_path.iterdir()) == [path]


def test_bounded_read_empty_exact_oversize_and_missing(tmp_path):
    fs = filesystem()
    path = tmp_path / "value"
    path.write_bytes(b"")
    assert fs.read_bounded(path, 0) == b""
    path.write_bytes(b"abcd")
    assert fs.read_bounded(path, 4) == b"abcd"
    with pytest.raises(fs.FileTooLargeError):
        fs.read_bounded(path, 3)
    with pytest.raises(ValueError):
        fs.read_bounded(path, -1)
    with pytest.raises(FileNotFoundError):
        fs.read_bounded(tmp_path / "absent", 4)


@pytest.mark.parametrize("operation", ["atomic_replace", "create_no_replace", "read_bounded"])
def test_directory_is_not_a_regular_file(tmp_path, operation):
    fs = filesystem()
    with pytest.raises(fs.UnsafePathError):
        getattr(fs, operation)(tmp_path, 10 if operation == "read_bounded" else b"data")


@pytest.mark.parametrize("name", ["../escape", "stream:private", "NUL", "CON.txt", "trailing.", "trailing "])
def test_unsafe_path_syntax_cannot_publish(tmp_path, name):
    fs = filesystem()
    with pytest.raises(fs.UnsafePathError):
        fs.atomic_replace(tmp_path / name, b"data")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("leaf", [True, False])
@pytest.mark.parametrize("operation", ["atomic_replace", "create_no_replace", "read_bounded"])
def test_symlink_or_reparse_metadata_is_refused(tmp_path, monkeypatch, leaf, operation):
    fs = filesystem()
    parent = tmp_path / "parent"
    parent.mkdir()
    path = parent / "value"
    path.write_bytes(b"original")
    flagged = path if leaf else parent
    original = Path.lstat
    def reparse(candidate, *args, **kwargs):
        info = original(candidate, *args, **kwargs)
        if candidate == flagged:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info
    monkeypatch.setattr(Path, "lstat", reparse)
    with pytest.raises(fs.UnsafePathError):
        getattr(fs, operation)(path, 100 if operation == "read_bounded" else b"replacement")
    assert path.read_bytes() == b"original"


def test_root_containment_is_component_aware(tmp_path):
    fs = filesystem()
    root = tmp_path / "repo"
    root.mkdir()
    assert fs.validate_path(root / "value", root=root) == root / "value"
    with pytest.raises(fs.UnsafePathError):
        fs.validate_path(tmp_path / "repo-other" / "value", root=root)


def test_real_directory_link_is_rejected_for_reads_and_writes(tmp_path):
    fs = filesystem()
    target = tmp_path / "target"
    target.mkdir()
    (target / "value").write_bytes(b"original")
    link = tmp_path / "link"
    if os.name == "nt":
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True, timeout=10)
        assert proc.returncode == 0, "could not create synthetic junction"
    else:
        link.symlink_to(target, target_is_directory=True)
    with pytest.raises(fs.UnsafePathError):
        fs.read_bounded(link / "value", 100)
    with pytest.raises(fs.UnsafePathError):
        fs.atomic_replace(link / "value", b"replacement")
    assert (target / "value").read_bytes() == b"original"


def test_no_replace_publish_error_is_not_misreported_as_collision(tmp_path, monkeypatch):
    fs = filesystem()
    def fail(*args):
        raise OSError("synthetic publish failure")
    monkeypatch.setattr(fs if os.name == "nt" else fs.os,
                        "_rename_handle" if os.name == "nt" else "link", fail)
    with pytest.raises(OSError):
        fs.create_no_replace(tmp_path / "value", b"data")
    assert list(tmp_path.iterdir()) == []


def test_readonly_stage_is_cleaned_after_a_concurrent_collision(tmp_path, monkeypatch):
    fs = filesystem()
    path = tmp_path / "value"
    owner = fs if os.name == "nt" else fs.os
    name = "_rename_handle" if os.name == "nt" else "link"
    publish = getattr(owner, name)
    def collide(source, destination):
        Path(destination).write_bytes(b"winner")
        return publish(source, destination)
    monkeypatch.setattr(owner, name, collide)
    assert fs.create_no_replace(path, b"loser", mode=0o400) is False
    assert path.read_bytes() == b"winner"
    assert list(tmp_path.iterdir()) == [path]


def test_observed_file_change_during_read_is_refused(tmp_path, monkeypatch):
    fs = filesystem()
    path = tmp_path / "value"
    path.write_bytes(b"original")
    original = fs.os.fstat
    count = 0
    def changing(fd):
        nonlocal count
        count += 1
        info = original(fd)
        if count == 2:
            return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                                   st_size=info.st_size, st_mtime_ns=info.st_mtime_ns + 1)
        return info
    monkeypatch.setattr(fs.os, "fstat", changing)
    with pytest.raises(fs.UnsafePathError):
        fs.read_bounded(path, 100)
