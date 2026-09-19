"""Bounded-reader contracts using synthetic files and deterministic read hooks."""
from contextlib import contextmanager
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from fleet_guards import filesystem as fs


def watch_reads(monkeypatch, *, on_read=None, on_close=None, short_reads=False):
    original = fs.os.fdopen
    requests = []

    @contextmanager
    def opened(*args, **kwargs):
        with original(*args, **kwargs) as stream:
            class Reader:
                def fileno(self):
                    return stream.fileno()

                def read(self, size):
                    requests.append(size)
                    data = stream.read(min(size, 17) if short_reads else size)
                    if on_read is not None:
                        on_read(len(requests))
                    return data

            yield Reader()
        if on_close is not None:
            on_close()

    monkeypatch.setattr(fs.os, "fdopen", opened)
    return requests


@pytest.mark.parametrize("size,limit", [(0, 0), (0, 64 * 1024 * 1024),
                                        (1024, 64 * 1024 * 1024),
                                        (65536, 65536), (131073, 131073)])
def test_read_requests_are_bounded_and_payload_is_exact(tmp_path, monkeypatch, size, limit):
    path = tmp_path / "synthetic.bin"
    payload = bytes(range(256)) * (size // 256) + b"x" * (size % 256)
    path.write_bytes(payload)
    requests = watch_reads(monkeypatch)
    actual = fs.read_bounded(path, limit)
    assert type(actual) is bytes
    assert actual == payload
    assert requests and all(0 < size <= 64 * 1024 for size in requests)
    assert sum(requests) <= len(payload) + 2 * 64 * 1024


def test_short_reads_are_not_mistaken_for_eof(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.bin"
    payload = b"synthetic" * 1000
    path.write_bytes(payload)
    watch_reads(monkeypatch, short_reads=True)
    assert fs.read_bounded(path, len(payload)) == payload


@pytest.mark.parametrize("limit", [-1, True, False, 1.5, "10", None])
def test_invalid_limit_types_are_refused(tmp_path, limit):
    with pytest.raises(ValueError, match="^invalid_limit$"):
        fs.read_bounded(tmp_path / "absent", limit)


def test_oversized_file_is_refused_before_open(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(b"synthetic-content")

    def unexpected_open(*args, **kwargs):
        pytest.fail("oversized input was opened")

    monkeypatch.setattr(fs.os, "open", unexpected_open)
    with pytest.raises(fs.FileTooLargeError, match="^file_too_large$"):
        fs.read_bounded(path, 3)


@pytest.mark.parametrize("change", ["grow", "shrink", "grow_over_limit"])
def test_growth_and_shrink_during_read_are_refused(tmp_path, monkeypatch, change):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(b"s" * 65536)
    limit = 65536 if change == "grow_over_limit" else 131072

    def mutate(call):
        if call == 1:
            if change == "shrink":
                with path.open("r+b") as writer:
                    writer.truncate(1)
            else:
                with path.open("ab") as writer:
                    writer.write(b"growth")

    watch_reads(monkeypatch, on_read=mutate)
    error = fs.FileTooLargeError if change == "grow_over_limit" else fs.UnsafePathError
    reason = "file_too_large" if change == "grow_over_limit" else "file_changed"
    with pytest.raises(error, match=f"^{reason}$"):
        fs.read_bounded(path, limit)


def test_growth_read_stops_at_exact_cap_plus_sentinel(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(b"s" * 65536)
    limit = 65539

    def grow(call):
        if call == 1:
            with path.open("ab") as writer:
                writer.write(b"g" * 131072)

    requests = watch_reads(monkeypatch, on_read=grow)
    with pytest.raises(fs.FileTooLargeError, match="^file_too_large$"):
        fs.read_bounded(path, limit)
    assert sum(requests) == limit + 1
    assert max(requests) <= 64 * 1024


def test_same_bytes_replacement_after_read_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "synthetic.bin"
    replacement = tmp_path / "replacement.bin"
    path.write_bytes(b"synthetic-content")
    replacement.write_bytes(path.read_bytes())
    before = path.stat()
    fs.os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_ino != replacement.stat().st_ino
    watch_reads(monkeypatch, on_close=lambda: fs.os.replace(replacement, path))
    with pytest.raises(fs.UnsafePathError, match="^file_changed$"):
        fs.read_bounded(path, 1024)


@pytest.mark.parametrize("change", ["inode", "device", "nonregular"])
def test_opened_identity_and_type_are_checked_before_read(tmp_path, monkeypatch, change):
    path = tmp_path / "synthetic.bin"
    path.write_bytes(b"synthetic-content")
    original = fs.os.fstat

    def different(fd):
        info = original(fd)
        return SimpleNamespace(st_dev=info.st_dev + (change == "device"),
                               st_ino=info.st_ino + (change == "inode"),
                               st_mode=stat.S_IFDIR if change == "nonregular" else info.st_mode)

    requests = watch_reads(monkeypatch)
    monkeypatch.setattr(fs.os, "fstat", different)
    with pytest.raises(fs.UnsafePathError, match="^file_changed$"):
        fs.read_bounded(path, 1024)
    assert requests == []


@pytest.mark.parametrize("leaf", [True, False])
def test_reparse_change_after_read_is_refused(tmp_path, monkeypatch, leaf):
    parent = tmp_path / "parent"
    parent.mkdir()
    path = parent / "synthetic.bin"
    path.write_bytes(b"synthetic-content")
    flagged = path if leaf else parent
    original = Path.lstat
    changed = False

    def reparse(candidate, *args, **kwargs):
        info = original(candidate, *args, **kwargs)
        if changed and candidate == flagged:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    def mutate(call):
        nonlocal changed
        changed = True

    monkeypatch.setattr(Path, "lstat", reparse)
    watch_reads(monkeypatch, on_read=mutate)
    with pytest.raises(fs.UnsafePathError, match="^reparse_point$"):
        fs.read_bounded(path, 1024)
