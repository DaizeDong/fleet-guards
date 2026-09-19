"""Candidate-only evidence for opened-object publication identity."""
import os

import pytest

from fleet_guards import filesystem as fs


def test_identity_result_never_adopts_a_replacement(tmp_path, monkeypatch):
    path = tmp_path / 'note'
    seen = {}
    sync = fs._sync_directory

    def replace(parent):
        seen['published'] = fs.identity(path)
        replacement = parent / 'competitor'
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)
        seen['competitor'] = fs.identity(path)
        sync(parent)

    monkeypatch.setattr(fs, '_sync_directory', replace)
    result = fs.create_no_replace_with_identity(path, b'synthetic')
    assert result == seen['published'] != seen['competitor']
    assert fs.identity(path) == seen['competitor']
    assert list(tmp_path.iterdir()) == [path]


def test_identity_unavailable_fails_before_publication(tmp_path, monkeypatch):
    path = tmp_path / 'note'

    def fail(info):
        raise OSError('synthetic missing identity')

    monkeypatch.setattr(fs, '_stat_identity', fail)
    with pytest.raises(OSError, match='missing identity'):
        fs.create_no_replace_with_identity(path, b'synthetic')
    assert list(tmp_path.iterdir()) == []


def test_bool_api_delegates_to_shared_identity_implementation(tmp_path, monkeypatch):
    calls = []
    def create(path, data, mode):
        calls.append((path, data, mode))
        return [1, 2] if data else None
    monkeypatch.setattr(fs, 'create_no_replace_with_identity', create)
    path = tmp_path / 'note'
    assert fs.create_no_replace(path, b'synthetic') is True
    assert fs.create_no_replace(path, b'') is False
    assert calls == [(path, b'synthetic', 0o600), (path, b'', 0o600)]
