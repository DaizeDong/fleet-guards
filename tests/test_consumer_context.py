"""Caller contexts never borrow environment or current directory from another call."""
from concurrent.futures import ThreadPoolExecutor
import os

from fleet_guards import datadir
from fleet_guards import secrets


def test_concurrent_explicit_contexts_do_not_mutate_ambient_state(tmp_path, monkeypatch):
    tool = tmp_path / 'consumer'
    tool.mkdir()
    ambient = tmp_path / 'ambient'
    ambient.mkdir()
    monkeypatch.setenv('DEMO_DATA_DIR', str(ambient))
    requests = []
    for label in ('first', 'second'):
        home = tmp_path / label
        (home / 'private').mkdir(parents=True)
        env = {'HOME': str(home), 'USERPROFILE': str(home), 'DEMO_DATA_DIR': '~/private'}
        requests.append((env, home, home / 'private'))
    before = dict(os.environ)
    old_cwd = os.getcwd()
    def resolve(row):
        env, home, expected = row
        return datadir.resolve_data_dir('demo', consumer_root=tool, env=env, cwd=home), expected
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(resolve, requests * 20))
    assert all(actual == expected for actual, expected in results)
    assert dict(os.environ) == before
    assert os.getcwd() == old_cwd


def test_relative_pointer_uses_explicit_cwd(tmp_path):
    tool = tmp_path / 'consumer'
    tool.mkdir()
    run = tmp_path / 'run'
    private = run / 'private'
    private.mkdir(parents=True)
    env = {'DEMO_CONFIG': 'private', 'HOME': str(run), 'USERPROFILE': str(run)}
    assert datadir.resolve_companion_root('demo', consumer_root=tool, env=env, cwd=run) == private


def test_context_missing_home_does_not_probe_ambient_home(tmp_path):
    tool = tmp_path / 'consumer'
    tool.mkdir()
    assert datadir.resolve_data_dir('demo', consumer_root=tool, env={}, cwd=tmp_path) is None


def test_support_custom_entropy_threshold_is_not_lost():
    text = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    assert secrets.scan(text, 'support-egress-v1', entropy_threshold=3.0)['state'] == 'findings'
    assert secrets.scan(text, 'support-egress-v1', entropy_threshold=8.0)['state'] == 'clean'
    assert secrets.scan(text, 'support-egress-v1', entropy_threshold=float('nan'))['state'] == 'scan_failed'
