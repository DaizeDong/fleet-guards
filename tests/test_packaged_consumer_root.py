"""Companion resolution across checkout, submodule, linked tree and wheel."""
import importlib.util
from pathlib import Path
import os
import subprocess
import sys
import zipfile

import pytest


REPO = Path(__file__).resolve().parents[1]


def legacy():
    spec = importlib.util.spec_from_file_location("legacy_datadir", REPO / "tools" / "datadir.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def packaged():
    assert importlib.util.find_spec("fleet_guards") is not None, "shared package is missing"
    from fleet_guards import datadir
    return datadir


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for key in ("DEMO_DATA_DIR", "DEMO_CONFIG", "DEMO_CONFIG_DIR"):
        monkeypatch.delenv(key, raising=False)


def layout(tmp_path, kind):
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    if kind == "linked":
        gitdir = tmp_path / "main" / ".git" / "worktrees" / "consumer"
        gitdir.mkdir(parents=True)
        (gitdir / "commondir").write_text("../..\n")
        (consumer / ".git").write_text("gitdir: " + gitdir.as_posix() + "\n")
    else:
        (consumer / ".git").mkdir()
    if kind == "submodule":
        kit = consumer / "guards"
        kit.mkdir()
        (kit / ".git").write_text("gitdir: ../.git/modules/guards\n")
        module_path = kit / "tools" / "datadir.py"
    else:
        module_path = consumer / "tools" / "datadir.py"
    companion = tmp_path / "demo-config"
    (companion / "data").mkdir(parents=True)
    (companion / ".companion").write_text("demo\n")
    return consumer, module_path, companion


@pytest.mark.parametrize("kind", ["checkout", "submodule", "linked"])
def test_legacy_discovers_consumer_sibling(monkeypatch, tmp_path, kind):
    consumer, module_path, companion = layout(tmp_path, kind)
    dd = legacy()
    monkeypatch.setattr(dd, "__file__", str(module_path))
    assert dd._own_repo_root() == str(consumer)
    assert dd.resolve_companion_root("demo") == companion
    assert dd.resolve_data_dir("demo") == companion / "data"


def test_legacy_explicit_root_overrides_module_location(monkeypatch, tmp_path):
    consumer, _, companion = layout(tmp_path, "checkout")
    dd = legacy()
    monkeypatch.setattr(dd, "__file__", str(tmp_path / "site-packages" / "tools" / "datadir.py"))
    assert dd.resolve_data_dir("demo", consumer_root=consumer) == companion / "data"


def test_linked_companion_identity_uses_common_git_config(tmp_path, monkeypatch):
    consumer, _, companion = layout(tmp_path, "checkout")
    (companion / ".companion").unlink()
    common = tmp_path / "main-companion" / ".git"
    worktree = common / "worktrees" / "companion"
    worktree.mkdir(parents=True)
    (common / "config").write_text('[remote "origin"]\nurl = https://example.com/acme/demo-config.git\n')
    (worktree / "commondir").write_text("../..\n")
    (companion / ".git").write_text("gitdir: " + worktree.as_posix() + "\n")
    dd = legacy()
    monkeypatch.setattr(dd, "__file__", str(consumer / "tools" / "datadir.py"))
    assert dd.resolve_companion_root("demo") == companion


def test_packaged_api_requires_explicit_root_and_rejects_in_repo_data(tmp_path, monkeypatch):
    dd = packaged()
    consumer, _, companion = layout(tmp_path, "checkout")
    with pytest.raises(TypeError):
        dd.resolve_data_dir("demo")
    assert dd.resolve_data_dir("demo", consumer_root=consumer) == companion / "data"
    inside = consumer / "data"
    inside.mkdir()
    monkeypatch.setenv("DEMO_DATA_DIR", str(inside))
    with pytest.raises(dd.DataDirInsideOwnRepo):
        dd.resolve_data_dir("demo", create=True, consumer_root=consumer)
    assert list(inside.iterdir()) == []


def test_packaged_precedence_and_unproven_companion(tmp_path, monkeypatch):
    dd = packaged()
    consumer, _, companion = layout(tmp_path, "checkout")
    (companion / ".companion").unlink()
    with pytest.raises(dd.CompanionUnproven):
        dd.resolve_companion_root("demo", consumer_root=consumer)
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    monkeypatch.setenv("DEMO_CONFIG", str(explicit))
    assert dd.resolve_companion_root("demo", consumer_root=consumer) == explicit


def test_packaged_data_path_cannot_escape_to_the_consumer(tmp_path):
    dd = packaged()
    consumer, _, _ = layout(tmp_path, "checkout")
    for relative in ("../../consumer/output", consumer / "output"):
        with pytest.raises(ValueError):
            dd.data_path("demo", relative, create=True, consumer_root=consumer)
    assert not (consumer / "output").exists()


def test_packaged_create_refuses_a_missing_in_repo_destination(tmp_path, monkeypatch):
    dd = packaged()
    consumer = tmp_path / "consumer"
    consumer.mkdir()
    target = consumer / "new-data"
    monkeypatch.setenv("DEMO_DATA_DIR", str(target))
    with pytest.raises(dd.DataDirInsideOwnRepo):
        dd.resolve_data_dir("demo", create=True, consumer_root=consumer)
    assert not target.exists()


def test_wheel_resolves_for_consumer_without_checkout_imports(tmp_path):
    packaged()
    from setuptools.build_meta import build_wheel
    stage = tmp_path / "wheel-stage"
    stage.mkdir()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    wheel = stage / build_wheel(str(stage))
    installed = tmp_path / "site-packages"
    with zipfile.ZipFile(wheel) as archive:
        assert archive.read("fleet_guards/_datadir.py") == (REPO / "tools" / "datadir.py").read_bytes()
        archive.extractall(installed)
    consumer, _, companion = layout(tmp_path, "checkout")
    code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from fleet_guards import datadir
root = Path(sys.argv[2])
assert datadir.resolve_companion_root('demo', consumer_root=root) == Path(sys.argv[3])
try:
    datadir.resolve_data_dir('demo')
except TypeError:
    pass
else:
    raise AssertionError('wheel inferred a consumer root')
assert Path(datadir.__file__).is_relative_to(Path(sys.argv[1]))
"""
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(installed), str(consumer), str(companion)],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0, proc.stderr
