"""Packaged companion API. Every call explicitly names the consumer's root.

tools/datadir.py remains the single implementation for standalone hook users.
The wheel build includes that same source as fleet_guards._datadir. A checkout
loads the source directly without importing a consumer's similarly named tools.
"""
import importlib.util
import importlib
from pathlib import Path

try:
    _core = importlib.import_module("fleet_guards._datadir")
except ModuleNotFoundError as error:
    if error.name != "fleet_guards._datadir":
        raise
    source = Path(__file__).resolve().parents[1] / "tools" / "datadir.py"
    # An installed wheel must contain _datadir; never infer a consumer from cwd
    # or search for another checkout on the machine.
    if not (source.parent.parent / "pyproject.toml").is_file():
        raise ImportError("fleet_guards resolver is missing") from None
    spec = importlib.util.spec_from_file_location("fleet_guards._datadir", source)
    _core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_core)

DataDirNotInitialized = _core.DataDirNotInitialized
DataDirInsideOwnRepo = _core.DataDirInsideOwnRepo
CompanionUnproven = _core.CompanionUnproven


def _root(consumer_root):
    if consumer_root is None:
        raise ValueError("consumer_root is required")
    return _core._own_repo_root(consumer_root)


def resolve_companion_root(skill, *, consumer_root, env=None, cwd=None):
    return _core.resolve_companion_root(skill, consumer_root=_root(consumer_root), env=env, cwd=cwd)


def resolve_data_dir(skill, create=False, *, consumer_root, env=None, cwd=None):
    return _core.resolve_data_dir(skill, create=create, consumer_root=_root(consumer_root), env=env, cwd=cwd)


def data_path(skill, relpath, create=False, *, consumer_root, env=None, cwd=None):
    return _core.data_path(skill, relpath, create=create, consumer_root=_root(consumer_root), env=env, cwd=cwd)


def assert_outside_own_repo(path, skill, *, consumer_root):
    return _core.assert_outside_own_repo(path, skill, consumer_root=_root(consumer_root))
