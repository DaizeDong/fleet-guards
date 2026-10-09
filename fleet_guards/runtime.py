"""Consumer-bound access to the canonical companion and PRIVATE admission tools."""
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
import threading

_LOAD_LOCK = threading.RLock()


def _canonical(name):
    with _LOAD_LOCK:
        return _load_canonical(name)


def _load_canonical(name):
    directory = Path(__file__).resolve().parent / "_canonical"
    if not directory.is_dir():
        source = directory.parent.parent
        if not (source / ".git").exists() or not (source / "pyproject.toml").is_file():
            raise ImportError("canonical Guards tools are missing; reinstall the accepted wheel")
        directory = source / "tools"
    path = directory / (name + ".py")
    key = "_fleet_guards_canonical_" + name
    previous = sys.modules.get(key)
    if previous is not None and Path(previous.__file__).resolve() == path:
        return previous
    spec = importlib.util.spec_from_file_location(key, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(key, None)
        raise
    return module


@dataclass(frozen=True)
class CompanionResolver:
    source_root: Path

    def __post_init__(self):
        path = Path(self.source_root)
        if not path.is_absolute():
            raise ValueError("source_root must be absolute")
        object.__setattr__(self, "source_root", path.resolve())

    def resolve_data_dir(self, skill, create=False):
        return _canonical("datadir").resolve_data_dir(
            skill, create=create, source_root=self.source_root)

    def resolve_companion_root(self, skill):
        return _canonical("datadir").resolve_companion_root(skill, source_root=self.source_root)

    def assert_outside_own_repo(self, path, skill):
        return _canonical("datadir").assert_outside_own_repo(
            path, skill, source_root=self.source_root)

    def data_path(self, skill, relative_path, create=False):
        return _canonical("datadir").data_path(
            skill, relative_path, create=create, source_root=self.source_root)


def companion_resolver(*, source_root):
    """Bind discovery to an explicit consumer source root, never the Guards installation."""
    return CompanionResolver(source_root)


def prove_private_companion(destination, *, visibility_map=None):
    """Check current effective Git routes using the canonical PRIVATE proof implementation."""
    return _canonical("data_boundary").prove_private_companion(
        destination, visibility_map=visibility_map)


def query_github_visibility(repository, *, timeout=20):
    """Ask GitHub for OWNER/NAME's visibility with any logged-in gh account, never the active one alone."""
    return _canonical("data_boundary").query_github_visibility(repository, timeout=timeout)


def authorize_artifact_write(source_root, companion_root, relative_path, **options):
    """Apply the canonical source contract and current PRIVATE admission before a write."""
    return _canonical("storage_contract").authorize_artifact_write(
        source_root, companion_root, relative_path, **options)
