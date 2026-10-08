"""Consumer-bound discovery uses the canonical engine in source and wheel builds."""
import importlib.util
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_source_resolver_requires_an_explicit_absolute_consumer(tmp_path):
    from fleet_guards.runtime import companion_resolver
    with pytest.raises(TypeError):
        companion_resolver()
    with pytest.raises(ValueError, match="absolute"):
        companion_resolver(source_root=Path("relative"))


def test_source_resolver_discovers_consumer_sibling_and_rejects_its_source(tmp_path, monkeypatch):
    from fleet_guards.runtime import companion_resolver
    source = tmp_path / "synthetic-tool"
    source.mkdir()
    companion = tmp_path / "synthetic-tool-config"
    companion.mkdir()
    (companion / ".companion").write_text("synthetic-tool\n", encoding="utf-8")
    (companion / "data").mkdir()
    for name in ("SYNTHETIC_TOOL_CONFIG", "SYNTHETIC_TOOL_CONFIG_DIR", "SYNTHETIC_TOOL_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    resolver = companion_resolver(source_root=source)
    assert resolver.resolve_companion_root("synthetic-tool") == companion
    assert resolver.resolve_data_dir("synthetic-tool") == companion / "data"
    monkeypatch.setenv("SYNTHETIC_TOOL_DATA_DIR", str(source))
    with pytest.raises(RuntimeError, match="INSIDE"):
        resolver.resolve_data_dir("synthetic-tool")


def test_bound_roots_remain_independent_in_one_process(tmp_path, monkeypatch):
    from fleet_guards.runtime import companion_resolver
    for name in ("SYNTHETIC_TOOL_CONFIG", "SYNTHETIC_TOOL_CONFIG_DIR", "SYNTHETIC_TOOL_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    resolvers = []
    for name in ("first", "second"):
        base = tmp_path / name
        source = base / "synthetic-tool"
        source.mkdir(parents=True)
        companion = base / "synthetic-tool-config"
        companion.mkdir()
        (companion / ".companion").write_text("synthetic-tool\n", encoding="utf-8")
        resolvers.append((companion_resolver(source_root=source), companion))
    for resolver, companion in reversed(resolvers):
        assert resolver.resolve_companion_root("synthetic-tool") == companion


def test_standalone_submodule_discovery_is_preserved(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("standalone_datadir", ROOT / "tools/datadir.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    consumer = tmp_path / "synthetic-tool"
    consumer.mkdir()
    (consumer / ".git").mkdir()
    guard_root = consumer / "guards"
    guard_root.mkdir()
    (guard_root / ".git").write_text("gitdir: ../.git/modules/guards\n", encoding="utf-8")
    monkeypatch.setattr(module, "__file__", str(guard_root / "tools/datadir.py"))
    assert os.path.normcase(module._own_repo_root()) == os.path.normcase(str(consumer))
