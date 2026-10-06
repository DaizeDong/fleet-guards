"""Build and run the installed wheel outside its source checkout."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from make_fixtures import _no_window  # noqa: E402


def run(*arguments, **kwargs):
    result = subprocess.run([sys.executable, *arguments], capture_output=True,
                            text=True, timeout=120, **_no_window(**kwargs))
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def test_wheel_runs_without_checkout_or_resolver(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("pyproject.toml", "PACKAGE.md", "LICENSE"):
        shutil.copyfile(ROOT / name, source / name)
    shutil.copytree(ROOT / "fleet_guards", source / "fleet_guards",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    wheels = tmp_path / "wheels"
    run("-m", "pip", "wheel", str(source), "--no-deps", "--no-build-isolation",
        "--wheel-dir", str(wheels), cwd=tmp_path)
    wheel, = wheels.glob("fleet_guards-0.2.0-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        assert any(name.endswith("/LICENSE") for name in archive.namelist())
        modules = {name for name in archive.namelist() if name.startswith("fleet_guards/")}
        assert modules == {"fleet_guards/" + name for name in (
            "__init__.py", "__main__.py", "filesystem.py", "findings.py", "secrets.py")}
    target = tmp_path / "installed"
    run("-m", "pip", "install", "--no-deps", "--target", str(target), str(wheel), cwd=tmp_path)
    probe = '''
import importlib.util, json, pathlib, sys
target = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(target))
import fleet_guards
from fleet_guards import filesystem, secrets
assert pathlib.Path(fleet_guards.__file__).parent == target / "fleet_guards"
assert pathlib.Path(filesystem.__file__).parent == target / "fleet_guards"
assert pathlib.Path(secrets.__file__).parent == target / "fleet_guards"
assert importlib.util.find_spec("fleet_guards.datadir") is None
assert importlib.util.find_spec("fleet_guards._datadir") is None
for name in ("UnsafePathError", "FileTooLargeError", "atomic_replace", "create_no_replace",
             "create_no_replace_with_identity", "detach_if_matches", "identity", "read_bounded",
             "sync_directory", "validate_path", "exclude_file_writes", "delete_if_identity_matches"):
    assert callable(getattr(filesystem, name))
assert secrets.scan("", max_text_chars=16 * 1024 * 1024, seconds=30)["state"] == "clean"
print(json.dumps({"version": fleet_guards.__version__, "isolated_import": True}))
'''
    result = run("-I", "-c", probe, str(target), cwd=tmp_path)
    assert json.loads(result.stdout) == {"version": "0.2.0", "isolated_import": True}
