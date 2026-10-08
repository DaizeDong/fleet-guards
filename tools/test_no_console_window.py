"""No process this kit starts may ever open a console window.

WHY THIS FILE EXISTS. A console program started by a process that has no console of its own
(pythonw, a scheduled task, a service) is handed a brand-new console, and Windows shows it as a
window. A daemon running under pythonw proved its private companion on every log line; each proof
ran about 19 git commands, and none of them asked for a hidden console. The result was roughly
9,000 terminal windows in eight hours on a machine that was then nearly unusable.

The fix is one rule: every spawn goes through `_no_window()`, which adds CREATE_NO_WINDOW when the
calling process has no console. This file holds the rule in three ways, because each alone has a
blind spot:

  1. the helper itself, every copy of it, against patched and real console states;
  2. a structural scan of every Python file in the kit, which fails on any spawn that bypasses the
     helper, and is shown to fail by negative controls that plant each bypass in a scratch copy;
  3. the real entry points (the companion proof, its read-only queries, the resolver lookup, the
     scanners' git runners) run end to end with Popen recorded, asserting what actually reached it.
"""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from make_fixtures import _no_window
import data_boundary as db
import fleet_sync
import make_fixtures
import pii_guard
import publication_guard

ROOT = Path(__file__).resolve().parent.parent
REAL_POPEN = subprocess.Popen
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
HELPER_MODULES = (db, pii_guard, publication_guard, fleet_sync, make_fixtures)
HELPERS = ("_console_less_windows", "_no_window")
PROXY_VARIABLES = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "curl_ca_bundle", "ssl_cert_file",
                   "ssl_cert_dir", "requests_ca_bundle", "curl_ssl_backend"}


# ----------------------------------------------------------------------------- 1. the helper
@pytest.fixture(params=HELPER_MODULES, ids=lambda module: module.__name__)
def module(request):
    return request.param


def test_console_query_is_windows_only(module, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert module._console_less_windows() is False
    assert module._no_window(cwd="x", text=True) == {"cwd": "x", "text": True}


def test_unanswerable_console_query_hides_the_child(module, monkeypatch):
    """If the console cannot be queried, assume the side on which no window can open."""
    import ctypes
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delattr(ctypes, "WinDLL", raising=False)
    assert module._console_less_windows() is True


def test_helper_hides_children_of_a_console_less_process(module, monkeypatch):
    monkeypatch.setattr(module, "_console_less_windows", lambda: True)
    assert module._no_window() == {"creationflags": CREATE_NO_WINDOW}
    assert module._no_window(cwd="x") == {"cwd": "x", "creationflags": CREATE_NO_WINDOW}


def test_helper_merges_flags_the_caller_already_passes(module, monkeypatch):
    monkeypatch.setattr(module, "_console_less_windows", lambda: True)
    merged = module._no_window(creationflags=CREATE_NEW_PROCESS_GROUP, env={"A": "1"})
    assert merged == {"creationflags": CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW, "env": {"A": "1"}}
    assert module._no_window(creationflags=None) == {"creationflags": CREATE_NO_WINDOW}


def test_helper_leaves_a_shared_console_alone(module, monkeypatch):
    """With a console, children share it: no window, and no output moved into a hidden console."""
    monkeypatch.setattr(module, "_console_less_windows", lambda: False)
    assert module._no_window(capture_output=True) == {"capture_output": True}
    assert module._no_window(creationflags=CREATE_NEW_PROCESS_GROUP) == {
        "creationflags": CREATE_NEW_PROCESS_GROUP}


@pytest.mark.parametrize("console_less", [True, False])
@pytest.mark.parametrize("flag", [DETACHED_PROCESS, CREATE_NEW_CONSOLE,
                                  DETACHED_PROCESS | CREATE_NO_WINDOW])
def test_helper_refuses_flags_that_open_or_orphan_a_console(module, monkeypatch, console_less, flag):
    """DETACHED_PROCESS makes Windows ignore CREATE_NO_WINDOW; CREATE_NEW_CONSOLE is a window."""
    monkeypatch.setattr(module, "_console_less_windows", lambda: console_less)
    with pytest.raises(ValueError):
        module._no_window(creationflags=flag)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows creation flags")
def test_helper_constant_is_the_platform_constant():
    assert CREATE_NO_WINDOW == subprocess.CREATE_NO_WINDOW
    assert DETACHED_PROCESS == subprocess.DETACHED_PROCESS
    assert CREATE_NEW_CONSOLE == subprocess.CREATE_NEW_CONSOLE


def _pythonw():
    candidate = Path(sys.executable).with_name("pythonw.exe")
    return candidate if candidate.is_file() else None


PROBE = r"""
import ctypes, json, sys
kernel = ctypes.WinDLL("kernel32")
kernel.GetConsoleWindow.restype = ctypes.c_void_p
window = kernel.GetConsoleWindow()
visible = bool(window) and bool(ctypes.WinDLL("user32").IsWindowVisible(ctypes.c_void_p(window)))
print(json.dumps({"console": bool(kernel.GetConsoleCP()), "visible": visible}))
"""

DRIVER = r"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("_console_probe_boundary", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
result = {"console_less": module._console_less_windows(), "keywords": module._no_window()}
result["child"] = json.loads(module._run([sys.argv[3], "-c", sys.argv[4]], sys.argv[5]))
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(result, stream)
"""


@pytest.mark.skipif(sys.platform != "win32" or _pythonw() is None, reason="needs pythonw.exe")
def test_real_console_less_parent_gives_its_git_runner_a_hidden_console(tmp_path):
    """The incident's own shape, for real: pythonw -> data_boundary._run -> console child.

    The child must still HAVE a console (its own children inherit that hidden one instead of
    opening windows) and must have no visible window. If the helper regressed, this test would
    open the very window it exists to forbid; that is the honest failure mode of a real-process
    check, and the patched and structural checks above and below fail first.
    """
    driver = tmp_path / "driver.py"
    driver.write_text(DRIVER, encoding="utf-8")
    report = tmp_path / "report.json"
    result = subprocess.run([str(_pythonw()), str(driver), str(ROOT / "tools/data_boundary.py"), str(report),
                             sys.executable, PROBE, str(tmp_path)],
                            capture_output=True, text=True, timeout=120, **_no_window())
    assert result.returncode == 0, result.stderr
    observed = json.loads(report.read_text(encoding="utf-8"))
    assert observed["console_less"] is True
    assert observed["keywords"] == {"creationflags": CREATE_NO_WINDOW}
    assert observed["child"] == {"console": True, "visible": False}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows consoles")
def test_a_hidden_console_counts_as_a_console(tmp_path):
    """A child started with the flag reports a console, so it adds no flag of its own."""
    result = subprocess.run([sys.executable, "-c",
                             "import importlib.util, sys\n"
                             "spec = importlib.util.spec_from_file_location('m', sys.argv[1])\n"
                             "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
                             "print(m._console_less_windows())",
                             str(ROOT / "tools/pii_guard.py")],
                            capture_output=True, text=True, timeout=120,
                            **_no_window(creationflags=CREATE_NO_WINDOW))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


# ----------------------------------------------------------------------------- 2. the structure
SPAWN_FUNCTIONS = {"run", "Popen", "call", "check_call", "check_output"}
NO_FLAG_POSSIBLE = {"getoutput", "getstatusoutput"}
OS_SPAWNERS = {"system", "popen", "startfile", "posix_spawn", "posix_spawnp"}
FORBIDDEN_MODULES = {"multiprocessing", "_winapi", "pty"}
SKIP_DIRECTORIES = {".git", "__pycache__", ".pytest_cache", "build", "dist"}


def _python_files(root):
    for directory, names, files in os.walk(root):
        here = Path(directory)
        names[:] = sorted(name for name in names
                          if name not in SKIP_DIRECTORIES and not name.endswith(".egg-info")
                          and not (here / name / ".git").exists())
        for name in sorted(files):
            if name.endswith(".py"):
                yield here / name


def _is_subprocess(node):
    return ((isinstance(node, ast.Name) and node.id == "subprocess")
            or (isinstance(node, ast.Attribute) and node.attr == "subprocess"))


def _is_helper_call(node):
    return (isinstance(node, ast.Call)
            and ((isinstance(node.func, ast.Name) and node.func.id == "_no_window")
                 or (isinstance(node.func, ast.Attribute) and node.func.attr == "_no_window")))


def _module_functions(tree):
    return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}


def scan(root):
    """Return (violations, spawn calls checked) for every Python file under `root`."""
    root = Path(root)
    violations, checked, trees = [], 0, {}
    for path in _python_files(root):
        relative = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        trees[relative] = tree
        is_test = path.name.startswith("test_") or path.name == "conftest.py"
        calls = {id(node.func): node for node in ast.walk(tree) if isinstance(node, ast.Call)}
        spawns = 0

        def report(node, reason):
            violations.append("%s:%d: %s" % (relative, node.lineno, reason))

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]
                names = {alias.name for alias in node.names}
                if module == "subprocess" and names & (SPAWN_FUNCTIONS | NO_FLAG_POSSIBLE | {"*"}):
                    report(node, "imports a spawn function by name, out of the scan's sight")
                if module == "os" and names & (OS_SPAWNERS | {"*"} | {n for n in names if n.startswith(("spawn", "exec"))}):
                    report(node, "imports an os spawn function by name")
                if module in FORBIDDEN_MODULES or (module == "concurrent" and "ProcessPoolExecutor" in names):
                    report(node, "imports a module that starts processes without the helper")
                if module == "asyncio" and names & {"create_subprocess_exec", "create_subprocess_shell"}:
                    report(node, "imports an asyncio spawn function")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "subprocess" and alias.asname not in (None, "subprocess"):
                        report(node, "aliases subprocess, out of the scan's sight")
                    if alias.name.split(".")[0] in FORBIDDEN_MODULES:
                        report(node, "imports a module that starts processes without the helper")
            elif isinstance(node, ast.Attribute):
                if _is_subprocess(node.value) and node.attr in NO_FLAG_POSSIBLE:
                    report(node, "subprocess.%s cannot take creationflags" % node.attr)
                elif isinstance(node.value, ast.Name) and node.value.id == "os" and (
                        node.attr in OS_SPAWNERS or node.attr.startswith(("spawn", "exec"))):
                    report(node, "os.%s cannot take creationflags" % node.attr)
                elif node.attr in {"create_subprocess_exec", "create_subprocess_shell", "ProcessPoolExecutor"}:
                    report(node, "%s starts processes without the helper" % node.attr)
                elif _is_subprocess(node.value) and node.attr in SPAWN_FUNCTIONS:
                    call = calls.get(id(node))
                    if call is None:
                        # A test may keep the original to wrap it (`original = subprocess.run`);
                        # the wrapped call still passes the caller's flagged keywords through.
                        if not is_test:
                            report(node, "references subprocess.%s without calling it" % node.attr)
                        continue
                    spawns += 1
                    splats = [keyword.value for keyword in call.keywords if keyword.arg is None]
                    if not any(_is_helper_call(value) for value in splats):
                        report(node, "subprocess.%s without **_no_window(...)" % node.attr)
                    if any(keyword.arg == "creationflags" for keyword in call.keywords):
                        report(node, "creationflags passed beside the helper; pass it through it")
        checked += spawns
        if spawns and not is_test and relative.startswith("tools/"):
            defined = _module_functions(tree)
            for name in HELPERS:
                if name not in defined:
                    violations.append("%s: spawns but carries no %s of its own" % (relative, name))
    canonical = _module_functions(trees["tools/data_boundary.py"])
    for relative, tree in sorted(trees.items()):
        for name, function in _module_functions(tree).items():
            if name in HELPERS and ast.dump(function) != ast.dump(canonical[name]):
                violations.append("%s:%d: %s differs from tools/data_boundary.py"
                                  % (relative, function.lineno, name))
    return violations, checked


def test_every_spawn_in_the_kit_goes_through_the_helper():
    violations, checked = scan(ROOT)
    assert violations == []
    # A scan that found nothing would also report nothing. There are dozens of spawns here.
    assert checked >= 40, "scan examined only %d spawn calls" % checked


def test_every_kit_module_that_spawns_carries_the_helper():
    tools = {path.name for path in (ROOT / "tools").glob("*.py") if not path.name.startswith("test_")}
    spawning = set()
    for name in tools:
        tree = ast.parse((ROOT / "tools" / name).read_text(encoding="utf-8"))
        if any(isinstance(node, ast.Attribute) and _is_subprocess(node.value) and node.attr in SPAWN_FUNCTIONS
               for node in ast.walk(tree)):
            spawning.add(Path(name).stem)
    assert spawning == {module.__name__ for module in HELPER_MODULES}


MUTATIONS = {
    "unflagged-run": ("tools/data_boundary.py",
                      "\n\ndef _planted():\n    return subprocess.run(['git', 'status'], capture_output=True)\n",
                      "subprocess.run without **_no_window"),
    "unflagged-popen": ("tools/pii_guard.py",
                        "\n\ndef _planted():\n    return subprocess.Popen(['git', 'status'])\n",
                        "subprocess.Popen without **_no_window"),
    "unflagged-test-spawn": ("tools/test_datadir.py",
                             "\n\ndef _planted():\n    return subprocess.check_output(['git', 'status'])\n",
                             "subprocess.check_output without **_no_window"),
    "creationflags-beside-helper": ("tools/fleet_sync.py",
                                    "\n\ndef _planted():\n    return subprocess.run(['git'], creationflags=8,"
                                    " **_no_window())\n",
                                    "creationflags passed beside the helper"),
    "os-system": ("tools/publication_guard.py", "\n\ndef _planted():\n    return os.system('git status')\n",
                  "os.system cannot take creationflags"),
    "os-popen": ("tools/data_boundary.py", "\n\ndef _planted():\n    return os.popen('git status')\n",
                 "os.popen cannot take creationflags"),
    "getoutput": ("tools/data_boundary.py", "\n\ndef _planted():\n    return subprocess.getoutput('git')\n",
                  "subprocess.getoutput cannot take creationflags"),
    "from-import": ("tools/data_boundary.py", "\nfrom subprocess import run as _planted\n",
                    "imports a spawn function by name"),
    "alias-import": ("tools/data_boundary.py", "\nimport subprocess as _planted\n",
                     "aliases subprocess"),
    "multiprocessing": ("tools/data_boundary.py", "\nimport multiprocessing\n",
                        "imports a module that starts processes"),
    "bare-reference": ("tools/data_boundary.py", "\n_planted = subprocess.run\n",
                       "references subprocess.run without calling it"),
    "drifted-copy": ("tools/pii_guard.py", None, "_no_window differs from tools/data_boundary.py"),
    "missing-copy": ("tools/make_fixtures.py", None, "carries no _console_less_windows of its own"),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_negative_control_each_bypass_turns_the_scan_red(tmp_path, mutation):
    """Plant each bypass in a scratch copy; the scan must name it. Proves the check can fail."""
    copy = tmp_path / "kit"
    for directory in ("tools", "tests", "fleet_guards"):
        shutil.copytree(ROOT / directory, copy / directory,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copyfile(ROOT / "conftest.py", copy / "conftest.py")
    assert scan(copy)[0] == []
    relative, planted, expected = MUTATIONS[mutation]
    target = copy / relative
    text = target.read_text(encoding="utf-8")
    if mutation == "drifted-copy":
        assert text.count("flags | 0x08000000") == 1
        text = text.replace("flags | 0x08000000", "flags | 0x00000000")
    elif mutation == "missing-copy":
        tree = ast.parse(text)
        function = _module_functions(tree)["_console_less_windows"]
        lines = text.splitlines(keepends=True)
        text = "".join(lines[:function.lineno - 1] + lines[function.end_lineno:])
    else:
        text += planted
    target.write_text(text, encoding="utf-8")
    violations, _ = scan(copy)
    assert any(expected in violation for violation in violations), violations


# ----------------------------------------------------------------------------- 3. the entry points
class SpawnRecord(list):
    """The (args, creationflags) of every Popen while `recording`; pause it to build fixtures."""
    recording = True


@pytest.fixture
def popen_record(monkeypatch):
    """Record the creationflags each real spawn receives, as a console-less process would send them.

    The process is made to look console-less (pythonw) to every helper copy. On Windows the flag is
    passed on to the real Popen, so the git commands genuinely run in a hidden console; elsewhere it
    is recorded and then removed, because POSIX Popen refuses creationflags.
    """
    real_windows = sys.platform == "win32"
    seen = SpawnRecord()

    class Recording(REAL_POPEN):
        def __init__(self, args, *positional, **keywords):
            if seen.recording:
                seen.append((args, keywords.get("creationflags", 0)))
            if not real_windows:
                keywords.pop("creationflags", None)
            super().__init__(args, *positional, **keywords)

    for module in HELPER_MODULES:
        monkeypatch.setattr(module, "_console_less_windows", lambda: True)
    monkeypatch.setattr(subprocess, "Popen", Recording)
    return seen


def _assert_all_hidden(seen, minimum=1):
    assert len(seen) >= minimum, seen
    unflagged = [args for args, flags in seen if not (flags or 0) & CREATE_NO_WINDOW]
    assert unflagged == []


@pytest.fixture
def plain_repo(tmp_path):
    repo = tmp_path / "plain"
    repo.mkdir()
    env = dict(os.environ, GIT_CONFIG_GLOBAL=str(tmp_path / "absent-global"), GIT_CONFIG_NOSYSTEM="1")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, capture_output=True, env=env,
                   **_no_window())
    (repo / "note.md").write_text("synthetic\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "note.md"], check=True, capture_output=True, env=env,
                   **_no_window())
    return repo


def test_data_boundary_git_runner_is_hidden(popen_record, plain_repo):
    popen_record.clear()
    assert db._run(["git", "rev-parse", "--show-toplevel"], str(plain_repo)).strip()
    _assert_all_hidden(popen_record)


def test_scanner_git_runners_are_hidden(popen_record, plain_repo):
    popen_record.clear()
    assert pii_guard._run(["git", "rev-parse", "--show-toplevel"], str(plain_repo)).strip()
    assert pii_guard._run_stdin(["git", "hash-object", "--stdin"], str(plain_repo), "synthetic\n").strip()
    _assert_all_hidden(popen_record, minimum=2)


def test_companion_proof_and_its_queries_are_hidden(popen_record, monkeypatch, tmp_path_factory):
    """The incident path: prove_private_companion on every write, then read-only queries."""
    from make_fixtures import make_private_api_fixture
    from test_git_context import git_environment
    # The proof refuses an ambient proxy or trust override, which is not what is under test here.
    for key in [key for key in os.environ if key.lower() in PROXY_VARIABLES]:
        monkeypatch.delenv(key)
    popen_record.recording = False      # build the fixture unrecorded; record only the proof
    fixture = make_private_api_fixture(tmp_path_factory.mktemp("console"), pii_guard._utcnow())
    popen_record.recording = True
    private = fixture["repos"]["private"]
    with git_environment(monkeypatch, private.env):
        proof = db.prove_private_companion(private.root, fixture["receipt"])
        proved = len(popen_record)
        head = db.read_private_companion_git(proof, "rev-parse", "--verify", "HEAD")
    assert head.returncode == 0
    assert proved >= 5, "the proof ran %d commands; it should run its full git inquiry" % proved
    _assert_all_hidden(popen_record, minimum=proved + 1)


def test_resolver_lookup_is_hidden(popen_record, tmp_path):
    """Selecting the deployment's datadir.py runs git against the consumer and its submodule."""
    from test_data_boundary import native_submodule_layout
    popen_record.recording = False
    consumer, _ = native_submodule_layout(tmp_path, "guards", resolver=True)
    popen_record.recording = True
    resolver = db._resolver_path(os.path.realpath(str(consumer)))
    assert resolver.endswith(os.path.join("guards", "tools", "datadir.py"))
    _assert_all_hidden(popen_record, minimum=3)


def test_fixture_generator_check_is_hidden(popen_record, tmp_path):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools/make_fixtures.py").write_text(
        "import pathlib, sys\n"
        "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1])\n"
        "(out / 'sample.json').write_text('{}\\n')\n", encoding="utf-8")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures/sample.json").write_text("{}\n", encoding="utf-8")
    out = []
    db.check_fixtures_are_generated(str(tmp_path), {"fixture": ["fixtures/sample.json"]}, out)
    assert out == []
    _assert_all_hidden(popen_record)


def test_sync_git_runner_is_hidden(popen_record, monkeypatch, plain_repo):
    popen_record.clear()
    monkeypatch.chdir(plain_repo)
    assert fleet_sync.git("rev-parse", "--show-toplevel")
    _assert_all_hidden(popen_record)


def test_publication_exec_path_probe_is_hidden(popen_record, monkeypatch):
    """Hooks inherit GIT_EXEC_PATH; the guard asks git for its default before trusting it."""
    git = shutil.which("git")
    if not git:
        pytest.skip("git is not on PATH")
    for key in [key for key in os.environ if key.upper() == "GIT_EXEC_PATH"]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("GIT_EXEC_PATH", os.path.join(os.path.dirname(git), "synthetic-exec-path"))
    popen_record.clear()
    with publication_guard.native_hook_environment("pre-commit"):
        pass
    assert [args[1:] for args, _ in popen_record] == [["--exec-path"]]
    _assert_all_hidden(popen_record)


def test_companion_exec_path_probe_is_hidden(popen_record):
    environment = {key: value for key, value in os.environ.items() if key.upper() != "GIT_EXEC_PATH"}
    native = subprocess.run(["git", "--exec-path"], env=environment, capture_output=True,
                            text=True, check=True, **_no_window()).stdout.strip()
    environment["GIT_EXEC_PATH"] = native
    popen_record.clear()
    assert db._git_exec_path_problem(environment) is None
    assert [args[1:] for args, _ in popen_record] == [["--exec-path"]]
    _assert_all_hidden(popen_record)
