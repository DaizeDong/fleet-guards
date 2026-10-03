"""Generated native regressions for physical companions and original Git objects."""
import os
from contextlib import contextmanager

import pytest

import data_boundary as db
import pii_guard as guard
from make_fixtures import (
    companion_environment_cases,
    make_companion_context_fixture,
    make_original_object_fixture,
    make_selected_index_fixture,
)
from make_fixtures import (
    make_private_api_fixture,
    private_api_forbidden_queries,
    private_api_remote_selection_cases,
    private_api_directory_queries,
)


@pytest.fixture(scope="module")
def private_api_fixture(tmp_path_factory):
    return make_private_api_fixture(tmp_path_factory.mktemp("private-api"), guard._utcnow())


def test_public_private_proof_preserves_context_without_exposing_environment(private_api_fixture, monkeypatch):
    fixture = private_api_fixture
    private = fixture["repos"]["private"]
    invoker = fixture["repos"]["invoker"]
    environment = dict(private.env, GIT_DIR=invoker.git("rev-parse", "--absolute-git-dir"),
                       FG_SYNTHETIC_SECRET=fixture["sentinel"])
    with git_environment(monkeypatch, environment):
        first = db.prove_private_companion(private.root / "archive", fixture["receipt"])
        second = db.prove_private_companion(private.root / "archive", fixture["receipt"])
        assert first.root == str(private.root.resolve())
        assert first.repositories == ("example-owner/synthetic-private",)
        assert first.signature == second.signature
        assert fixture["sentinel"] not in repr(first)
        assert "FG_SYNTHETIC_SECRET" not in repr(first)
        with pytest.raises(AttributeError):
            first.root = str(invoker.root)
        assert db.read_private_companion_git(first, "rev-parse", "--verify", "HEAD").stdout.strip() == private.git("rev-parse", "HEAD")
        for relative, status in ((fixture["ignored"], 0), (fixture["unignored"], 1)):
            query = db.read_private_companion_git(first, "check-ignore", "--no-index", "-q", "--", relative)
            assert query.returncode == status


@pytest.mark.parametrize("target", ["public", "unknown"])
def test_public_private_proof_rejects_unproved_destinations(private_api_fixture, monkeypatch, target):
    repo = private_api_fixture["repos"][target]
    with git_environment(monkeypatch, repo.env), pytest.raises(db.GitError):
        db.prove_private_companion(repo.root, private_api_fixture["receipt"])


def test_public_private_proof_signature_binds_routing(private_api_fixture, monkeypatch):
    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    with git_environment(monkeypatch, repo.env):
        original = db.prove_private_companion(repo.root, fixture["receipt"])
        try:
            repo.git("config", "remote.origin.pushurl", fixture["alternate_route"])
            updated = db.prove_private_companion(repo.root, fixture["receipt"])
            assert updated.repositories == original.repositories
            assert updated.signature != original.signature
            with pytest.raises(db.GitError, match="changed"):
                db.read_private_companion_git(original, "rev-parse", "--verify", "HEAD")
        finally:
            repo.git("config", "--unset-all", "remote.origin.pushurl")


def test_public_private_proof_refuses_changes_during_attestation(private_api_fixture, monkeypatch):
    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    original = db._companion_visibility
    def changed(*arguments):
        result = original(*arguments)
        repo.git("config", "remote.origin.pushurl", fixture["alternate_route"])
        return result
    monkeypatch.setattr(db, "_companion_visibility", changed)
    with git_environment(monkeypatch, repo.env):
        try:
            with pytest.raises(db.GitError, match="changed"):
                db.prove_private_companion(repo.root, fixture["receipt"])
        finally:
            repo.git("config", "--unset-all", "remote.origin.pushurl")


@pytest.mark.parametrize("arguments", private_api_forbidden_queries())
def test_public_private_queries_reject_unsupported_operations_before_execution(
        private_api_fixture, monkeypatch, arguments):
    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    with git_environment(monkeypatch, repo.env):
        proof = db.prove_private_companion(repo.root, fixture["receipt"])
        monkeypatch.setattr(db.subprocess, "run", lambda *args, **kwargs: pytest.fail("unsupported query executed"))
        with pytest.raises(db.GitError):
            db.read_private_companion_git(proof, *arguments)


@pytest.mark.parametrize("failure", ["status", "launch"])
def test_public_private_ignore_failures_cannot_mean_unignored(private_api_fixture, monkeypatch, failure):
    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    with git_environment(monkeypatch, repo.env):
        proof = db.prove_private_companion(repo.root, fixture["receipt"])
        original = db.subprocess.run
        def failed_query(command, *args, **kwargs):
            if command[1] == "check-ignore":
                if failure == "launch":
                    raise OSError(fixture["sentinel"])
                return db.subprocess.CompletedProcess(command, 128, "", fixture["sentinel"])
            return original(command, *args, **kwargs)
        monkeypatch.setattr(db.subprocess, "run", failed_query)
        with pytest.raises(db.GitError) as error:
            db.read_private_companion_git(proof, "check-ignore", "--no-index", "-q", "--", fixture["unignored"])
        assert fixture["sentinel"] not in str(error.value)


def test_public_private_ignore_query_supports_repository_root(private_api_fixture, monkeypatch):
    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    with git_environment(monkeypatch, repo.env):
        proof = db.prove_private_companion(repo.root, fixture["receipt"])
        result = db.read_private_companion_git(proof, "check-ignore", "--no-index", "-q", "--", ".")
        assert result.returncode == 1


@pytest.mark.parametrize("relative,status", private_api_directory_queries())
def test_public_private_ignore_query_preserves_absent_directory_semantics(
        private_api_fixture, monkeypatch, relative, status):
    import subprocess

    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    assert not (repo.root / relative).exists()
    arguments = ("check-ignore", "--no-index", "-q", "--", relative)
    native = subprocess.run(["git", *arguments], cwd=repo.root, env=repo.env,
                            capture_output=True)
    assert native.returncode == status
    with git_environment(monkeypatch, repo.env):
        proof = db.prove_private_companion(repo.root, fixture["receipt"])
        assert db.read_private_companion_git(proof, *arguments).returncode == status
    assert not (repo.root / relative).exists()


@pytest.mark.parametrize("key,value,allowed", private_api_remote_selection_cases())
def test_public_private_proof_checks_remote_selectors(private_api_fixture, monkeypatch, key, value, allowed):
    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    with git_environment(monkeypatch, repo.env):
        try:
            repo.git("config", key, value)
            if allowed:
                assert db.prove_private_companion(repo.root, fixture["receipt"]).repositories
            else:
                with pytest.raises(db.GitError, match="remote selection"):
                    db.prove_private_companion(repo.root, fixture["receipt"])
        finally:
            repo.git("config", "--unset-all", key)


def test_public_private_proof_accepts_named_remote_without_origin(private_api_fixture, monkeypatch):
    fixture = private_api_fixture
    repo = fixture["repos"]["private"]
    with git_environment(monkeypatch, repo.env):
        try:
            repo.git("remote", "rename", "origin", "Archive")
            repo.git("config", "remote.pushDefault", "Archive")
            assert db.prove_private_companion(repo.root, fixture["receipt"]).repositories
        finally:
            repo.git("config", "--unset-all", "remote.pushDefault")
            repo.git("remote", "rename", "Archive", "origin")


@contextmanager
def git_environment(monkeypatch, env):
    with monkeypatch.context() as context:
        for key in list(os.environ):
            if key.upper().startswith("GIT_"):
                context.delenv(key)
        for key, value in env.items():
            context.setenv(key, value)
        yield


@pytest.fixture(name="tmp_path")
def short_git_tmp_path(tmp_path_factory):
    """Keep generated Git object and replacement-ref paths below Windows MAX_PATH."""
    return tmp_path_factory.mktemp("g10")


@pytest.fixture(scope="module")
def companion_fixture(tmp_path_factory):
    return make_companion_context_fixture(tmp_path_factory.mktemp("physical-companions"),
                                          guard._utcnow())


@pytest.mark.parametrize("label,expected", [("private", 0), ("public", 1), ("unknown", 1)])
def test_source10_physical_visibility_controls(companion_fixture, monkeypatch, capsys, label, expected):
    repo = companion_fixture["repos"][label]
    with git_environment(monkeypatch, repo.env):
        assert db.check_companion(str(repo.root), 5, str(companion_fixture["receipt"])) == expected
    output = capsys.readouterr()
    assert ("PRIVATE verified" in output.out) is (expected == 0)


@pytest.mark.parametrize("variant", [
    "git-dir", "git-dir-and-worktree", "common-dir", "worktree",
    "command-config", "config-parameters", "copied-index",
])
def test_source10_public_destination_cannot_borrow_private_identity(
        companion_fixture, monkeypatch, capsys, variant):
    public = companion_fixture["repos"]["public"]
    overrides = companion_environment_cases(companion_fixture)[variant]
    with git_environment(monkeypatch, dict(public.env, **overrides)):
        result = db.check_companion(str(public.root), 5, str(companion_fixture["receipt"]))
    output = capsys.readouterr()
    assert result == 1, output.out + output.err
    assert "PRIVATE verified" not in output.out
    assert "PUBLIC" in output.err


@pytest.mark.parametrize("target", ["private", "linked"])
@pytest.mark.parametrize("copied", [False, True])
def test_source10_companion_survives_other_repository_hook_context(
        companion_fixture, monkeypatch, capsys, target, copied):
    invoker = companion_fixture["repos"]["invoker"]
    selected = invoker.copy_index("hook")
    env = dict(invoker.env, GIT_DIR=invoker.git("rev-parse", "--absolute-git-dir"),
               GIT_WORK_TREE=str(invoker.root), GIT_PREFIX="archive/")
    if copied:
        env["GIT_INDEX_FILE"] = selected
    destination = companion_fixture["repos"][target].root / "archive"
    with git_environment(monkeypatch, env):
        result = db.check_companion(str(destination), 5, str(companion_fixture["receipt"]))
    output = capsys.readouterr()
    assert result == 0, output.out + output.err
    assert "PRIVATE verified: example-owner/synthetic-private" in output.out


@pytest.mark.parametrize("reverse", [False, True])
def test_source10_transient_rewrite_cannot_remove_public_destination(
        companion_fixture, monkeypatch, capsys, reverse):
    public = "https://github.com/example-owner/synthetic-public.git"
    private = "https://github.com/example-owner/synthetic-private.git"
    label, before, after = ("private", private, public) if reverse else ("public", public, private)
    repo = companion_fixture["repos"][label]
    env = dict(repo.env, GIT_CONFIG_COUNT="1",
               GIT_CONFIG_KEY_0="url." + after + ".insteadOf", GIT_CONFIG_VALUE_0=before)
    with git_environment(monkeypatch, env):
        result = db.check_companion(str(repo.root), 5, str(companion_fixture["receipt"]))
    output = capsys.readouterr()
    assert result == 1, output.out + output.err
    assert "PRIVATE verified" not in output.out


@pytest.mark.parametrize("kind", [
    "commit-body", "message", "author", "committer", "ancestor",
    "blob", "tree-path", "tag", "nested-tag",
])
@pytest.mark.parametrize("blocked", [False, True])
def test_source10_replacement_cannot_hide_original_history(tmp_path, monkeypatch, kind, blocked):
    fixture = make_original_object_fixture(tmp_path, kind, blocked=blocked)
    repo = fixture["repo"]
    with git_environment(monkeypatch, repo.env):
        stats = guard._blank_history_stats()
        findings = guard.scan_history(repo.root, set(),
                                      guard.Policy.of([guard.Token(fixture["token"], "secret")]), stats)
    assert stats["commits"] >= 1
    if blocked:
        assert any(value == fixture["expected"] and severity == "BLOCK"
                   for _, _, value, severity in findings), findings
    else:
        assert findings == []


def test_source10_custom_replacement_namespace_keeps_original(tmp_path, monkeypatch):
    fixture = make_original_object_fixture(tmp_path, "commit-body", custom_base=True)
    repo = fixture["repo"]
    with git_environment(monkeypatch, repo.env):
        findings = guard.scan_history(repo.root, set(),
                                      guard.Policy.of([guard.Token(fixture["token"], "secret")]))
    assert any(value == fixture["token"] and severity == "BLOCK"
               for _, _, value, severity in findings), findings


@pytest.mark.parametrize("kind", ["commit-body", "message", "author", "committer", "ancestor"])
def test_source10_range_uses_original_history(tmp_path, monkeypatch, kind):
    fixture = make_original_object_fixture(tmp_path, kind)
    repo = fixture["repo"]
    with git_environment(monkeypatch, repo.env):
        findings = guard.scan_range(repo.root, set(),
                                    guard.Policy.of([guard.Token(fixture["token"], "secret")]),
                                    "refs/heads/main")
    assert any(value == fixture["expected"] and severity == "BLOCK"
               for _, _, value, severity in findings), findings


@pytest.mark.parametrize("linked", [False, True])
@pytest.mark.parametrize("blocked", [False, True])
def test_source10_scanner_preserves_selected_index(tmp_path, monkeypatch, linked, blocked):
    fixture = make_selected_index_fixture(tmp_path, linked=linked, blocked=blocked)
    repo = fixture["repo"]
    policy = guard.Policy.of([guard.Token(fixture["token"], "secret")])
    with git_environment(monkeypatch, repo.env):
        selected = guard.scan_staged(repo.root, set(), policy)
    default_env = dict(repo.env)
    default_env.pop("GIT_INDEX_FILE")
    with git_environment(monkeypatch, default_env):
        default = guard.scan_staged(repo.root, set(), policy)
    assert any(value == fixture["token"] and severity == "BLOCK"
               for _, _, value, severity in selected) is blocked
    assert default == []


def test_source10_companion_preserves_global_ignore(tmp_path, monkeypatch, capsys):
    from make_fixtures import configure_companion_context_fixture
    fixture = configure_companion_context_fixture(
        make_companion_context_fixture(tmp_path, guard._utcnow()), "global-ignore")
    private = fixture["repos"]["private"]
    with git_environment(monkeypatch, private.env):
        result = db.check_companion(str(private.root), 5, str(fixture["receipt"]))
    output = capsys.readouterr()
    assert result == 0, output.out + output.err
    assert "PRIVATE verified" in output.out
    assert "LOOSE files wearing a run shape:    0" in output.out


@pytest.mark.parametrize("authorization,expected", [
    ("missing", 2), ("global", 0), ("reset", 2), ("command", 0),
])
def test_source10_companion_preserves_existing_ownership_policy(
        tmp_path, monkeypatch, capsys, authorization, expected):
    from make_fixtures import configure_companion_context_fixture
    fixture = configure_companion_context_fixture(
        make_companion_context_fixture(tmp_path, guard._utcnow()), authorization)
    private = fixture["repos"]["private"]
    with git_environment(monkeypatch, private.env):
        result = db.check_companion(str(private.root), 5, str(fixture["receipt"]))
    output = capsys.readouterr()
    assert result == expected, output.out + output.err
    assert ("PRIVATE verified" in output.out) is (expected == 0)


def test_source10_companion_does_not_use_invoking_index(tmp_path, monkeypatch, capsys):
    from make_fixtures import configure_companion_context_fixture
    fixture = configure_companion_context_fixture(
        make_companion_context_fixture(tmp_path, guard._utcnow()), "distinct-index")
    invoker, private = fixture["repos"]["invoker"], fixture["repos"]["private"]
    env = dict(invoker.env, GIT_DIR=invoker.git("rev-parse", "--absolute-git-dir"),
               GIT_WORK_TREE=str(invoker.root), GIT_INDEX_FILE=invoker.copy_index("different"))
    with git_environment(monkeypatch, env):
        result = db.check_companion(str(private.root), 5, str(fixture["receipt"]))
    output = capsys.readouterr()
    assert result == 1, output.out + output.err
    assert "PRIVATE verified" in output.out
    assert "LOOSE files wearing a run shape:    1" in output.out
    assert "archive/invoker-only.jsonl" in output.err


@contextmanager
def repository_marker_view(monkeypatch, layout, failed_marker=None, error_type=None):
    """Model portable predicate/stat failures; this is not a native ACL test."""
    import genericpath
    import datadir
    native_stat = os.stat
    absent = {os.path.normcase(os.path.abspath(path)) for path in layout["absent_parents"]}
    failed = (os.path.normcase(os.path.abspath(failed_marker))
              if failed_marker is not None else None)

    def controlled_stat(path, *args, **kwargs):
        if not isinstance(path, int):
            normalized = os.path.normcase(os.path.abspath(path))
            if normalized == failed:
                raise error_type("synthetic repository-marker metadata failure")
            if normalized in absent:
                raise FileNotFoundError("synthetic exported ancestor")
        return native_stat(path, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(datadir, "__file__", str(layout["module"]))
        context.setattr(os.path, "isdir", genericpath.isdir)
        context.setattr(os.path, "isfile", genericpath.isfile)
        context.setattr(os, "stat", controlled_stat)
        yield datadir


@pytest.mark.parametrize("kind", ["directory", "gitfile", "linked", "exported"])
@pytest.mark.parametrize("inside", [False, True])
def test_source11_repository_marker_controls(tmp_path, monkeypatch, kind, inside):
    from make_fixtures import make_repository_marker_fixture
    layout = make_repository_marker_fixture(tmp_path, kind)
    target = layout["inside" if inside else "outside"]
    monkeypatch.setenv("SYNTHETIC_MARKER_DATA_DIR", str(target))
    with repository_marker_view(monkeypatch, layout) as datadir:
        assert datadir._own_repo_root() == (None if kind == "exported" else str(layout["tool"]))
        if inside and kind != "exported":
            with pytest.raises(datadir.DataDirInsideOwnRepo):
                datadir.assert_outside_own_repo(target, "synthetic-marker")
            with pytest.raises(datadir.DataDirInsideOwnRepo):
                datadir.resolve_data_dir("synthetic-marker")
        else:
            datadir.assert_outside_own_repo(target, "synthetic-marker")
            assert datadir.resolve_data_dir("synthetic-marker") == target


@pytest.mark.parametrize("kind,marker", [
    ("directory", "git"), ("gitfile", "git"), ("linked", "git"), ("linked", "common"),
])
@pytest.mark.parametrize("error_type", [PermissionError, OSError])
@pytest.mark.parametrize("inside", [False, True])
def test_source11_repository_marker_errors_refuse_output(
        tmp_path, monkeypatch, kind, marker, error_type, inside):
    from make_fixtures import make_repository_marker_fixture
    layout = make_repository_marker_fixture(tmp_path, kind)
    target = layout["inside" if inside else "outside"]
    monkeypatch.setenv("SYNTHETIC_MARKER_DATA_DIR", str(target))
    with repository_marker_view(monkeypatch, layout, layout[marker], error_type) as datadir:
        for operation in (
                datadir._own_repo_root,
                lambda: datadir.assert_outside_own_repo(target, "synthetic-marker"),
                lambda: datadir.resolve_data_dir("synthetic-marker")):
            with pytest.raises(datadir.DataDirResolutionError) as raised:
                operation()
            assert type(raised.value.__cause__) is error_type
            assert "output is not authorized" in str(raised.value)


@pytest.mark.parametrize("outcome", ["pass", "fail", "missing"])
def test_source11_ci_git_context_step_executes_and_propagates(tmp_path, outcome):
    from pathlib import Path
    import shutil
    import subprocess
    from make_fixtures import write_git_context_ci_suite
    action = Path(__file__).parent.parent / "ci/pii-guard/action.yml"
    blocks = action.read_text(encoding="utf-8").split("    - name:")
    matches = [block for block in blocks if "test_git_context.py" in block]
    assert len(matches) == 1, "CI must unconditionally run the Git context suite"
    block = matches[0]
    assert "\n      if:" not in block
    body = block.split("      run: |\n", 1)[1]
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("        "):
            break
        lines.append(line[8:])
    consumer = tmp_path / "consumer"
    write_git_context_ci_suite(consumer, outcome)
    action_path = consumer / "guards/ci/pii-guard"
    action_path.mkdir(parents=True)
    if os.name == "nt":
        bash = Path(shutil.which("git")).parent.parent / "bin/bash.exe"
    else:
        bash = Path(shutil.which("bash"))
    assert bash.is_file(), "native Bash required to validate the CI run block"
    env = dict(os.environ, GITHUB_ACTION_PATH=action_path.as_posix())
    result = subprocess.run([str(bash), "--noprofile", "--norc", "-e", "-c", "\n".join(lines)],
                            cwd=consumer, env=env, capture_output=True, text=True)
    assert (result.returncode == 0) is (outcome == "pass"), result.stdout + result.stderr
    if outcome == "missing":
        assert "::error::" in result.stdout + result.stderr
    else:
        assert ("1 passed" if outcome == "pass" else "1 failed") in result.stdout + result.stderr


def test_source11_standalone_ci_uses_shared_git_context_step():
    from pathlib import Path
    root = Path(__file__).parent.parent
    workflow = (root / ".github/workflows/pii-guard.yml").read_text(encoding="utf-8")
    assert "uses: ./ci/pii-guard" in workflow
    action = (root / "ci/pii-guard/action.yml").read_text(encoding="utf-8")
    assert 'python -m pytest "$GITHUB_ACTION_PATH/../../tools/test_git_context.py" -q' in action


@pytest.mark.parametrize("hook_name", ["pre-commit", "pre-push"])
@pytest.mark.parametrize("selected_tool", ["pii_guard.py", "data_boundary.py"])
@pytest.mark.parametrize("state", ["empty", "pass", "fail"])
def test_source12_mandatory_hook_tools_must_be_nonempty(
        tmp_path, hook_name, selected_tool, state):
    from pathlib import Path
    import shutil
    import subprocess
    from make_fixtures import make_required_hook_tool_fixture

    fixture = make_required_hook_tool_fixture(
        tmp_path, Path(__file__).parent.parent, hook_name, selected_tool, state)
    bash = (Path(shutil.which("git")).parent.parent / "bin/bash.exe"
            if os.name == "nt" else Path(shutil.which("bash")))
    result = subprocess.run(
        [str(bash), "--noprofile", "--norc", str(fixture["hook"])],
        cwd=fixture["repo"].root, env=fixture["repo"].env,
        capture_output=True, text=True, encoding="utf-8", input="")
    output = result.stdout + result.stderr
    assert result.returncode == (0 if state == "pass" else 1), output
    calls = (fixture["receipt"].read_text(encoding="utf-8").splitlines()
             if fixture["receipt"].exists() else [])
    if state == "empty":
        assert selected_tool in output and "empty" in output.lower(), output
        assert calls == []
    else:
        expected = ["pii_guard.py", "data_boundary.py"]
        if state == "fail" and selected_tool == "pii_guard.py":
            expected = ["pii_guard.py"]
        assert calls == expected
        if state == "fail":
            assert "BLOCKED by " + selected_tool[:-3] in output


@contextmanager
def source13_policy_fault(monkeypatch, target, site, error_type):
    """Model one generated leaf's metadata or read failure on every platform."""
    import builtins
    import genericpath

    normalize = lambda path: os.path.normcase(os.path.abspath(os.fspath(path)))
    selected = normalize(target)
    original_stat, original_open = os.stat, builtins.open

    def broken_stat(path, *args, **kwargs):
        if not isinstance(path, int) and normalize(path) == selected:
            raise error_type("synthetic policy metadata failure")
        return original_stat(path, *args, **kwargs)

    def broken_open(path, *args, **kwargs):
        if not isinstance(path, int) and normalize(path) == selected:
            raise error_type("synthetic policy read failure")
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as context:
        if site == "stat":
            context.setattr(guard.os.path, "exists", genericpath.exists)
            context.setattr(guard.os, "stat", broken_stat)
        else:
            context.setattr(builtins, "open", broken_open)
        yield


def source13_policy_setup(tmp_path, monkeypatch, layer, present=True):
    from make_fixtures import make_policy_io_fixture

    fixture = make_policy_io_fixture(
        tmp_path, layer, present, guard.CANARY_TOKEN, guard._utcnow())
    monkeypatch.setenv("PII_DENYLIST", str(fixture["denylist"]))
    monkeypatch.setenv("HOME", str(fixture["home"]))
    monkeypatch.setenv("USERPROFILE", str(fixture["home"]))
    monkeypatch.setattr(guard, "_repo_slug",
                        lambda root: ("example-owner/other-tool", "other-tool"))
    return fixture


def source13_load_layer(fixture, layer):
    if layer == "denylist":
        return guard.load_policy(None)
    return guard._load_visibility(str(fixture["visibility"]), [])


@pytest.mark.parametrize("layer", ["denylist", "visibility"])
@pytest.mark.parametrize("present", [False, True])
def test_source13_policy_healthy_and_absent_controls(tmp_path, monkeypatch, layer, present):
    fixture = source13_policy_setup(tmp_path, monkeypatch, layer, present)
    loaded = source13_load_layer(fixture, layer)
    if layer == "denylist":
        assert loaded.denylist_present is present
        tokens, text = loaded, fixture["token"]
    else:
        assert (loaded is not None) is present
        tokens = guard.Policy.of(guard.load_cross_repo_tokens(
            str(fixture["repo"]), str(fixture["visibility"])))
        text = fixture["cross_token"]
    findings = []
    guard.scan_text(text, "notes.md", set(), tokens, findings)
    assert any(value == text and severity == "BLOCK"
               for _where, _label, value, severity in findings) is present


@pytest.mark.parametrize("layer", ["denylist", "visibility"])
@pytest.mark.parametrize("error_type", [PermissionError, OSError])
@pytest.mark.parametrize("site", ["stat", "read"])
def test_source13_policy_io_errors_are_not_absence(
        tmp_path, monkeypatch, layer, error_type, site):
    fixture = source13_policy_setup(tmp_path, monkeypatch, layer)
    with source13_policy_fault(monkeypatch, fixture["target"], site, error_type):
        with pytest.raises(guard.PolicyError):
            source13_load_layer(fixture, layer)


@pytest.mark.parametrize("layer", ["denylist", "visibility"])
@pytest.mark.parametrize("error_type", [PermissionError, OSError])
@pytest.mark.parametrize("site", ["stat", "read"])
def test_source13_policy_io_errors_exit_nonzero(
        tmp_path, monkeypatch, layer, error_type, site):
    import sys

    fixture = source13_policy_setup(tmp_path, monkeypatch, layer)
    monkeypatch.setattr(guard, "_repo_root", lambda path: str(fixture["repo"]))
    monkeypatch.setattr(guard, "load_repo_allow", lambda root: set())
    monkeypatch.setattr(sys, "argv", [guard.__file__, "--repo", str(fixture["repo"])])
    scanned = []

    def no_content_scan(root, allow, policy, stats):
        scanned.append(root)
        return []

    monkeypatch.setattr(guard, "tracked_files", lambda root: [])
    monkeypatch.setattr(guard, "scan_tree", no_content_scan)
    with source13_policy_fault(monkeypatch, fixture["target"], site, error_type):
        status = guard.cli()
    assert status == 2
    assert not scanned, "An unreadable policy must stop the CLI before content scanning"


def source13_batch_setup(monkeypatch, variant):
    from make_fixtures import make_object_batch_fixture

    fixture = make_object_batch_fixture(variant, guard.MAX_BLOB_BYTES)
    requests = []

    def run(arguments, root):
        key = tuple(arguments)
        assert key in fixture["responses"], key
        requests.append(key)
        return fixture["responses"][key]

    def stdin(arguments, root, payload):
        key = tuple(arguments)
        requests.append(key)
        if key == ("git", "cat-file", "--batch-check", "--buffer"):
            assert payload.splitlines() == fixture["objects"]
            return fixture["metadata"]
        assert key == ("git", "cat-file", "--batch", "--buffer"), key
        return fixture["batch"](payload.splitlines())

    policy = guard.Policy.of([guard.Token(fixture["token"], "secret")])
    monkeypatch.setattr(guard, "_run", run)
    monkeypatch.setattr(guard, "_run_stdin", stdin)
    monkeypatch.setattr(guard, "_repo_root", lambda path: path)
    monkeypatch.setattr(guard, "load_repo_allow", lambda root: set())
    monkeypatch.setattr(guard, "load_policy", lambda root: policy)
    monkeypatch.setattr(guard, "_repo_slug", lambda root: ("", ""))
    return fixture, policy, requests


from make_fixtures import object_batch_faults


@pytest.mark.parametrize("variant", object_batch_faults())
def test_source13_batch_protocol_rejects_incomplete_objects(
        tmp_path, monkeypatch, capsys, variant):
    import sys

    fixture, _policy, requests = source13_batch_setup(monkeypatch, variant)
    monkeypatch.setattr(sys, "argv", [guard.__file__, "--repo", str(tmp_path), "--history"])
    assert guard.cli() == 2
    output = capsys.readouterr()
    assert "SCAN FAILED" in output.err
    assert "pii_guard: clean" not in output.out
    assert ("git", "cat-file", "--batch-check", "--buffer") in requests


@pytest.mark.parametrize("variant", ["healthy", "binary", "oversize"])
def test_source13_batch_protocol_preserves_scan_policy(tmp_path, monkeypatch, capsys, variant):
    import sys

    fixture, policy, _requests = source13_batch_setup(monkeypatch, variant)
    stats = guard._blank_history_stats()
    if variant == "oversize":
        with pytest.raises(guard.ScanIncompleteError, match="history blob"):
            guard.scan_history(str(tmp_path), set(), policy, stats)
        findings = []
    else:
        findings = guard.scan_history(str(tmp_path), set(), policy, stats)
    assert stats["blobs_total"] == 2
    assert stats["blobs_scanned"] == (2 if variant == "healthy" else 1)
    assert stats["blobs_binary"] == int(variant == "binary")
    assert len(stats["blobs_oversize"]) == int(variant == "oversize")
    assert any(value == fixture["token"] and severity == "BLOCK"
               for _where, _label, value, severity in findings) is (variant == "healthy")
    monkeypatch.setattr(sys, "argv", [guard.__file__, "--repo", str(tmp_path), "--history"])
    assert guard.cli() == {"healthy": 1, "binary": 0, "oversize": 2}[variant]
    output = capsys.readouterr()
    assert "SCAN FAILED" not in output.err
    if variant == "oversize":
        assert "NOT examined" in output.err
        assert "SCAN INCOMPLETE" in output.err
        assert "pii_guard: clean" not in output.out


@pytest.mark.parametrize("variant", ["healthy", "missing", "extra", "bad-oid", "bad-type"])
def test_source13_reference_batch_population(tmp_path, monkeypatch, variant):
    from make_fixtures import make_reference_batch_fixture

    fixture = make_reference_batch_fixture(variant)
    monkeypatch.setattr(guard, "_run", lambda args, root: fixture["responses"][tuple(args)])

    def stdin(arguments, root, payload):
        assert arguments == ["git", "cat-file", "--batch-check", "--buffer"]
        assert payload.splitlines() == [ref + "^{}" for ref in fixture["refs"]]
        return fixture["targets"]

    monkeypatch.setattr(guard, "_run_stdin", stdin)
    stats = guard._blank_history_stats()
    if variant == "healthy":
        guard._scan_object_graph(str(tmp_path), set(), guard.Policy.of([]), [],
                                 ["--all"], stats, "<blob> ")
        assert stats["trees_scanned"] == 1
    else:
        with pytest.raises(guard.GitError):
            guard._scan_object_graph(str(tmp_path), set(), guard.Policy.of([]), [],
                                     ["--all"], stats, "<blob> ")
