"""Dispatch verified upstream updates and advance consumer gitlinks."""
import argparse
import base64
import configparser
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


# ------------------------------------------------- spawning processes (identical in every kit file)
# A console program started by a process that has NO console (pythonw, a scheduled task, a service)
# is handed a brand-new console, and Windows shows it as a window. Measured 2026-10-05: a daemon
# under pythonw ran a companion proof on every log line, each proof ran about 19 git commands, and
# the machine took roughly 9,000 terminal windows in eight hours. So every spawn in this kit goes
# through _no_window(), and tools/test_no_console_window.py fails on any spawn that does not.
#
# The flag is added ONLY when this process has no console. A process that has one already shares it
# with its children and never opens a window; giving those children CREATE_NO_WINDOW would instead
# move their unredirected output and terminal prompts into a hidden console, where a hook's findings
# would vanish (measured: an unredirected child's output is simply lost). DETACHED_PROCESS and
# CREATE_NEW_CONSOLE are refused outright: the first makes Windows ignore CREATE_NO_WINDOW and
# leaves a console-less child whose own children open windows again, and the second opens a window
# by definition.
#
# Each file carries its own copy because consumers load these files one at a time by path; a
# shared sibling module would be a new way for a single copied file to fail. That test holds
# every copy identical, so the copies cannot drift.
def _console_less_windows():
    """True on Windows when this process has no console, so a console child would get a window.

    A hidden console counts as a console: children of a CREATE_NO_WINDOW child share it unseen.
    If the console cannot be queried the answer is True, the side on which no window can open.
    """
    import sys
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return not ctypes.WinDLL("kernel32").GetConsoleCP()
    except (ImportError, AttributeError, OSError):
        return True


def _no_window(**kwargs):
    """Return subprocess keywords that can never open a console window.

    Merges into any creationflags the caller passes: subprocess.run(args, **_no_window(cwd=root)).
    """
    flags = kwargs.get("creationflags", 0) or 0
    if flags & 0x00000018:              # DETACHED_PROCESS | CREATE_NEW_CONSOLE
        raise ValueError("DETACHED_PROCESS and CREATE_NEW_CONSOLE can open console windows")
    if _console_less_windows():
        kwargs["creationflags"] = flags | 0x08000000      # CREATE_NO_WINDOW
    return kwargs


# Built-in kits: always followed on main through their own gate workflow. A consumer declaration
# cannot replace or shadow these settings.
SOURCES = {
    "DaizeDong/fleet-guards": "pii-guard.yml",
    "DaizeDong/fleet-style": "style.yml",
}
BUILTIN_BRANCH = "main"
MAX_DECLARED_SOURCES = 32

_REPOSITORY = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}")
_WORKFLOW = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\.ya?ml")
_BRANCH_PART = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"
_BRANCH = re.compile(_BRANCH_PART + r"(?:/" + _BRANCH_PART + r")*")


def valid_repository(name):
    return (isinstance(name, str) and bool(_REPOSITORY.fullmatch(name))
            and name.split("/")[1] not in (".", "..") and not name.lower().endswith(".git"))


def valid_workflow(name):
    return isinstance(name, str) and bool(_WORKFLOW.fullmatch(name))


def valid_branch(name):
    """A conservative subset of git-check-ref-format for a branch name."""
    return (isinstance(name, str) and 0 < len(name) <= 200 and bool(_BRANCH.fullmatch(name))
            and ".." not in name and name != "HEAD" and not name.endswith(".")
            and not any(part.endswith(".lock") for part in name.split("/")))


def builtin_name(source):
    """Canonical built-in name for a case-insensitive match, else None."""
    for name in SOURCES:
        if isinstance(source, str) and source.lower() == name.lower():
            return name
    return None


def builtin_spec(name):
    return {"workflow": SOURCES[name], "branch": BUILTIN_BRANCH}


def _reject_duplicate_keys(pairs):
    seen = set()
    for key, _value in pairs:
        folded = key.lower() if isinstance(key, str) else key
        if folded in seen:
            raise ValueError("Duplicate upstream declaration")
        seen.add(folded)
    return dict(pairs)


def parse_sources(value):
    """Validate consumer-declared upstreams: {"owner/repo": {"workflow": "x.yml", "branch": "b"}}.

    Returns only the non-built-in declarations. Restating a built-in kit with its own settings is
    accepted and ignored; declaring it with any other workflow or branch is an error.
    """
    if value is None or not value.strip():
        return {}
    try:
        data = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError:
        raise ValueError("FLEET_SYNC_SOURCES is not valid JSON") from None
    if not isinstance(data, dict):
        raise ValueError("FLEET_SYNC_SOURCES must be a JSON object")
    if len(data) > MAX_DECLARED_SOURCES:
        raise ValueError("Too many declared upstreams")
    declared = {}
    for name, spec in data.items():
        if not valid_repository(name):
            raise ValueError("Invalid declared upstream repository")
        if not isinstance(spec, dict) or set(spec) != {"workflow", "branch"}:
            raise ValueError("A declared upstream needs exactly the fields workflow and branch")
        if not valid_workflow(spec["workflow"]):
            raise ValueError("Invalid declared upstream workflow file name")
        if not valid_branch(spec["branch"]):
            raise ValueError("Invalid declared upstream branch")
        builtin = builtin_name(name)
        if builtin:
            if spec != builtin_spec(builtin):
                raise ValueError("A built-in kit cannot be redeclared with other settings")
            continue
        declared[name] = {"workflow": spec["workflow"], "branch": spec["branch"]}
    return declared


def resolve_source(source, sources=None):
    """Return (canonical name, spec) for a built-in or declared upstream; reject anything else."""
    builtin = builtin_name(source)
    if builtin:
        return builtin, builtin_spec(builtin)
    for name, spec in (sources or {}).items():
        if isinstance(source, str) and source.lower() == name.lower():
            return name, spec
    raise ValueError("Unknown upstream repository")


def api(path, token, *, body=None):
    """Never include API response bodies, credentials, or target names in errors."""
    request = Request(
        "https://api.github.com/" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=45) as response:
            data = response.read()
            return json.loads(data) if data else None
    except HTTPError as exc:
        raise RuntimeError("GitHub API returned HTTP %s" % exc.code) from None


def source_from_url(url, sources=None):
    for source in (*SOURCES, *(sources or {})):
        if url.lower().removesuffix(".git") in (
            "https://github.com/" + source.lower(),
            "git@github.com:" + source.lower(),
        ):
            return source
    return None


def validate_path(path):
    if not re.fullmatch(r"[A-Za-z0-9_.\-/]+", path) or path.startswith("/"):
        raise ValueError("Unsafe submodule path")
    if any(part in ("", ".", "..", ".git") for part in path.split("/")):
        raise ValueError("Unsafe submodule path")
    return str(PurePosixPath(path))


def select_modules(contents, source, sources=None):
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(contents)
    selected = []
    for section in config.sections():
        values = config[section]
        upstream = source_from_url(values.get("url", ""), sources)
        if upstream and source in ("all", upstream):
            expected = resolve_source(upstream, sources)[1]["branch"]
            # A missing branch means main, so an upstream tracked on another branch must say so.
            branch = values.get("branch", "main")
            if branch != expected:
                raise ValueError("A submodule's .gitmodules branch does not match its upstream's "
                                 "declared branch (built-in kits require main)")
            selected.append({"path": validate_path(values["path"]),
                             "source": upstream, "branch": branch})
    return selected


def parse_targets(value):
    targets = json.loads(value)
    if not isinstance(targets, list) or not targets:
        raise ValueError("FLEET_SYNC_TARGETS must contain subscriptions")
    seen = set()
    for target in targets:
        if not isinstance(target, dict) or set(target) != {"repository", "credential"}:
            raise ValueError("Invalid subscription fields")
        repository = target["repository"]
        credential = target["credential"]
        if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Invalid subscription repository")
        if not isinstance(credential, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", credential):
            raise ValueError("Invalid credential key")
        if repository.lower() in seen:
            raise ValueError("Duplicate subscription")
        seen.add(repository.lower())
    return targets


def successful_run(response, sha):
    for run in response["workflow_runs"]:
        if run["head_sha"] == sha and run["event"] == "push":
            return run["status"] == "completed" and run["conclusion"] == "success"
    return False


def verified_tip(source, expected_sha, token, spec=None):
    """Return the declared branch tip if its latest push run of the gate workflow succeeded.

    spec defaults to the built-in kit's settings; a built-in kit never accepts other settings.
    """
    builtin = source in SOURCES
    if spec is None:
        if not builtin:
            raise ValueError("Unknown upstream repository")
        spec = builtin_spec(source)
    elif builtin and spec != builtin_spec(source):
        raise ValueError("A built-in kit cannot be redeclared with other settings")
    if (not valid_repository(source) or not isinstance(spec, dict)
            or set(spec) != {"workflow", "branch"}
            or not valid_workflow(spec["workflow"]) or not valid_branch(spec["branch"])):
        raise ValueError("Invalid upstream declaration")
    if expected_sha and not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ValueError("Invalid upstream commit")
    branch = spec["branch"]
    tip = api("repos/%s/commits/%s" % (source, quote(branch, safe="/")), token)["sha"]
    if expected_sha and tip != expected_sha:
        print("Obsolete notification: a newer upstream commit exists.")
        return None
    query = urlencode({"head_sha": tip, "branch": branch, "event": "push", "per_page": 100})
    runs = api("repos/%s/actions/workflows/%s/runs?%s" % (source, spec["workflow"], query), token)
    if not successful_run(runs, tip):
        raise RuntimeError("The latest upstream commit has not passed its required workflow")
    return tip


def dispatch_targets(targets, credentials, source, sha):
    if not isinstance(credentials, dict) or any(not isinstance(credentials.get(t["credential"]), str)
                                              or not credentials[t["credential"]] for t in targets):
        raise ValueError("A subscription credential is missing")

    def send(target):
        try:
            api("repos/%s/dispatches" % target["repository"], credentials[target["credential"]],
                body={"event_type": "fleet-submodule-update", "client_payload": {
                    "source_repository": source, "source_sha": sha}})
            return True
        except Exception:
            # The public upstream log must not identify private subscribers.
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(send, targets))
    failed = sum(not result for result in outcomes)
    print("Notifications accepted: %s; failed: %s" % (len(outcomes) - failed, failed))
    if failed:
        raise RuntimeError("%s subscription notifications failed; inspect credentials and access" % failed)


def git(*args, capture=True, env=None):
    result = subprocess.run(["git", *args], check=True, text=True,
                            stdout=subprocess.PIPE if capture else None, **_no_window(env=env))
    return result.stdout.strip() if capture else ""


def github_auth_env(token, base=None):
    """Environment that authenticates one git process to github.com over HTTPS.

    The credential travels only in GIT_CONFIG_* variables of that child process: never in argv
    (visible to process listings and to CalledProcessError text), never in a URL, never in a config
    file that outlives the command. The first entry resets any persisted extra header, such as the
    one actions/checkout writes into each submodule's config, so the request carries exactly one
    Authorization header. SSH-form github.com URLs are rewritten to HTTPS for the same process.
    """
    if not isinstance(token, str) or not token.strip():
        raise RuntimeError("An upstream fetch credential is required")
    env = dict(os.environ if base is None else base)
    try:
        start = int(env.get("GIT_CONFIG_COUNT", "0") or "0")
    except ValueError:
        raise RuntimeError("Invalid GIT_CONFIG_COUNT in the environment") from None
    if start < 0:
        raise RuntimeError("Invalid GIT_CONFIG_COUNT in the environment")
    credential = base64.b64encode(("x-access-token:" + token).encode()).decode()
    entries = (("http.https://github.com/.extraheader", ""),
               ("http.https://github.com/.extraheader", "AUTHORIZATION: basic " + credential),
               ("url.https://github.com/.insteadOf", "git@github.com:"))
    for offset, (key, value) in enumerate(entries):
        env["GIT_CONFIG_KEY_%d" % (start + offset)] = key
        env["GIT_CONFIG_VALUE_%d" % (start + offset)] = value
    env["GIT_CONFIG_COUNT"] = str(start + len(entries))
    return env


def require_hooks():
    """Git ignores non-executable hooks, so existence alone cannot arm a gate."""
    for name in ("pre-commit", "pre-push"):
        hook = Path(".githooks", name)
        entry = git("ls-files", "--stage", "--", hook.as_posix()).split()
        if (not hook.is_file() or not os.access(hook, os.X_OK)
                or len(entry) < 4 or entry[0] != "100755"):
            raise RuntimeError("Missing or non-executable .githooks shim; complete fleet-guards installation")


def load_guard_tool(guard, filename):
    """Load policy from the selected consumer kit, without ambient import fallback."""
    name = "_fleet_sync_" + Path(filename).stem
    spec = importlib.util.spec_from_file_location(name, guard / "tools" / filename)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def visibility_receipt_path(root, publication):
    """Reject worktree destinations and filesystem aliases before writing metadata."""
    path = Path(os.path.expanduser("~/.pii-guard/visibility.json"))
    if (not path.is_absolute() or ".." in path.parts
            or path.resolve().is_relative_to(Path(root).resolve())
            or not publication.unaliased_absolute(path.parent.parent)):
        raise RuntimeError("Visibility receipt must be external and unaliased")
    for node in (path.parent, path):
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        if (not publication.unaliased_absolute(node)
                or node == path.parent and not stat.S_ISDIR(info.st_mode)
                or node == path and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
            raise RuntimeError("Visibility receipt must be an unaliased regular file")
    return path


def refresh_visibility_receipt(guard, root, token):
    """Initialize hook metadata only for an explicitly opted-in POSIX Actions job."""
    if os.name != "posix":
        raise RuntimeError("Hosted visibility refresh requires POSIX private permissions")
    if os.environ.get("GITHUB_ACTIONS") != "true" or not isinstance(token, str) or not token.strip():
        raise RuntimeError("Visibility refresh requires an Actions job and a metadata credential")
    publication = load_guard_tool(guard, "publication_guard.py")
    boundary = load_guard_tool(guard, "data_boundary.py")
    path = visibility_receipt_path(root, publication)
    context = boundary._companion_git_context(root)
    repositories = set()
    for urls in publication.configured_urls(boundary, context):
        if not urls:
            raise RuntimeError("Visibility refresh requires configured publication routes")
        for url in urls:
            key, _host = boundary._github_publication_route(url)
            if key is None:
                raise RuntimeError("Publication destination is UNKNOWN")
            repositories.add("%s/%s" % key)
    receipt = {}
    for repository in sorted(repositories):
        try:
            state = publication.github_visibility(repository, token)
        except (OSError, ValueError, TypeError):
            raise RuntimeError("Authoritative repository visibility is unavailable") from None
        if state not in {"PRIVATE", "PUBLIC"}:
            raise RuntimeError("Authoritative repository visibility is UNKNOWN")
        receipt[repository] = state
    receipt["_refreshed"] = load_guard_tool(guard, "pii_guard.py")._utcnow()
    path.parent.mkdir(mode=0o700, exist_ok=True)
    visibility_receipt_path(root, publication)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = ".visibility-" + secrets.token_hex(16) + ".tmp"
    created = False
    try:
        os.fchmod(directory, 0o700)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            os.fchmod(output.fileno(), 0o600)
            json.dump(receipt, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        visibility_receipt_path(root, publication)
        if not os.path.samestat(os.fstat(directory), path.parent.stat()):
            raise RuntimeError("Visibility receipt directory changed during refresh")
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        created = False
    finally:
        try:
            if created:
                os.unlink(temporary, dir_fd=directory)
        finally:
            os.close(directory)
    print("Visibility metadata refreshed for %s publication destinations." % len(repositories))


def update_consumer(source, expected_sha, token, *, refresh_visibility=False, sources=None):
    sources = sources or {}
    if source != "all":
        # Neither built-in nor declared: refused, never widened into a full reconciliation.
        source = resolve_source(source, sources)[0]
    if git("status", "--porcelain"):
        raise RuntimeError("Consumer checkout is not clean")
    modules = select_modules(Path(".gitmodules").read_text(encoding="utf-8"), source, sources)
    if not modules:
        raise RuntimeError("No matching upstream submodule is installed")
    changed = []
    for module in modules:
        spec = resolve_source(module["source"], sources)[1]
        sha = verified_tip(module["source"], expected_sha, token, spec)
        if not sha:
            continue
        path = module["path"]
        entry = git("ls-files", "--stage", "--", path).split()
        if len(entry) < 4 or entry[0] != "160000":
            raise RuntimeError("Selected path is not a tracked gitlink")
        old = entry[1]
        if old == sha:
            continue
        # Fetch only the declared upstream branch, never an arbitrary payload URL. The credential
        # reaches git through this process's environment only, so private upstreams work too.
        auth = github_auth_env(token)
        git("submodule", "update", "--init", "--", path, capture=False, env=auth)
        git("-C", path, "fetch", "https://github.com/%s.git" % module["source"],
            "refs/heads/" + spec["branch"], capture=False, env=auth)
        git("-C", path, "merge-base", "--is-ancestor", old, sha)
        git("-C", path, "checkout", "--detach", sha, capture=False)
        git("add", "--", path)
        changed.append(path)
    staged = git("diff", "--cached", "--name-only").splitlines()
    if sorted(staged) != sorted(changed):
        raise RuntimeError("Unexpected staged files; refusing to commit")
    if changed:
        guard_modules = select_modules(Path(".gitmodules").read_text(encoding="utf-8"),
                                       "DaizeDong/fleet-guards", sources)
        if len(guard_modules) != 1:
            raise RuntimeError("A single fleet-guards submodule is required for the commit gate")
        guard = Path(guard_modules[0]["path"])
        for tool in ("publication_guard.py", "data_boundary.py", "pii_guard.py"):
            path = guard / "tools" / tool
            if not path.is_file() or not path.stat().st_size:
                raise RuntimeError("Missing or empty publication policy component: " + tool)
        root = Path(git("rev-parse", "--show-toplevel"))
        if refresh_visibility:
            refresh_visibility_receipt(guard, root, token)
        subprocess.run([sys.executable, str(guard / "tools/publication_guard.py"),
                        "pre-commit", "--repo", str(root)], check=True, **_no_window())
        # Arm existing fail-closed shims. A missing shim must be repaired during enrollment.
        require_hooks()
        git("config", "core.hooksPath", ".githooks")
        bot_name = "github-actions[bot]"
        bot_email = "41898282+github-actions[bot]@users.noreply.github.com"
        for key, value in (("user.name", bot_name), ("user.email", bot_email),
                           ("guard.expectedName", bot_name), ("guard.expectedEmail", bot_email)):
            git("config", key, value)
        git("commit", "-m", "chore: sync verified fleet submodules", capture=False)
        branch = os.environ["CONSUMER_BRANCH"]
        # A concurrent user push is rejected normally; never force-push or overwrite it.
        git("push", "origin", "HEAD:refs/heads/" + branch, capture=False)
    print("Updated submodules: %s" % len(changed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("dispatch", "update"))
    parser.add_argument("--refresh-visibility", action="store_true",
                        help="refresh hook metadata for a changed update in a POSIX Actions job")
    args = parser.parse_args()
    if args.refresh_visibility and args.command != "update":
        parser.error("--refresh-visibility is only valid for update")
    source = os.environ.get("SOURCE_REPOSITORY", "")
    expected_sha = os.environ.get("SOURCE_SHA", "")
    if args.command == "dispatch":
        source, spec = dispatch_source(source, os.environ.get("FLEET_SYNC_UPSTREAM_WORKFLOW", ""),
                                       os.environ.get("FLEET_SYNC_UPSTREAM_BRANCH", ""))
        token = os.environ["GH_TOKEN"]
        sha = verified_tip(source, expected_sha, token, spec)
        if sha:
            dispatch_targets(parse_targets(os.environ["FLEET_SYNC_TARGETS"]),
                             json.loads(os.environ["FLEET_SYNC_CREDENTIALS"]), source, sha)
    else:
        sources = parse_sources(os.environ.get("FLEET_SYNC_SOURCES", ""))
        if os.environ.get("FLEET_SYNC_EVENT") == "repository_dispatch":
            # A notification names one upstream; it is never a reason to reconcile everything.
            if source in ("", "all"):
                raise ValueError("A dispatch notification must name its upstream repository")
        elif not source:
            source = "all"
        token = os.environ["GH_TOKEN"]
        update_consumer(source, expected_sha, token, refresh_visibility=args.refresh_visibility,
                        sources=sources)


def dispatch_source(source, workflow, branch):
    """Resolve the notifying repository: a built-in kit, or an upstream naming its own gate."""
    if not workflow and not branch:
        return resolve_source(source)
    if not workflow or not branch:
        raise ValueError("A custom upstream must name both its gate workflow and its branch")
    declared = parse_sources(json.dumps({source: {"workflow": workflow, "branch": branch}}))
    return resolve_source(source, declared)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Public dispatcher failures cannot print private repository paths or tokens.
        if len(sys.argv) > 1 and sys.argv[1] == "dispatch":
            print("::error::Fleet dispatch failed (%s). Check required CI, subscriptions and credentials." % type(exc).__name__)
        else:
            print("::error::%s" % exc)
        sys.exit(1)
