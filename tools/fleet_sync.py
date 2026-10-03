"""Dispatch verified upstream updates and advance consumer gitlinks."""
import argparse
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
from urllib.parse import urlencode
from urllib.request import Request, urlopen

SOURCES = {
    "DaizeDong/fleet-guards": "pii-guard.yml",
    "DaizeDong/fleet-style": "style.yml",
}


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


def source_from_url(url):
    for source in SOURCES:
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


def select_modules(contents, source):
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(contents)
    selected = []
    for section in config.sections():
        values = config[section]
        upstream = source_from_url(values.get("url", ""))
        if upstream and source in ("all", upstream):
            branch = values.get("branch", "main")
            if branch != "main":
                raise ValueError("Automatic synchronization requires the upstream main branch")
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


def verified_tip(source, expected_sha, token):
    if source not in SOURCES:
        raise ValueError("Unknown upstream repository")
    if expected_sha and not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ValueError("Invalid upstream commit")
    tip = api("repos/%s/commits/main" % source, token)["sha"]
    if expected_sha and tip != expected_sha:
        print("Obsolete notification: a newer upstream commit exists.")
        return None
    query = urlencode({"head_sha": tip, "branch": "main", "event": "push", "per_page": 100})
    runs = api("repos/%s/actions/workflows/%s/runs?%s" % (source, SOURCES[source], query), token)
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


def git(*args, capture=True):
    result = subprocess.run(["git", *args], check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ""


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


def update_consumer(source, expected_sha, token, *, refresh_visibility=False):
    if source not in (*SOURCES, "all"):
        raise ValueError("Unknown upstream repository")
    if git("status", "--porcelain"):
        raise RuntimeError("Consumer checkout is not clean")
    modules = select_modules(Path(".gitmodules").read_text(encoding="utf-8"), source)
    if not modules:
        raise RuntimeError("No matching upstream submodule is installed")
    changed = []
    for module in modules:
        sha = verified_tip(module["source"], expected_sha, token)
        if not sha:
            continue
        path = module["path"]
        entry = git("ls-files", "--stage", "--", path).split()
        if len(entry) < 4 or entry[0] != "160000":
            raise RuntimeError("Selected path is not a tracked gitlink")
        old = entry[1]
        if old == sha:
            continue
        # Fetch only the declared upstream, never an arbitrary payload URL.
        git("submodule", "update", "--init", "--", path, capture=False)
        git("-C", path, "fetch", "https://github.com/%s.git" % module["source"],
            "refs/heads/main", capture=False)
        git("-C", path, "merge-base", "--is-ancestor", old, sha)
        git("-C", path, "checkout", "--detach", sha, capture=False)
        git("add", "--", path)
        changed.append(path)
    staged = git("diff", "--cached", "--name-only").splitlines()
    if sorted(staged) != sorted(changed):
        raise RuntimeError("Unexpected staged files; refusing to commit")
    if changed:
        guard_modules = select_modules(Path(".gitmodules").read_text(encoding="utf-8"), "DaizeDong/fleet-guards")
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
                        "pre-commit", "--repo", str(root)], check=True)
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
    token = os.environ["GH_TOKEN"]
    if args.command == "dispatch":
        sha = verified_tip(source, expected_sha, token)
        if sha:
            dispatch_targets(parse_targets(os.environ["FLEET_SYNC_TARGETS"]),
                             json.loads(os.environ["FLEET_SYNC_CREDENTIALS"]), source, sha)
    else:
        update_consumer(source, expected_sha, token, refresh_visibility=args.refresh_visibility)


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
