"""Dispatch verified upstream updates and advance consumer gitlinks."""
import argparse
import configparser
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path, PurePosixPath
import re
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


def update_consumer(source, expected_sha, token):
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
        for tool in ("pii_guard.py", "data_boundary.py"):
            subprocess.run([sys.executable, str(guard / "tools" / tool)], check=True)
        # Arm existing fail-closed shims. A missing shim must be repaired during enrollment.
        if not all(Path(".githooks", hook).is_file() for hook in ("pre-commit", "pre-push")):
            raise RuntimeError("Missing .githooks shims; complete fleet-guards installation")
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
    args = parser.parse_args()
    source = os.environ.get("SOURCE_REPOSITORY", "")
    expected_sha = os.environ.get("SOURCE_SHA", "")
    token = os.environ["GH_TOKEN"]
    if args.command == "dispatch":
        sha = verified_tip(source, expected_sha, token)
        if sha:
            dispatch_targets(parse_targets(os.environ["FLEET_SYNC_TARGETS"]),
                             json.loads(os.environ["FLEET_SYNC_CREDENTIALS"]), source, sha)
    else:
        update_consumer(source, expected_sha, token)


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
