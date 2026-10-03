"""Apply publication policy to the invoking repository, with proven private scope."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import shutil
import stat
import ssl
import sys
import tempfile
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, url):
        return None


def unaliased_absolute(path):
    """Inspect path topology without reading executable or helper contents."""
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        return False
    try:
        for node in [*reversed(candidate.parents), candidate]:
            info = node.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return False
    except OSError:
        return False
    return True


@contextmanager
def native_hook_environment(phase):
    """Git injects its default helper path into hooks; arbitrary overrides remain unproved."""
    selected = {key: value for key, value in os.environ.items() if key.upper() == "GIT_EXEC_PATH"}
    removed = False
    if phase in {"pre-commit", "pre-push"} and len(selected) == 1:
        environment = {key: value for key, value in os.environ.items() if key.upper() != "GIT_EXEC_PATH"}
        git = shutil.which("git")
        if (git and unaliased_absolute(git) and Path(git).is_file()
                and Path(git).name.casefold() == ("git.exe" if os.name == "nt" else "git")):
            result = subprocess.run([git, "--exec-path"], env=environment, capture_output=True,
                                    text=True, encoding="utf-8")
            default = result.stdout.strip()
            actual = next(iter(selected.values()))
            if (result.returncode == 0 and unaliased_absolute(default) and unaliased_absolute(actual)
                    and Path(default).is_dir()
                    and os.path.normcase(os.path.normpath(default)) == os.path.normcase(os.path.normpath(actual))):
                for key in selected:
                    del os.environ[key]
                removed = True
    try:
        yield
    finally:
        if removed:
            os.environ.update(selected)


def github_visibility(repository, token):
    """Read authoritative metadata from the canonical API without forwarding credentials."""
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or any(part in {".", ".."} for part in repository.split("/"))):
        raise ValueError("Repository metadata requires a canonical owner/name")
    unproved = {"http_proxy", "https_proxy", "all_proxy", "ssl_cert_file", "ssl_cert_dir",
                "curl_ca_bundle", "requests_ca_bundle", "sslkeylogfile"}
    if any(key.casefold() in unproved for key in os.environ):
        raise ValueError("Repository metadata TLS or proxy environment is unproved")
    request = urllib.request.Request(
        "https://api.github.com/repos/" + repository,
        headers={"Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
                 "User-Agent": "fleet-guards", "X-GitHub-Api-Version": "2022-11-28"})
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=15) as response:
        if response.geturl() != request.full_url:
            raise ValueError("Repository metadata response changed the requested destination")
        metadata = json.load(response)
    if (not isinstance(metadata, dict)
            or str(metadata.get("full_name", "")).casefold() != repository.casefold()):
        raise ValueError("Repository metadata does not identify the requested destination")
    if metadata.get("private") is True and metadata.get("visibility") == "private":
        return "PRIVATE"
    if metadata.get("private") is False and metadata.get("visibility") == "public":
        return "PUBLIC"
    return "UNKNOWN"


def configured_urls(boundary, context, push_only=False):
    """Enumerate actual Git-expanded routes in both contexts without contacting them."""
    root, physical, effective = context
    for environment in (physical, effective):
        urls = set()
        for remote in boundary._run(["git", "remote"], root, env=environment).splitlines():
            for options in (["--push"],) if push_only else ([], ["--push"]):
                urls.update(boundary._run(
                    ["git", "remote", "get-url", *options, "--all", remote],
                    root, env=environment).splitlines())
        yield urls


def private_proof(boundary, root, phase, destination):
    """Only a complete fresh proof can select private policy; uncertainty stays public."""
    try:
        if phase == "ci" and os.environ.get("GITHUB_ACTIONS") == "true":
            token = os.environ.get("GITHUB_TOKEN")
            if not token:
                raise boundary.GitError("CI repository metadata credential is unavailable")
            context = boundary._companion_git_context(root)
            repositories = set()
            for urls in configured_urls(boundary, context):
                for url in urls:
                    key, _host = boundary._github_publication_route(url)
                    if key is None:
                        raise boundary.GitError("CI publication destination is UNKNOWN")
                    repositories.add("%s/%s" % key)
            receipt = {name: github_visibility(name, token) for name in sorted(repositories)}
            from pii_guard import _utcnow
            receipt["_refreshed"] = _utcnow()
            with tempfile.TemporaryDirectory(prefix="guard-visibility-") as temporary:
                if Path(temporary).resolve().is_relative_to(Path(root).resolve()):
                    raise boundary.GitError("Visibility metadata must stay outside the worktree")
                path = Path(temporary) / "visibility.json"
                path.write_text(json.dumps(receipt), encoding="utf-8")
                proof = boundary.prove_private_companion(root, path)
        else:
            proof = boundary.prove_private_companion(root)
        if phase == "pre-push" and destination:
            if not all(destination in urls for urls in configured_urls(boundary, proof._context, True)):
                raise boundary.GitError("Actual push destination is outside the PRIVATE proof")
        boundary.read_private_companion_git(proof, "check-ignore", "--no-index", "-q", "--", ".")
        return proof
    except boundary.GitError as error:
        print("publication_guard: PRIVATE scope not proven; public policy applies. " + str(error), flush=True)
    except (urllib.error.URLError, OSError, ValueError, TypeError):
        print("publication_guard: authoritative visibility metadata unavailable; public policy applies.", flush=True)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("pre-commit", "pre-push", "ci"))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--push-destination", default="")
    arguments = parser.parse_args()
    kit = Path(__file__).resolve().parent
    for name in ("pii_guard.py", "data_boundary.py"):
        path = kit / name
        if not path.is_file() or not path.stat().st_size:
            print("BLOCKED: %s is missing or empty; publication policy is unchecked." % path)
            return 1
    import data_boundary as boundary
    with native_hook_environment(arguments.phase):
        proof = private_proof(boundary, os.path.abspath(arguments.repo),
                              arguments.phase, arguments.push_destination)
    if proof is not None:
        print("publication_guard: PRIVATE verified: " + ", ".join(proof.repositories))
        print("publication_guard: public-content PII scan is out of scope; structural checks remain required.")
        previous = sys.argv
        try:
            sys.argv = [str(kit / "data_boundary.py"), "--repo", proof.root]
            result = boundary.main(private_proof=proof)
        finally:
            sys.argv = previous
        if result == 0:
            with native_hook_environment(arguments.phase):
                current = private_proof(boundary, proof.root, arguments.phase, arguments.push_destination)
            if (current is None or (current.root, current.repositories, current.signature)
                    != (proof.root, proof.repositories, proof.signature)):
                print("publication_guard: PRIVATE authorization changed during checks; retry required.")
                return 2
        # A distinct successful hook status keeps the public semantic layer out of private pushes.
        return 10 if result == 0 and arguments.phase == "pre-push" else result
    scope = ["--tree", "--staged" if arguments.phase == "pre-commit" else "--history"]
    for name, options in (("pii_guard.py", scope), ("data_boundary.py", [])):
        result = subprocess.run([sys.executable, str(kit / name), "--repo", arguments.repo, *options])
        if result.returncode:
            label = "push" if arguments.phase == "pre-push" else arguments.phase
            print("%s BLOCKED by %s." % (label, Path(name).stem))
            return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, ImportError, AttributeError) as error:
        print("publication_guard: SCAN FAILED (%s); publication policy was not completed."
              % type(error).__name__, file=sys.stderr)
        sys.exit(2)
