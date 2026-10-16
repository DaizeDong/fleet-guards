"""Apply publication policy to the invoking repository, with proven private scope."""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys

# Consumers also load this file by path (importlib), where tools/ is not on sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import data_boundary as boundary  # noqa: E402


@contextmanager
def native_hook_environment():
    """Drop Git's own injected helper path for children; any other override stays and is refused."""
    selected = {key: value for key, value in os.environ.items() if key.upper() == "GIT_EXEC_PATH"}
    removed = bool(selected) and boundary._git_exec_path_problem(dict(os.environ)) is None
    if removed:
        for key in selected:
            del os.environ[key]
    try:
        yield
    finally:
        if removed:
            os.environ.update(selected)


def push_urls(context):
    """Enumerate actual Git-expanded push routes in both contexts without contacting them."""
    root, physical, effective = context
    for environment in (physical, effective):
        urls = set()
        for remote in boundary._run(["git", "remote"], root, env=environment).splitlines():
            urls.update(boundary._run(
                ["git", "remote", "get-url", "--push", "--all", remote],
                root, env=environment).splitlines())
        yield urls


def private_proof(root, phase, destination):
    """Only a complete fresh proof can select private policy; uncertainty stays public."""
    try:
        proof = boundary.prove_private_companion(root)
        if phase == "pre-push" and destination:
            if not all(destination in urls for urls in push_urls(proof._context)):
                raise boundary.GitError("Actual push destination is outside the PRIVATE proof")
        return proof
    except boundary.GitError as error:
        print("publication_guard: PRIVATE scope not proven; public policy applies. " + str(error), flush=True)
    except (OSError, ValueError, TypeError):
        print("publication_guard: visibility receipt unavailable; public policy applies.", flush=True)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("pre-commit", "pre-push"))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--push-destination", default="")
    arguments = parser.parse_args()
    kit = Path(__file__).resolve().parent
    path = kit / "pii_guard.py"
    if not path.is_file() or not path.stat().st_size:
        print("BLOCKED: %s is missing or empty; publication policy is unchecked." % path)
        return 1
    proof = private_proof(os.path.abspath(arguments.repo), arguments.phase, arguments.push_destination)
    if proof is not None:
        print("publication_guard: PRIVATE verified: " + ", ".join(proof.repositories))
        print("publication_guard: public-content PII scan is out of scope; structural checks remain required.")
        previous = sys.argv
        try:
            sys.argv = [str(kit / "data_boundary.py"), "--repo", proof.root]
            return boundary.main(private_proof=proof)
        finally:
            sys.argv = previous
    # Commit checks only what is being committed; push checks everything being published.
    scope = ["--staged"] if arguments.phase == "pre-commit" else ["--tree", "--history"]
    for name, options in (("pii_guard.py", scope), ("data_boundary.py", [])):
        result = subprocess.run([sys.executable, str(kit / name), "--repo", arguments.repo, *options],
                                **boundary._no_window())
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
