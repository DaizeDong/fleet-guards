"""Apply publication policy to the invoking repository, with proven private scope."""
import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import shutil
import stat
import sys


# ------------------------------------------------- spawning processes (identical in every kit file)
# Every spawn goes through _no_window(): a console child of a console-less process (pythonw, a
# scheduled task) otherwise opens a visible window. The flag is added only when this process has no
# console, so a hook's unredirected output is never hidden. Each file carries its own copy because
# the hook runs these files by path and the package imports them individually.
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
                                    text=True, encoding="utf-8", **_no_window())
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
        proof = boundary.prove_private_companion(root)
        if phase == "pre-push" and destination:
            if not all(destination in urls for urls in configured_urls(boundary, proof._context, True)):
                raise boundary.GitError("Actual push destination is outside the PRIVATE proof")
        boundary.read_private_companion_git(proof, "check-ignore", "--no-index", "-q", "--", ".")
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
            return boundary.main(private_proof=proof)
        finally:
            sys.argv = previous
    # Commit checks only what is being committed; push checks everything being published.
    scope = ["--staged"] if arguments.phase == "pre-commit" else ["--tree", "--history"]
    for name, options in (("pii_guard.py", scope), ("data_boundary.py", [])):
        result = subprocess.run([sys.executable, str(kit / name), "--repo", arguments.repo, *options],
                                **_no_window())
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
