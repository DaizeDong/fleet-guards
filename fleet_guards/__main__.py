"""JSON-only credential CLI: stdin to metadata; exits clean=0, findings=1, failure=2."""
import argparse
import json
import sys

from . import secrets
from .findings import failed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["scan"])
    parser.add_argument("--policy", default="credential-shapes-v1")
    args = parser.parse_args(argv)
    policy = args.policy if args.policy in secrets.POLICIES else None
    try:
        # UTF-8 can require four bytes per character. Bound bytes before decoding.
        data = sys.stdin.buffer.read(secrets.MAX_TEXT_CHARS * 4 + 1)
        if len(data) > secrets.MAX_TEXT_CHARS * 4:
            result = failed(policy, "input_limit")
        else:
            result = secrets.scan(data.decode("utf-8"), args.policy)
    except UnicodeError:
        result = failed(policy, "invalid_encoding")
    except OSError:
        result = failed(policy, "input_error")
    print(json.dumps(result, sort_keys=True))
    return {"clean": 0, "findings": 1, "scan_failed": 2}[result["state"]]


if __name__ == "__main__":
    raise SystemExit(main())
