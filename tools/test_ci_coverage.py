"""Every shipped pytest module must be an unconditional shared CI step."""
import ast
from pathlib import Path


def test_shared_ci_runs_every_guard_test_module():
    root = Path(__file__).parent.parent
    action = (root / "ci/pii-guard/action.yml").read_text(encoding="utf-8")
    blocks = action.split("    - name:")[1:]
    modules = []
    for path in sorted((root / "tools").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
               and node.name.startswith("test_") for node in ast.walk(tree)):
            modules.append(path.name)
    assert modules
    for name in modules:
        command = 'python -m pytest "$GITHUB_ACTION_PATH/../../tools/' + name + '" -q'
        matches = [block for block in blocks if command in {line.strip() for line in block.splitlines()}]
        assert len(matches) == 1, "Shared CI must run " + name + " once with its exit code intact"
        assert "\n      if:" not in matches[0]
        assert "continue-on-error:" not in matches[0]
