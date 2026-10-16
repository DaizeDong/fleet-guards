"""Consumer access to the canonical companion resolver and storage contract.

The modules come from fleet_guards._tools, which is the checkout's tools/ directory: an editable
install (pip install -e "$(git config --get fleet.guards)") maps it to the checkout, and a built
wheel carries a copy. PRIVATE publication is enforced at commit time by the consumer's .githooks
shims, not by a runtime proof.
"""
from dataclasses import dataclass
import importlib
from pathlib import Path


def _canonical(name):
    return importlib.import_module("fleet_guards._tools." + name)


@dataclass(frozen=True)
class CompanionResolver:
    source_root: Path

    def __post_init__(self):
        path = Path(self.source_root)
        if not path.is_absolute():
            raise ValueError("source_root must be absolute")
        object.__setattr__(self, "source_root", path.resolve())

    def resolve_data_dir(self, skill):
        return _canonical("datadir").resolve_data_dir(skill, source_root=self.source_root)

    def resolve_companion_root(self, skill):
        return _canonical("datadir").resolve_companion_root(skill, source_root=self.source_root)

    def assert_outside_own_repo(self, path, skill):
        return _canonical("datadir").assert_outside_own_repo(
            path, skill, source_root=self.source_root)


def companion_resolver(*, source_root):
    """Bind discovery to an explicit consumer source root, never the Guards installation."""
    return CompanionResolver(source_root)


def storage_contract():
    """The canonical storage_contract module (schema validation and path ownership)."""
    return _canonical("storage_contract")
