"""Canonical source storage contracts: schema validation and path ownership.

Inventory/retirement orchestration belongs to consumers. This module neither
creates directories nor writes data, Git configuration, receipts, or indexes.
The companion's PRIVATE publication is enforced at commit time, not here.
"""
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat

CONTRACT = "storage.contract.json"
FIELDS = ("artifact_id", "path_pattern", "purpose", "schema", "producer",
          "consumer_or_final_deliverable", "rebuild_or_restore")
CLASSES = {"core", "rebuildable", "retired"}
SEPARATE = "separate_companion"
COMBINED = "combined_private_repo"


def relative_path(value, *, pattern=False):
    """Accept portable relative paths without Windows aliases or traversal."""
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("path must be a nonempty relative POSIX path")
    parts = value.split("/")
    if any(p in {"", ".", ".."} or p.endswith((" ", ".")) for p in parts):
        raise ValueError("path contains an absolute, empty or traversal component")
    for part in parts:
        if part.casefold() == ".git" or any(ord(c) < 32 or c in '<>|"' for c in part):
            raise ValueError("repository metadata and invalid path characters are forbidden")
        if re.match(r"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³]) *(?:\.|$)",
                    part, re.I):
            raise ValueError("path contains a reserved Windows name")
        if not pattern and any(c in part for c in "*?"):
            raise ValueError("retirement requires a concrete path, not a glob")
    if all(character in "*?/" for character in value):
        raise ValueError("repository metadata and unrestricted catch-all paths are forbidden")
    return value



def validate_contract(repo):
    path = no_links(Path(repo) / CONTRACT)
    if not path.is_file() or path.lstat().st_nlink != 1:
        raise ValueError("source contract must be an ordinary unlinked file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1):
        raise ValueError("storage contract requires schema_version 1")
    if not isinstance(value.get("tool"), str) or not value["tool"].strip():
        raise ValueError("storage contract requires a tool identity")
    layout = value.get("layout", SEPARATE)
    if layout not in (SEPARATE, COMBINED):
        raise ValueError("unsupported storage layout")
    roots = value.get("data_roots")
    if layout == COMBINED:
        if not isinstance(roots, list) or not roots:
            raise ValueError("combined_private_repo requires nonempty data_roots")
        for root in roots:
            relative_path(root)
        folded = [root.casefold() for root in roots]
        if len(set(folded)) != len(folded) or any(
                b.startswith(a + "/") for a in folded for b in folded if a != b):
            raise ValueError("data_roots must not overlap")
    elif roots is not None:
        raise ValueError("data_roots is only supported for explicit combined_private_repo layout")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("storage contract requires an audited nonempty artifact list")
    identifiers = set()
    for row in artifacts:
        if not isinstance(row, dict) or any(not isinstance(row.get(k), str) or not row[k].strip() for k in FIELDS):
            raise ValueError("artifact requires all documented nonempty fields")
        if row["artifact_id"] in identifiers:
            raise ValueError("duplicate artifact_id")
        identifiers.add(row["artifact_id"])
        relative_path(row["path_pattern"], pattern=True)
        if layout == COMBINED and not in_data_scope(value, row["path_pattern"]):
            raise ValueError("artifact path_pattern is outside declared data_roots")
        retention = row.get("retention_rule")
        if (not isinstance(retention, dict) or retention.get("class") not in CLASSES
                or not isinstance(retention.get("rule"), str) or not retention["rule"].strip()):
            raise ValueError("artifact requires an explicit retention class and rule")
        persistence = row.get("persistence", "versioned")
        if persistence not in ("versioned", "transient"):
            raise ValueError("artifact persistence must be versioned or transient")
        if persistence == "transient":
            reason = row.get("transient_reason")
            if not isinstance(reason, str) or not reason.strip():
                raise ValueError("transient persistence requires a nonempty transient_reason")
        elif "transient_reason" in row:
            raise ValueError("transient_reason requires transient persistence")
        for key in ("max_bytes",):
            if key in row and (type(row[key]) is not int or row[key] <= 0):
                raise ValueError("artifact max_bytes must be a positive integer")
    if "max_bytes" in value and (type(value["max_bytes"]) is not int or value["max_bytes"] <= 0):
        raise ValueError("contract max_bytes must be a positive integer")
    if not isinstance(value.get("protected_paths", []), list):
        raise ValueError("protected_paths must be a list of relative patterns")
    for pattern in value.get("protected_paths", []):
        relative_path(pattern, pattern=True)
    return value


def in_data_scope(contract, relative):
    if contract.get("layout", SEPARATE) != COMBINED:
        return True
    return any(relative == root or relative.startswith(root + "/") for root in contract["data_roots"])


def matches(path, pattern):
    """Segment glob: * stays within a segment; ** matches zero or more segments."""
    if os.name == "nt":
        path, pattern = path.casefold(), pattern.casefold()
    def match(parts, pats):
        if not pats:
            return not parts
        if pats[0] == "**":
            return match(parts, pats[1:]) or bool(parts) and match(parts[1:], pats)
        return bool(parts) and fnmatch.fnmatchcase(parts[0], pats[0]) and match(parts[1:], pats[1:])
    return match(path.split("/"), pattern.split("/"))


def no_links(path, *, allow_missing=False):
    """Inspect lexical ancestors before resolve can hide a junction or symlink."""
    path = Path(os.path.abspath(path))
    for node in (*reversed(path.parents), path):
        try:
            info = node.lstat()
        except FileNotFoundError:
            if allow_missing:
                return None
            raise
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("symlink/junction boundary refused: " + str(node))
    return path


def owners(contract, path):
    return [row for row in contract["artifacts"] if matches(path, row["path_pattern"])]


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
