"""Metadata-only scan results, suitable for serialization into ordinary logs."""
from typing import Literal, TypedDict


class Finding(TypedDict):
    rule_id: str
    span: list[int]
    severity: Literal["block"]
    confidence: float


def finding(rule_id: str, span: tuple[int, int], confidence: float = 0.99) -> Finding:
    return {"rule_id": rule_id, "span": list(span), "severity": "block", "confidence": confidence}


def failed(policy: str | None, code: str) -> dict:
    # Never include exception messages, input text, or unkeyed value fingerprints.
    return {"state": "scan_failed", "policy_version": policy, "findings": [], "error_code": code}
