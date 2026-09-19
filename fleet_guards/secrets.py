"""Versioned union of credential shapes from support, sync and backup.

Only ``state == 'clean'`` can authorize a caller to proceed. This module does
not redact documents or interpret configuration field ownership. Scan the final
serialized output too. Offsets are half-open character offsets into the input.
"""
from collections import Counter
import math
import re
import time

from .findings import failed, finding


POLICIES = ("credential-shapes-v1", "support-egress-v1")
MAX_TEXT_CHARS = 1_000_000
MAX_FINDINGS = 1000
SCAN_SECONDS = 1.0
MAX_SCAN_TEXT_CHARS = 16 * 1024 * 1024
MAX_SCAN_SECONDS = 30.0

# The shorter thresholds and case-insensitive variants preserve sync and backup
# detections; the extra provider families preserve support's precise rules.
_SHAPES = tuple((name, re.compile(pattern, re.I)) for name, pattern in (
    ("anthropic_key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("openai_key", r"\bsk-[A-Za-z0-9_-]{12,}"),
    ("aws_access_key", r"\b(?:AKIA|ASIA|AGPA|AIDA)[A-Z0-9]{16}\b"),
    ("stripe_key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("github_token", r"\b(?:ghp_[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9._-]{20,})"),
    ("github_pat_fine", r"\bgithub_pat_[A-Za-z0-9_]{12,}"),
    ("gitlab_token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("npm_token", r"\bnpm_[A-Za-z0-9]{20,}"),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("google_api_key", r"\bAIza[A-Za-z0-9_-]{30,}"),
    ("discord_bot_token", r"\b(?:mfa\.[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40})\b"),
    ("discord_webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[^\s<>\"']+"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[^\s<>\"']+"),
    ("feishu_webhook", r"https://open\.feishu\.cn/open-apis/bot/v2/hook/[0-9a-f-]{20,}"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("private_key_pem", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("credential_uri", r"https?://[^/\s:@]+:[^@\s/]+@"),
    ("db_connection_string", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@"),
))
_KEY = r"(?:password|passwd|pwd|api[_-]?key|secret|access[_-]?(?:key|token)|refresh[_-]?token|client[_-]?secret|private[_-]?key|token|webhook)"
_VALUE = r'''(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;`]+)'''
# Plain-text/YAML values can contain commas and semicolons. CLI/JSON argument
# delimiters must not truncate those values before the legacy length check.
_ASSIGNMENT_VALUE = r'''(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s`]+)'''
_ASSIGNMENT = re.compile(r"\b" + _KEY + r"\b[\"']?\s*[:=]\s*" + _ASSIGNMENT_VALUE, re.I)
_CLI = re.compile(r"--" + _KEY + r"\b(?:=|\s+|[\"']\s*,\s*)" + _VALUE, re.I)
_QUERY = re.compile(r"[?&](?:key|api_key|token|secret|password)=(?P<value>[^&#\s\"']+)", re.I)
_BEARER = re.compile(r"\bBearer\s+" + _VALUE, re.I)
_CANDIDATE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_CANARY = re.compile(r"\b[A-Z0-9_]*CANARY[A-Z0-9_]*\b")
_API_TEMPLATE = re.compile(r"sk-your-(?:[a-z][a-z0-9]{0,31}-)?(?:api-)?key(?:-here)?")
_PLACEHOLDER = re.compile(
    r"(?:redacted|example|placeholder|changeme|x{4,}|\*{4,}|"
    r"<[A-Za-z_][A-Za-z0-9_.-]*>|\$\{[A-Za-z_][A-Za-z0-9_]*\}|"
    r"\$env:[A-Za-z_][A-Za-z0-9_]*|process\.env\.[A-Za-z_][A-Za-z0-9_]*|"
    r"os\.environ\[['\"][A-Za-z_][A-Za-z0-9_]*['\"]\])", re.I,
)


class _BudgetExceeded(Exception):
    pass


def shannon_entropy(text):
    if not text:
        return 0.0
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in Counter(text).values())


def _template(value):
    return bool(_PLACEHOLDER.fullmatch(value) or _API_TEMPLATE.fullmatch(value))


def _complete_api_template(match, text):
    if not _API_TEMPLATE.fullmatch(match.group()):
        return False
    token_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~+/=-"
    start, end = match.span()
    return (start == 0 or text[start - 1] not in token_chars) and (end == len(text) or text[end] not in token_chars)


def _scan(text, policy, entropy_threshold, seconds):
    deadline = time.monotonic() + seconds
    strict = policy == "support-egress-v1"
    findings = []

    def check_budget():
        if time.monotonic() >= deadline:
            raise _BudgetExceeded

    def add(name, span, confidence=0.99):
        check_budget()
        if len(findings) >= MAX_FINDINGS:
            raise _BudgetExceeded
        findings.append(finding(name, span, confidence))

    for name, pattern in _SHAPES:
        check_budget()
        for match in pattern.finditer(text):
            if not strict and name == "openai_key" and _complete_api_template(match, text):
                continue
            add(name, match.span())

    for name, pattern, minimum in (
        ("credential_assignment", _ASSIGNMENT, 8),
        ("cli_credential", _CLI, 1),
        ("query_credential", _QUERY, 1),
        ("bearer_token", _BEARER, 1),
    ):
        check_budget()
        for match in pattern.finditer(text):
            check_budget()
            value = match.group("value")
            if value[:1] in ("'", '"') and value[-1:] == value[:1]:
                value = value[1:-1]
            if len(value) >= minimum and (strict or not _template(value)):
                add(name, match.span())

    if strict:
        for match in _CANARY.finditer(text):
            add("canary_secret", match.span())
        for match in _CANDIDATE.finditer(text):
            check_budget()
            start, end = match.span()
            if any(a < end and start < b for a, b in (f["span"] for f in findings)):
                continue
            token = match.group()
            classes = sum(bool(re.search(p, token)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
            if len(token) >= 24 and classes >= 2:
                entropy = shannon_entropy(token)
                if entropy >= entropy_threshold:
                    add("high_entropy_token", match.span(), 0.6)
    check_budget()
    findings.sort(key=lambda f: (f["span"][0], f["span"][1], f["rule_id"]))
    check_budget()
    return {"state": "findings" if findings else "clean", "policy_version": policy, "findings": findings}


def scan(text: str, policy: str = "credential-shapes-v1", *, entropy_threshold: float = 4.0,
         max_text_chars: int | None = None, seconds: float | None = None) -> dict:
    """Return metadata only. Unknown policies, incomplete scans and failures fail closed.

    Input and finding counts are bounded. Time is checked between regex operations;
    this is not an OS-enforced regex timeout. Patterns avoid nested quantifiers.
    Explicit per-call budgets may opt into at most 16 Mi characters / 30 seconds.
    Omitted budgets retain the 1M character / 1 second defaults. Byte limits are
    the caller's responsibility; the scan never truncates or partitions input.
    """
    if not isinstance(policy, str) or policy not in POLICIES:
        return failed(None, "unknown_policy")
    if not isinstance(text, str):
        return failed(policy, "invalid_text")
    if (not isinstance(entropy_threshold, (int, float)) or
            not math.isfinite(entropy_threshold) or entropy_threshold < 0):
        return failed(policy, "invalid_entropy_threshold")
    max_text_chars = MAX_TEXT_CHARS if max_text_chars is None else max_text_chars
    seconds = SCAN_SECONDS if seconds is None else seconds
    if (type(max_text_chars) is not int or not 0 < max_text_chars <= MAX_SCAN_TEXT_CHARS or
            type(seconds) not in (int, float) or not 0 < seconds <= MAX_SCAN_SECONDS):
        return failed(policy, "invalid_scan_budget")
    if len(text) > max_text_chars:
        return failed(policy, "input_limit")
    try:
        return _scan(text, policy, entropy_threshold, seconds)
    except _BudgetExceeded:
        return failed(policy, "scan_budget")
    except Exception:
        # A broken detector must never turn into a clean result or log its input.
        return failed(policy, "scanner_error")
