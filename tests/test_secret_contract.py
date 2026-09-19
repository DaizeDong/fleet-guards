"""Synthetic credential contracts; no live credentials or external transports."""
import hashlib
import importlib.util
import json
import subprocess
import sys

import pytest


def scanner():
    assert importlib.util.find_spec("fleet_guards") is not None, "shared package is missing"
    from fleet_guards import secrets
    return secrets


# Prefixes and payloads are assembled so the public test source contains no usable tokens.
SHAPES = [
    ("AKIA" + "A" * 16, "aws_access_key"),
    ("ASIA" + "A" * 16, "aws_access_key"),
    ("AGPA" + "A" * 16, "aws_access_key"),
    ("AIDA" + "A" * 16, "aws_access_key"),
    ("glpat-" + "A" * 24, "gitlab_token"),
    ("npm_" + "A" * 36, "npm_token"),
    ("sk-ant-" + "a" * 24, "anthropic_key"),
    ("sk-proj-" + "a" * 24, "openai_key"),
    ("sk-" + "a" * 12, "openai_key"),
    ("ghp_" + "A" * 12, "github_token"),
    ("ghs_" + "a._-" * 9, "github_token"),
    ("github_pat_" + "A" * 12, "github_pat_fine"),
    ("xoxb-" + "A" * 10, "slack_token"),
    ("AIza" + "A" * 30, "google_api_key"),
    ("sk_" + "test_" + "a" * 16, "stripe_key"),
    ("rk_" + "live_" + "a" * 16, "stripe_key"),
    ("mfa." + "A" * 20, "discord_bot_token"),
    ("A" * 24 + "." + "A" * 6 + "." + "A" * 27, "discord_bot_token"),
    ("eyJ" + "A" * 8 + "." + "A" * 8 + "." + "A" * 8, "jwt"),
    ("Bearer " + "short", "bearer_token"),
    ("https://discord.com/api/webhooks/123/" + "A" * 24, "discord_webhook"),
    ("https://ptb.discordapp.com/api/webhooks/123/" + "A" * 24, "discord_webhook"),
    ("https://hooks.slack.com/services/" + "A/B/C", "slack_webhook"),
    ("https://open.feishu.cn/open-apis/bot/v2/hook/" + "a" * 24, "feishu_webhook"),
    ("https://user1:synthetic-password@example.com/", "credential_uri"),
    ("postgresql://user1:p@example.com/db", "db_connection_string"),
    ("mongodb+srv://user1:p@example.com/db", "db_connection_string"),
    ("https://example.com/?token=short", "query_credential"),
    ("run --api-key short", "cli_credential"),
    ("run --password='synthetic password'", "cli_credential"),
    ('{"password": "synthetic-password"}', "credential_assignment"),
    ("refresh_token = synthetic-value", "credential_assignment"),
    ("private_key = synthetic-value", "credential_assignment"),
    ("access-key: synthetic-value", "credential_assignment"),
]


@pytest.mark.parametrize("text,rule", SHAPES)
def test_union_of_legacy_shapes(text, rule):
    result = scanner().scan(text)
    assert result["state"] == "findings"
    assert rule in {f["rule_id"] for f in result["findings"]}


@pytest.mark.parametrize("policy", ["credential-shapes-v1", "support-egress-v1"])
@pytest.mark.parametrize("value", ["ab;cd;ef", "ab,cd,ef", "12;34,56", "redacted;actual"])
def test_plain_assignment_punctuation_is_part_of_the_value(policy, value):
    result = scanner().scan("password: " + value, policy)
    assert result["state"] == "findings"
    assert "credential_assignment" in {f["rule_id"] for f in result["findings"]}


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "DSA ", "OPENSSH ", "ENCRYPTED ", "PGP "])
def test_private_key_headers(kind):
    assert scanner().scan("-----BEGIN " + kind + "PRIVATE KEY-----")["state"] == "findings"


def test_pgp_private_key_block():
    assert scanner().scan("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----")["state"] == "findings"


@pytest.mark.parametrize("text", [
    "The public rate limit is 100 requests per minute.",
    "0123456789abcdef" * 4,
    "def use_token(token: str):\n    return token.strip()",
    'API_KEY = os.environ["API_KEY"]',
    "token = process.env.API_TOKEN",
    'password = "${PASSWORD}"',
    'password = "<PASSWORD>"',
    'token = "$env:API_TOKEN"',
    'token = "redacted"',
    "sk-your-synthetic-api-key",
    "The secret variable name is API_KEY.",
    'sha256 = "' + "0123456789abcdef" * 4 + '"',
    'const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";',
])
def test_benign_text_and_complete_templates(text):
    result = scanner().scan(text)
    assert result["state"] == "clean"
    assert result["findings"] == []


@pytest.mark.parametrize("value", [
    "redacted-but-a-value", "example-secret-value", "your_actual_password",
    "${PASSWORD}suffix", "<PASSWORD>suffix", "$env:API_TOKEN/suffix",
    "process.env.API_TOKEN+suffix", "sk-your-synthetic-api-key123",
])
def test_partial_templates_are_not_exempt(value):
    assert scanner().scan('password = "' + value + '"')["state"] == "findings"


def test_template_does_not_suppress_another_credential():
    assert scanner().scan("sk-your-synthetic-api-key\n" + "npm_" + "A" * 24)["state"] == "findings"


@pytest.mark.parametrize("suffix", ["/suffix", ".suffix", "+suffix", "=suffix"])
def test_a_template_prefix_inside_a_larger_token_is_not_exempt(suffix):
    assert scanner().scan("sk-your-synthetic-api-key" + suffix)["state"] == "findings"


def test_support_policy_retains_entropy_and_canary_checks():
    secret = scanner()
    blob = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"
    assert secret.scan(blob)["state"] == "clean"
    assert secret.scan(blob, "support-egress-v1")["state"] == "findings"
    assert secret.scan("SYNTHETIC_CANARY", "support-egress-v1")["state"] == "findings"
    # Support historically blocked these shapes even when they were documentation templates.
    assert secret.scan("sk-your-synthetic-api-key", "support-egress-v1")["state"] == "findings"


def test_metadata_contains_spans_but_neither_values_nor_password_hashes():
    value = "synthetic-password"
    text = 'prefix\npassword = "' + value + '"'
    result = scanner().scan(text)
    assert result["policy_version"] == "credential-shapes-v1"
    assert result == scanner().scan(text)
    for finding in result["findings"]:
        assert set(finding) == {"rule_id", "span", "severity", "confidence"}
        start, end = finding["span"]
        assert 0 <= start < end <= len(text)
        assert value in text[start:end]
    serialized = json.dumps(result)
    assert value not in serialized
    assert hashlib.sha256(value.encode()).hexdigest()[:8] not in serialized
    assert scanner().scan(serialized)["state"] == "clean"


def test_scan_final_serialization_catches_cli_argument_pairs():
    document = json.dumps({"args": ["--token", "synthetic-value"]})
    assert scanner().scan(document)["state"] == "findings"


@pytest.mark.parametrize("text,policy", [(None, "credential-shapes-v1"), ("safe", "unknown"), (b"safe", "credential-shapes-v1")])
def test_invalid_scan_requests_fail_closed(text, policy):
    result = scanner().scan(text, policy)
    assert result["state"] == "scan_failed"
    assert result["error_code"]


def test_input_and_finding_budgets_fail_closed(monkeypatch):
    secret = scanner()
    monkeypatch.setattr(secret, "MAX_TEXT_CHARS", 10)
    assert secret.scan("a" * 11)["state"] == "scan_failed"
    monkeypatch.setattr(secret, "MAX_TEXT_CHARS", 1000)
    monkeypatch.setattr(secret, "MAX_FINDINGS", 1)
    assert secret.scan(("npm_" + "A" * 24 + " ") * 2)["state"] == "scan_failed"


def test_scanner_exception_and_timeout_cannot_authorize_release(monkeypatch):
    secret = scanner()
    monkeypatch.setattr(secret.time, "monotonic", lambda: 10.0)
    monkeypatch.setattr(secret, "SCAN_SECONDS", -1)
    assert secret.scan("safe")["state"] == "scan_failed"
    def broken_clock():
        raise RuntimeError("synthetic-private-input")
    monkeypatch.setattr(secret.time, "monotonic", broken_clock)
    result = secret.scan("safe")
    assert result["state"] == "scan_failed"
    assert "synthetic-private-input" not in json.dumps(result)


@pytest.mark.parametrize("data,code,state", [(b"safe", 0, "clean"), (b"Bearer synthetic", 1, "findings"), (b"\xff", 2, "scan_failed")])
def test_cli_json_and_exit_status(data, code, state):
    scanner()
    proc = subprocess.run([sys.executable, "-m", "fleet_guards", "scan"], input=data, capture_output=True, timeout=15)
    assert proc.returncode == code
    assert json.loads(proc.stdout)["state"] == state
    assert proc.stderr == b""
