"""Secret redaction: values never survive into text or structures."""

import json

from veyron.redact import REDACTED, is_likely_secret, redact_mapping, redact_text


def test_api_key_redacted():
    text = 'api_key = "FAKE_KEY_ABCDEFGHIJKLMNOP"'
    out = redact_text(text)
    assert "FAKE_KEY_ABCDEFGHIJKLMNOP" not in out
    assert REDACTED in out
    assert "api_key" in out  # the label survives for context


def test_password_redacted():
    out = redact_text("password=hunter2-not-real-value")
    assert "hunter2-not-real-value" not in out
    assert REDACTED in out


def test_pem_block_redacted():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
    out = redact_text(pem)
    assert "MIIEvQIBADANBg" not in out


def test_github_token_redacted():
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    out = redact_text(f"token is {tok} end")
    assert tok not in out


def test_aws_key_redacted():
    out = redact_text('aws_secret_access_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"')
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" not in out


def test_mapping_redaction_deep():
    payload = {
        "evidence": "api_key='FAKE_DEEP_KEY_123456789'",
        "nested": [{"password": "FAKE_PASS_987654321"}],
        "count": 3,
    }
    out = redact_mapping(payload)
    blob = json.dumps(out)
    assert "FAKE_DEEP_KEY_123456789" not in blob
    assert "FAKE_PASS_987654321" not in blob
    assert out["count"] == 3


def test_clean_text_unchanged():
    text = "def add(a, b):\n    return a + b\n"
    assert redact_text(text) == text


def test_is_likely_secret():
    assert is_likely_secret("ghp_" + "A" * 40)
    assert not is_likely_secret("hello world")
