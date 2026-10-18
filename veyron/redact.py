"""Redaction helpers for secrets discovered during assessment.

VEYRON treats every detected secret as sensitive. Detected values are
redacted in logs, reports, and AI payloads by default. Values are never
transmitted to external services and are never used to authenticate.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

REDACTED = "[REDACTED]"

# Patterns for *potential* secrets. These are intentionally conservative:
# they flag candidates for human review, they do not verify activity.
# Each pattern is paired with a group number whose match must be replaced.
SECRET_PATTERNS: list[tuple[re.Pattern[str], int | None]] = [
    # (api_key=..., secret_key=..., access_token=...)
    (
        re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b"
            r"\s*[:=]\s*[\"']?([^\s\"']{6,})[\"']?"
        ),
        2,
    ),
    # (password=..., passwd=..., pwd=...)
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*[\"']?([^\s\"']{6,})[\"']?"
        ),
        2,
    ),
    # Generic labelled values: value=..., secret=..., token=..., credential=...
    (
        re.compile(
            r"(?i)\b(value|secret|token|credential|passwd|pwd)\b\s*[:=]\s*[\"']?([^\s\"']{6,})[\"']?"
        ),
        2,
    ),
    # PEM private key blocks (entire block replaced).
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.S,
        ),
        0,
    ),
    # AWS credential pair.
    (
        re.compile(
            r"(?i)\b(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id)\b"
            r"\s*[:=]\s*[\"']?([A-Z0-9]{16,})[\"']?"
        ),
        2,
    ),
    # Well-known token shapes (whole match replaced).
    (re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), 0),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{36,}\b"), 0),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), 0),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0),
]


def redact_text(text: str) -> str:
    """Return text with likely secret values replaced by [REDACTED]."""

    if not text:
        return text

    result = text
    for pattern, group in SECRET_PATTERNS:

        def repl(m: re.Match[str], g: int = group) -> str:
            if g == 0:
                return REDACTED
            start, end = m.span(g)
            return m.string[m.start() : start] + REDACTED + m.string[end :]

        result = pattern.sub(repl, result)
    return result


# Mapping keys whose *values* are always redacted, even without an inline
# `key = value` pattern (dict payloads carry keys and values separately).
SECRET_KEY_PATTERN = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|credential|authorization|private[_-]?key|pwd)"
)


def redact_mapping(value: Any) -> Any:
    """Return a redacted deep copy of a nested mapping/list/str structure."""

    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for k, v in value.items():
            if isinstance(k, str) and SECRET_KEY_PATTERN.search(k) and not isinstance(v, (Mapping, list)):
                out[k] = REDACTED  # value wholesale: key says it is sensitive
            else:
                out[k] = redact_mapping(v)
        return out
    if isinstance(value, list):
        return [redact_mapping(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def is_likely_secret(text: str) -> bool:
    """Return True if the text contains a pattern matching a likely secret."""

    if not text:
        return False
    return any(pattern.search(text) for pattern, _group in SECRET_PATTERNS)
