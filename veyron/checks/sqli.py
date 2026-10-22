"""Error-based SQL injection differential.

The check appends a single quote/double quote and looks for a *new* database
error that was absent in the baseline response.  It never uses time-based,
stacked, UNION, or data-modifying payloads, and it does not attempt to extract
data.  An error differential is corroboration; it is only VALIDATED under
CONTROLLED_VALIDATION after independent reproduction.
"""

from __future__ import annotations

import re

from ..net.client import redact_url
from ..validation import CLASS_INJECTION, ValidationEvidence
from .base import CheckContext, CheckFinding, finalize
from .xss import mutate_query, query_parameters

DB_ERROR_PATTERNS = [
    re.compile(r"(?i)you have an error in your sql syntax"),
    re.compile(r"(?i)warning:\s*mysqli?_"),
    re.compile(r"(?i)unclosed quotation mark after the character string"),
    re.compile(r"(?i)\bORA-\d{5}\b"),
    re.compile(r"(?i)pg_query\(\):\s*query failed"),
    re.compile(r"(?i)sqlite3?\.OperationalError"),
    re.compile(r"(?i)syntax error at or near"),
    re.compile(r"(?i)quoted string not properly terminated"),
]

PAYLOADS = ("'", '"', "')")


def _db_error(text: str) -> str | None:
    for pattern in DB_ERROR_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def check_sqli(ctx: CheckContext, urls: list[str]) -> list[CheckFinding]:
    if not ctx.allowed():
        return []
    findings: list[CheckFinding] = []
    for url in urls:
        params = query_parameters(url)
        if not params:
            continue
        baseline = ctx.get(url)
        if not baseline.ok:
            continue
        baseline_body = baseline.text(limit=400_000)
        if _db_error(baseline_body):
            continue  # pre-existing error: cannot attribute it to the probe
        for name in params:
            hits: list[tuple[str, str, str]] = []
            for payload in PAYLOADS:
                probe_url = mutate_query(url, name, payload)
                response = ctx.get(probe_url)
                body = response.text(limit=400_000)
                error = _db_error(body)
                if error:
                    hits.append((payload, probe_url, body))
            if not hits:
                continue
            payload, probe_url, body = hits[0]
            # Reproduce with the same payload before claiming a differential.
            repeat = ctx.get(probe_url)
            repeated = _db_error(repeat.text(limit=400_000)) is not None
            observed = (
                "A database error appeared only when a quote was injected into "
                f"parameter {name!r}: {_db_error(body)!r} (SQL syntax error)."
            )
            evidence = ValidationEvidence(
                endpoint=probe_url,
                method="GET",
                request=f"GET {redact_url(probe_url)} (payload {payload!r})",
                response=body[:400],
                response_headers=dict(repeat.headers),
                status_code=repeat.status,
                reproducible=repeated,
                reproductions=2 if repeated else 1,
                preconditions="Parameter is concatenated into a database query.",
                expected="Quotes are parameterised and do not alter SQL parsing.",
                observed=observed,
                limitations=(
                    "Error text can originate from a WAF, framework, or deliberate "
                    "decoy. No data was read and no database state was changed."
                ),
                validation_method="error-differential",
                environment="Remote HTTP target (authorised scope)",
                independent_sources=["error-differential"],
            )
            findings.append(finalize(ctx, CheckFinding(
                title=f"SQL injection indicator in parameter {name!r}",
                category="sql-injection",
                severity="high",
                confidence="medium",
                description=(
                    "Injecting a quote into this parameter produced a database syntax "
                    "error that was absent from the baseline. This is a strong SQL "
                    "injection indicator requiring parameterisation review."
                ),
                endpoint=redact_url(probe_url),
                evidence=observed,
                remediation=(
                    "Use parameterised queries/prepared statements; never concatenate "
                    "untrusted input into SQL. Suppress database error details and "
                    "add server-side input validation as defence in depth."
                ),
                source="dast.sqli",
            ), evidence, severity="high"))
    return findings
