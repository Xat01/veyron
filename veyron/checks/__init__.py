"""Web vulnerability checks.

The runner is intentionally small: each check is an independent function that
takes a :class:`CheckContext` and returns evidence-bearing findings.  Failures
in one check do not abort the assessment, and every request still passes
through the shared client's scope, budget and proxy controls.
"""

from __future__ import annotations

from typing import Any

from .access_control import check_access_control
from .base import CallbackVerifier, CheckContext, CheckFinding
from .path_traversal import check_path_traversal
from .sqli import check_sqli
from .ssrf import check_ssrf
from .ssti import check_ssti
from .xss import check_xss

__all__ = [
    "CallbackVerifier",
    "CheckContext",
    "CheckFinding",
    "run_checks",
]


def run_checks(ctx: CheckContext, urls: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """Run profile-appropriate checks and return (findings, errors)."""
    if not ctx.allowed():
        return [], []
    findings: list[CheckFinding] = []
    errors: list[str] = []

    # De-duplicate URLs while preserving order; limit parameter explosion.
    unique_urls: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    unique_urls = unique_urls[:50]

    for label, func in (
        ("xss", lambda: check_xss(ctx, unique_urls)),
        ("sqli", lambda: check_sqli(ctx, unique_urls)),
        ("ssti", lambda: check_ssti(ctx, unique_urls)),
        ("path-traversal", lambda: check_path_traversal(ctx, unique_urls)),
        ("ssrf", lambda: check_ssrf(ctx, unique_urls)),
        ("access-control", lambda: check_access_control(ctx)),
    ):
        try:
            findings.extend(func())
        except Exception as exc:  # noqa: BLE001 - one check must not abort the run
            errors.append(f"{label} check failed: {type(exc).__name__}: {exc}")

    # Deduplicate identical findings (same title + endpoint).
    out: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.title, finding.endpoint)
        if key in seen_findings:
            continue
        seen_findings.add(key)
        out.append(finding.to_dict())
    return out, errors
