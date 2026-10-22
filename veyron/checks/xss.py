"""Reflection/encoding checks for cross-site scripting (XSS).

Only a harmless marker is sent: no ``<script>``, no event handlers, no
JavaScript execution.  We test whether HTML metacharacters survive encoding;
that is necessary evidence for XSS, not proof of script execution.  The
finding therefore stays CORROBORATED under SAFE_ACTIVE and can only be
VALIDATED under CONTROLLED_VALIDATION after independent reproduction.
"""

from __future__ import annotations

import html
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..net.client import HttpClient, HttpResponse, redact_url
from ..validation import CLASS_INJECTION, ValidationEvidence
from .base import CheckContext, CheckFinding, finalize


def mutate_query(url: str, name: str, value: str) -> str:
    """Replace the first occurrence of query parameter ``name``."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    out: list[tuple[str, str]] = []
    for key, old in pairs:
        if key == name and not replaced:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, old))
    if not replaced:
        out.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(out), ""))


def query_parameters(url: str) -> list[str]:
    return [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def _is_html(response: HttpResponse) -> bool:
    ctype = response.header("content-type").lower()
    return "html" in ctype or "xml" in ctype


def _excerpt(text: str, marker: str, width: int = 240) -> str:
    index = text.find(marker)
    if index < 0:
        return ""
    start = max(0, index - width // 2)
    return text[start:start + width]


def check_xss(ctx: CheckContext, urls: list[str]) -> list[CheckFinding]:
    if not ctx.allowed():
        return []
    findings: list[CheckFinding] = []
    for url in urls:
        params = query_parameters(url)
        if not params:
            continue
        for name in params:
            token = secrets.token_hex(4)
            marker = f'vynreflect{token}"><vynreflect>'
            probe_url = mutate_query(url, name, marker)
            baseline = ctx.get(url)
            first = ctx.get(probe_url)
            if not (_is_html(first) and first.text().find(marker) >= 0):
                continue
            body = first.text(limit=400_000)
            if html.escape(marker) in body:
                # Correctly encoded in this context: no finding.
                continue
            # Reproduce independently; a single reflection is not enough.
            second = ctx.get(probe_url)
            reproductions = 2 if second.text().find(marker) >= 0 else 1
            observed = (
                "vyn-reflect marker was returned without HTML encoding in an HTML "
                f"response (parameter {name!r}); context excerpt: "
                + _excerpt(body, marker)
            )
            evidence = ValidationEvidence(
                endpoint=probe_url,
                method="GET",
                request=f"GET {redact_url(probe_url)}",
                response=_excerpt(body, marker),
                response_headers=dict(first.headers),
                status_code=first.status,
                reproducible=reproductions >= 2,
                reproductions=reproductions,
                preconditions="Target accepts reflected query parameters; no authentication used.",
                expected="HTML metacharacters are encoded or rejected.",
                observed=observed,
                limitations=(
                    "Reflection proves missing output encoding in this context. "
                    "Executable script context and browser behaviour were not "
                    "tested; do not treat the marker as a weaponised payload."
                ),
                validation_method="reflected-marker",
                environment="Remote HTTP target (authorised scope)",
                independent_sources=["reflection-differential"],
            )
            findings.append(finalize(ctx, CheckFinding(
                title=f"Reflected XSS: unencoded parameter {name!r}",
                category="xss",
                severity="medium",
                confidence="medium",
                description=(
                    "A query parameter is reflected into the HTML response without "
                    "encoding HTML metacharacters. This is consistent with reflected "
                    "cross-site scripting; confirmation requires context review."
                ),
                endpoint=redact_url(probe_url),
                evidence=observed,
                remediation=(
                    "Encode output for the correct HTML/attribute/JavaScript context, "
                    "validate input against an allowlist, and enforce a restrictive "
                    "Content-Security-Policy. Do not rely on blocklists."
                ),
                source="dast.xss",
            ), evidence))
    return findings
