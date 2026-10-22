"""SSRF validation using operator-controlled callback infrastructure.

The only destinations inserted into parameters are the operator's own
callback URLs.  The check never targets cloud metadata addresses, internal
networks, or unrelated services.  A finding is only created when the target
actually calls back with a unique token.
"""

from __future__ import annotations

import secrets
import time

from ..assessment import PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT
from ..net.client import redact_url
from ..validation import CLASS_SSRF, ValidationEvidence
from .base import CheckContext, CheckFinding, finalize
from .xss import mutate_query, query_parameters


def check_ssrf(ctx: CheckContext, urls: list[str], *, wait_seconds: float = 1.0) -> list[CheckFinding]:
    if ctx.profile not in {PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT}:
        return []
    callback = ctx.callback
    if callback is None:
        return []
    findings: list[CheckFinding] = []
    for url in urls:
        params = query_parameters(url)
        if not params:
            continue
        for name in params:
            token = secrets.token_hex(6)
            callback_url = callback.url_for(token) if hasattr(callback, "url_for") else callback.url
            probe_url = mutate_query(url, name, callback_url)
            before = len(callback.hits())
            response = ctx.get(probe_url)
            # Give the target a bounded window to make the outbound call.
            deadline = time.monotonic() + wait_seconds
            hit = False
            while time.monotonic() < deadline:
                if token in callback.hits()[before:]:
                    hit = True
                    break
                time.sleep(0.05)
            if not hit:
                continue
            # Second independent reproduction with a fresh token.
            token2 = secrets.token_hex(6)
            callback_url2 = (
                callback.url_for(token2) if hasattr(callback, "url_for") else callback.url
            )
            before2 = len(callback.hits())
            ctx.get(mutate_query(url, name, callback_url2))
            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline:
                if token2 in callback.hits()[before2:]:
                    break
                time.sleep(0.05)
            reproductions = 1 + int(token2 in callback.hits()[before2:])
            observed = (
                "The target server made an outbound callback to operator-controlled "
                f"infrastructure for parameter {name!r}; callback token observed "
                f"({reproductions} independent reproduction(s))."
            )
            evidence = ValidationEvidence(
                endpoint=probe_url,
                method="GET",
                request=f"GET {redact_url(probe_url)}",
                response=f"HTTP {response.status}; callback token observed: {hit}",
                response_headers=dict(response.headers),
                status_code=response.status,
                reproducible=reproductions >= 2,
                reproductions=reproductions,
                preconditions=(
                    "The application accepts a URL-like value and fetches it "
                    "server-side; operator-controlled callback infrastructure is available."
                ),
                expected="User-supplied URLs are rejected or restricted to an allowlist.",
                observed=observed,
                limitations=(
                    "The callback proves server-side request capability, not which "
                    "internal service is reachable. Cloud metadata and internal "
                    "networks were deliberately not tested."
                ),
                validation_method="callback-observation",
                callback_observed=True,
                environment="Authorised test environment",
                independent_sources=["callback", "reproduction"],
            )
            findings.append(finalize(ctx, CheckFinding(
                title=f"Server-side request forgery in parameter {name!r}",
                category="ssrf",
                severity="high",
                confidence="high",
                description=(
                    "A URL-like parameter caused the target server to contact "
                    "operator-controlled callback infrastructure. This demonstrates "
                    "server-side request capability."
                ),
                endpoint=redact_url(probe_url),
                evidence=observed,
                remediation=(
                    "Do not fetch arbitrary user-supplied URLs. Use a strict allowlist "
                    "of schemes/hosts/ports, block link-local and metadata ranges at "
                    "the network layer, require authentication, and disable redirects."
                ),
                source="dast.ssrf",
            ), evidence, severity="high"))
    return findings
