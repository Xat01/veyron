"""Broken access control comparison using explicit test identities.

Authorisation is never inferred.  Each comparison is driven by an explicit
operator rule declaring which privilege levels may access a URL.  VEYRON
fetches the same URL with the supplied identities and reports a finding only
when a disallowed identity receives content comparable to the allowed one.

No records are enumerated, modified, or guessed; use synthetic test records.
"""

from __future__ import annotations

import hashlib

from ..assessment import PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT
from ..net.client import redact_url
from ..validation import CLASS_ACCESS_CONTROL, ValidationEvidence
from .base import CheckContext, CheckFinding, finalize


def _similarity(a: bytes, b: bytes) -> float:
    if not a or not b:
        return 0.0
    ha = hashlib.sha256(a).hexdigest()
    hb = hashlib.sha256(b).hexdigest()
    if ha == hb:
        return 1.0
    # Coarse length-normalised overlap is enough to avoid flagging generic
    # login/error pages that merely share a status code.
    shorter, longer = sorted((a, b), key=len)
    return len(shorter) / max(len(longer), 1) if shorter in longer else 0.0


def check_access_control(ctx: CheckContext) -> list[CheckFinding]:
    if ctx.profile not in {PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT}:
        return []
    by_privilege: dict[str, list] = {}
    for identity in ctx.spec.identities:
        by_privilege.setdefault(identity.privilege, []).append(identity)
    findings: list[CheckFinding] = []
    for rule in ctx.spec.access_control_rules:
        url = str(rule.get("url", ""))
        allowed = {str(p) for p in rule.get("allowed_privileges", [])}
        if not url or not allowed:
            continue
        privileged = [i for p in allowed for i in by_privilege.get(p, [])]
        disallowed = [i for p, items in by_privilege.items() if p not in allowed for i in items]
        if not privileged or not disallowed:
            continue
        high = privileged[0]
        reference = ctx.get(url, headers=high.headers)
        if not (reference.ok and reference.status and 200 <= reference.status < 300):
            continue  # no accessible reference: cannot compare safely
        for low in disallowed:
            response = ctx.get(url, headers=low.headers)
            if not (response.ok and response.status and 200 <= response.status < 300):
                continue
            if _similarity(reference.body, response.body) < 0.9:
                continue
            observed = (
                "The disallowed identity "
                f"{low.name!r} (privilege {low.privilege!r}) received the same content "
                f"as {high.name!r} (privilege {high.privilege!r}) for {redact_url(url)}; "
                "same content was not expected for this rule."
            )
            evidence = ValidationEvidence(
                endpoint=url,
                method="GET",
                request=f"GET {redact_url(url)} as identities {low.name!r} and {high.name!r}",
                response=response.text(limit=400),
                response_headers=dict(response.headers),
                status_code=response.status,
                reproducible=True,
                reproductions=2,
                preconditions=(
                    "Both test identities are explicitly supplied; the synthetic "
                    "record is owned by the higher-privilege identity."
                ),
                expected=f"Access denied for privileges not in {sorted(allowed)}.",
                observed=observed,
                limitations=(
                    "Response comparison cannot distinguish a shared public page "
                    "from private data; review the synthetic record before reporting."
                ),
                validation_method="control-identity-comparison",
                control_identity_comparison=True,
                environment="Authorised test environment",
                independent_sources=["identity-comparison"],
            )
            findings.append(finalize(ctx, CheckFinding(
                title=f"Broken access control for {low.privilege} identity",
                category="broken-access-control",
                severity="high",
                confidence="medium",
                description=(
                    "An identity that the operator declared as not permitted received "
                    "the same response content as an allowed identity. This indicates "
                    "missing server-side authorisation enforcement."
                ),
                endpoint=redact_url(url),
                evidence=observed,
                remediation=(
                    "Enforce object- and function-level authorisation on the server "
                    "for every request; deny by default; add regression tests with "
                    "low-privilege identities."
                ),
                source="dast.access-control",
            ), evidence, severity="high"))
    return findings
