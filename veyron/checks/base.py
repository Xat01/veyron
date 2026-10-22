"""Modular, safety-gated web checks.

Each check receives an explicit :class:`CheckContext` containing the shared
HTTP client (and therefore the enforced scope, proxy and budget) and returns
evidence-bearing finding dictionaries.  Checks never open sockets themselves
and never decide whether they are authorised: the caller supplies both the
profile and the scope, and the client refuses out-of-scope destinations.

Profiles:
* PASSIVE checks observe only.
* SAFE_ACTIVE checks send bounded, harmless differential markers.
* CONTROLLED_VALIDATION checks may reproduce a differential and use
  operator-controlled callbacks/test identities.
* LAB_EXPLOIT is reserved for isolated environments.
"""

from __future__ import annotations

import hashlib

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from ..assessment import (
    AssessmentSpec,
    PROFILE_CONTROLLED_VALIDATION,
    PROFILE_LAB_EXPLOIT,
    PROFILE_SAFE_ACTIVE,
)
from ..net.client import HttpClient, HttpResponse, redact_url
from ..validation import (
    CLASS_ACCESS_CONTROL,
    CLASS_FILE_HANDLING,
    CLASS_INJECTION,
    CLASS_SSRF,
    ValidationEvidence,
    apply_outcome,
    evaluate,
)


class CallbackVerifier(Protocol):
    """Operator-controlled callback infrastructure."""

    @property
    def url(self) -> str: ...

    def hits(self) -> list[str]: ...


@dataclass
class CheckContext:
    client: HttpClient
    spec: AssessmentSpec
    callback: CallbackVerifier | None = None
    # Optional assessment-level budget/stop hooks owned by the caller.
    consume: Callable[[], bool] | None = None
    stop: Callable[[], bool] | None = None

    @property
    def profile(self) -> str:
        return self.spec.profile

    def allowed(self) -> bool:
        return self.spec.profile in {
            PROFILE_SAFE_ACTIVE,
            PROFILE_CONTROLLED_VALIDATION,
            PROFILE_LAB_EXPLOIT,
        }

    def can_validate(self) -> bool:
        return self.spec.profile in {PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT}

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpResponse:
        """Budget-aware GET through the shared client."""
        if self.stop is not None and self.stop():
            return HttpResponse(ok=False, url=url, error="assessment stopped", error_kind="cancelled")
        if self.consume is not None and not self.consume():
            return HttpResponse(
                ok=False, url=url, error="request budget exhausted", error_kind="budget"
            )
        return self.client.get(url, headers=headers)


@dataclass
class CheckFinding:
    """Normalised shape shared by the DAST report and the Finding model."""

    title: str
    category: str
    severity: str
    confidence: str
    description: str
    endpoint: str
    evidence: str
    remediation: str
    validation_status: str = "DETECTED"
    validation_evidence: dict[str, Any] = field(default_factory=dict)
    preconditions: str = ""
    limitations: str = ""
    source: str = "dast.webcheck"

    def to_dict(self) -> dict[str, Any]:
        digest = hashlib.sha256(
            f"{self.source}|{self.category}|{self.endpoint}|{self.title}".encode("utf-8")
        ).hexdigest()[:12].upper()
        return {
            "id": f"VYN-{digest}",
            "title": self.title,
            "detail": self.description,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "url": self.endpoint,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "validation_status": self.validation_status,
            "validation_evidence": self.validation_evidence,
            "asset": redact_url(self.endpoint),
            "expected_behavior": self.validation_evidence.get("expected", ""),
            "observed_behavior": self.validation_evidence.get("observed", ""),
            "impact": self.description,
            "preconditions": self.validation_evidence.get("preconditions", self.preconditions),
            "reproduction": self.validation_evidence.get("request", ""),
            "verification": (
                "Re-run the same harmless request with the same marker and confirm the "
                "response is now encoded/rejected; add a regression test."
            ),
            "limitations": self.limitations or self.validation_evidence.get("limitations", ""),
            "source": self.source,
            "tool": "veyron-dast",
        }


def finalize(ctx: CheckContext, finding: CheckFinding, evidence: ValidationEvidence,
             *, severity: str | None = None) -> CheckFinding:
    """Attach sanitised evidence and let the validation engine set the state."""
    safe = evidence.sanitized(ctx.spec.evidence_retention)
    finding.validation_evidence = safe
    finding.evidence = (
        safe.get("observed")
        or safe.get("response", "")[:500]
        or finding.evidence
    )
    outcome = evaluate(
        category=finding.category,
        evidence=evidence,
        profile=ctx.profile,
        authorized=True,
        in_scope=True,
        severity=severity or finding.severity,
    )
    finding.validation_status = outcome.status
    finding.confidence = outcome.confidence if outcome.confidence != "low" else finding.confidence
    safe["engine"] = outcome.to_dict()
    finding.validation_evidence = safe
    return finding


def _can_read(response: HttpResponse) -> bool:
    return response.ok and response.status is not None and 200 <= response.status < 300


__all__ = [
    "AssessmentSpec",
    "CheckContext",
    "CheckFinding",
    "CallbackVerifier",
    "CLASS_ACCESS_CONTROL",
    "CLASS_FILE_HANDLING",
    "CLASS_INJECTION",
    "CLASS_SSRF",
    "apply_outcome",
    "evaluate",
    "finalize",
    "_can_read",
]
