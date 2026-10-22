"""Evidence-driven validation.

Detection and confirmation are deliberately separate.  A scanner signature, a
reflected marker, or an AI opinion is never enough to mark a finding
``VALIDATED``.  Each vulnerability class declares the evidence it requires;
:func:`evaluate` applies those requirements deterministically and returns an
outcome that explains *why* confirmation was or was not possible.

The engine never invents evidence and never contacts a target.  Callers pass
the evidence they actually observed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .assessment import (
    PROFILE_CONTROLLED_VALIDATION,
    PROFILE_LAB_EXPLOIT,
    PROFILE_PASSIVE,
    PROFILE_SAFE_ACTIVE,
)
from .net.client import redact_headers, redact_url
from .redact import redact_text

VALIDATION_METHODS = {
    "passive-observation",
    "response-differential",
    "reflected-marker",
    "error-differential",
    "control-identity-comparison",
    "callback-observation",
    "harmless-file-canary",
    "static-dataflow",
    "version-correlation",
}

# Vulnerability classes used by the validation engine and reports.  Keep
# these stable: reports and history use them as identifiers.
CLASS_INJECTION = "injection"
CLASS_ACCESS_CONTROL = "broken-access-control"
CLASS_SSRF = "ssrf"
CLASS_FILE_HANDLING = "file-handling"
CLASS_AUTH_SESSION = "authentication-session"
CLASS_DEPENDENCY = "dependency"
CLASS_CONFIGURATION = "configuration"


@dataclass(frozen=True)
class Requirement:
    """Minimum evidence for one class at a given confidence target."""

    allowed_methods: frozenset[str]
    requires_observation: bool = True
    requires_reproduction: bool = False
    requires_control_identity: bool = False
    requires_callback: bool = False
    validates_in_passive: bool = False


REQUIREMENTS: dict[str, Requirement] = {
    CLASS_INJECTION: Requirement(
        frozenset({"response-differential", "reflected-marker", "error-differential"}),
        requires_reproduction=True,
    ),
    CLASS_ACCESS_CONTROL: Requirement(
        frozenset({"control-identity-comparison"}),
        requires_reproduction=True,
        requires_control_identity=True,
    ),
    CLASS_SSRF: Requirement(
        frozenset({"callback-observation"}),
        requires_callback=True,
        requires_reproduction=True,
    ),
    CLASS_FILE_HANDLING: Requirement(
        frozenset({"harmless-file-canary", "response-differential"}),
        requires_reproduction=True,
    ),
    CLASS_AUTH_SESSION: Requirement(
        frozenset({"passive-observation"}), requires_observation=True,
        validates_in_passive=True,
    ),
    CLASS_DEPENDENCY: Requirement(
        frozenset({"version-correlation"}), requires_observation=False,
        requires_reproduction=False,
    ),
    CLASS_CONFIGURATION: Requirement(
        frozenset({"passive-observation"}), requires_observation=True,
        validates_in_passive=True,
    ),
}

# Observed, non-destructive proof that a control was actually exercised.  A
# scanner report alone never satisfies this.
OBSERVABLE_MARKERS = (
    "49",  # template arithmetic result
    "syntax error",
    "traceback",
    "root:x:",
    "vyn-reflect",
    "resolved path",
    "callback",
    "different response",
    "same content",
)

# Evidence excerpts can contain credentials even when the scanner did not
# classify them as secrets.  Redact these shapes unconditionally.
_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{8,}=*"),
    re.compile(r"(?i)\b(session|sessionid|csrf|xsrf|api[_-]?key|token|secret)\s*=\s*[^&\s;\"']+"),
)


def sanitize_excerpt(value: str) -> str:
    """Redact credentials from an evidence excerpt."""
    text = redact_text(value or "")
    for pattern in _CREDENTIAL_PATTERNS:
        text = pattern.sub(lambda m: m.group(0).split(":", 1)[0] + ": [REDACTED]"
                           if ":" in m.group(0) and "=" not in m.group(0)
                           else re.sub(r"=.*", "=[REDACTED]", m.group(0), count=1),
                           text)
    return text


@dataclass
class ValidationEvidence:
    """Sanitised evidence gathered for one finding.

    Request/response bodies are excerpts, not full captures.  Credentials,
    cookies and likely secrets are redacted before the evidence is stored.
    """

    endpoint: str = ""
    method: str = ""
    request: str = ""
    response: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None
    reproducible: bool = False
    reproductions: int = 0
    preconditions: str = ""
    source_location: str = ""
    environment: str = ""
    expected: str = ""
    observed: str = ""
    limitations: str = ""
    validation_method: str = ""
    callback_observed: bool = False
    control_identity_comparison: bool = False
    independent_sources: list[str] = field(default_factory=list)

    def sanitized(self, retention: str = "redacted") -> dict[str, Any]:
        """Return a report-safe representation; never includes credentials."""
        if retention == "none":
            return {"retention": "none", "note": "evidence retention disabled by operator"}
        base: dict[str, Any] = {
            "endpoint": redact_url(self.endpoint),
            "method": self.method,
            "status_code": self.status_code,
            "reproducible": self.reproducible,
            "reproductions": self.reproductions,
            "preconditions": sanitize_excerpt(self.preconditions),
            "source_location": self.source_location,
            "environment": sanitize_excerpt(self.environment),
            "expected": sanitize_excerpt(self.expected),
            "observed": sanitize_excerpt(self.observed),
            "limitations": sanitize_excerpt(self.limitations),
            "validation_method": self.validation_method,
            "callback_observed": self.callback_observed,
            "control_identity_comparison": self.control_identity_comparison,
            "independent_sources": list(self.independent_sources),
            "retention": retention,
        }
        if retention in {"redacted", "full"}:
            base["request"] = sanitize_excerpt(self.request)
            base["response"] = sanitize_excerpt(self.response)
            base["response_headers"] = redact_headers(self.response_headers)
        return base


@dataclass
class ValidationOutcome:
    status: str
    reason: str
    missing: list[str] = field(default_factory=list)
    confidence: str = "low"

    @property
    def validated(self) -> bool:
        return self.status == "VALIDATED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "missing": list(self.missing),
            "confidence": self.confidence,
        }


def _class_key(value: str) -> str:
    raw = (value or "").strip().lower()
    aliases = {
        "sql-injection": CLASS_INJECTION,
        "sqli": CLASS_INJECTION,
        "xss": CLASS_INJECTION,
        "cross-site-scripting": CLASS_INJECTION,
        "command-injection": CLASS_INJECTION,
        "ssti": CLASS_INJECTION,
        "path-traversal": CLASS_INJECTION,
        "deserialization": CLASS_INJECTION,
        "access-control": CLASS_ACCESS_CONTROL,
        "idor": CLASS_ACCESS_CONTROL,
        "ssrf": CLASS_SSRF,
        "file-upload": CLASS_FILE_HANDLING,
        "authentication": CLASS_AUTH_SESSION,
        "session": CLASS_AUTH_SESSION,
        "dependency": CLASS_DEPENDENCY,
        "configuration": CLASS_CONFIGURATION,
    }
    return aliases.get(raw, raw)


def class_requirement(category: str) -> Requirement:
    key = _class_key(category)
    return REQUIREMENTS.get(key, Requirement(frozenset(VALIDATION_METHODS)))


def evaluate(
    *,
    category: str,
    evidence: ValidationEvidence,
    profile: str,
    authorized: bool,
    in_scope: bool,
    severity: str = "unknown",
) -> ValidationOutcome:
    """Decide the strongest defensible validation status for one finding.

    Order of precedence matters: an authorization or scope failure is never
    presented as a negative result about the vulnerability itself.
    """
    requirement = class_requirement(category)

    if not authorized:
        return ValidationOutcome(
            "VALIDATION_NOT_PERMITTED",
            "active validation was not explicitly authorised for this assessment",
            ["explicit authorisation"],
        )
    if not in_scope:
        return ValidationOutcome(
            "BLOCKED_BY_SCOPE",
            "the endpoint is outside the declared assessment scope",
            ["in-scope endpoint"],
        )
    if profile == PROFILE_PASSIVE and not requirement.validates_in_passive:
        return ValidationOutcome(
            "VALIDATION_NOT_PERMITTED",
            "PASSIVE profile does not permit vulnerability-specific validation",
            ["SAFE_ACTIVE or CONTROLLED_VALIDATION profile"],
        )
    if profile == PROFILE_SAFE_ACTIVE and requirement.requires_reproduction:
        # Safe-active may *corroborate* with a bounded differential, but it
        # cannot produce the independent reproductions required to validate.
        corroborated = (
            bool(evidence.observed.strip())
            and bool(evidence.expected.strip())
            and evidence.validation_method in requirement.allowed_methods
            and evidence.reproductions >= 1
        )
        if corroborated:
            return ValidationOutcome(
                "CORROBORATED",
                "bounded safe-active differential observed; independent "
                "reproduction under CONTROLLED_VALIDATION is still required",
                ["CONTROLLED_VALIDATION profile", "a second independent reproduction"],
            )
        return ValidationOutcome(
            "REQUIRES_MANUAL_REVIEW",
            "SAFE_ACTIVE evidence is insufficient for this class; "
            "controlled validation is required",
            ["CONTROLLED_VALIDATION profile", "an observed differential"],
        )
    if profile not in {
        PROFILE_PASSIVE,
        PROFILE_SAFE_ACTIVE,
        PROFILE_CONTROLLED_VALIDATION,
        PROFILE_LAB_EXPLOIT,
    }:
        return ValidationOutcome(
            "INCONCLUSIVE", f"unknown profile {profile!r}", ["a supported profile"]
        )

    missing: list[str] = []
    # An advisory correlation is never exploitability, regardless of profile.
    if _class_key(category) == CLASS_DEPENDENCY:
        return ValidationOutcome(
            "ANALYSED",
            "advisory correlation does not demonstrate exploitability; "
            "runtime reachability and preconditions require separate evidence",
            ["demonstrated reachability of the vulnerable code path"],
        )
    if requirement.requires_observation:
        if not evidence.observed.strip():
            missing.append("observed behaviour")
        if not evidence.expected.strip():
            missing.append("expected secure behaviour")
    if evidence.validation_method not in requirement.allowed_methods:
        missing.append(
            "an allowed validation method ("
            + ", ".join(sorted(requirement.allowed_methods))
            + ")"
        )
    if requirement.requires_reproduction:
        if not evidence.reproducible or evidence.reproductions < 2:
            missing.append("reproduction on at least two independent attempts")
    if requirement.requires_control_identity and not evidence.control_identity_comparison:
        missing.append("a low-privilege versus higher-privilege identity comparison")
    if requirement.requires_callback and not evidence.callback_observed:
        missing.append("an observed call-back to operator-controlled infrastructure")

    if missing:
        # Dependency findings can never be promoted by version alone: an
        # advisory is correlation, not exploitability.
        if _class_key(category) == CLASS_DEPENDENCY:
            return ValidationOutcome(
                "ANALYSED",
                "advisory correlation does not demonstrate exploitability",
                missing,
            )
        return ValidationOutcome(
            "INCONCLUSIVE",
            "validation evidence is incomplete",
            missing,
        )

    # Even complete evidence for an actively probed class needs an observed
    # differential/marker; refuse narrative-only confirmation.  Passive
    # observations (cookie flags, dependency versions) are exempt.
    blob = " ".join(
        [evidence.observed, evidence.expected, evidence.response, evidence.request]
    ).lower()
    marker_required = _class_key(category) in {
        CLASS_INJECTION,
        CLASS_ACCESS_CONTROL,
        CLASS_SSRF,
        CLASS_FILE_HANDLING,
    }
    if marker_required and not any(marker in blob for marker in OBSERVABLE_MARKERS):
        return ValidationOutcome(
            "REQUIRES_MANUAL_REVIEW",
            "evidence does not contain an observable differential or marker",
            ["a concrete observed differential or marker"],
        )

    confidence = "high" if len(set(evidence.independent_sources)) > 1 else "medium"
    if severity in {"critical", "high"} and confidence == "medium":
        confidence = "medium"
    return ValidationOutcome(
        "VALIDATED",
        "evidence requirements satisfied for this class; "
        f"method={evidence.validation_method}, reproductions={evidence.reproductions}",
        confidence=confidence,
    )


def apply_outcome(finding: Any, outcome: ValidationOutcome, *, actor: str = "validation-engine") -> bool:
    """Apply a validation outcome to a Finding or a DAST finding dict.

    Returns True when the state changed.  The caller's evidence is expected to
    already be attached to the finding; this function only enforces the
    lifecycle and records the reason.
    """
    current = (
        finding.validation_status
        if hasattr(finding, "validation_status")
        else finding.get("validation_status", "DETECTED")
    )
    if current == outcome.status:
        return False
    if hasattr(finding, "transition"):
        return bool(finding.transition(outcome.status, outcome.reason, actor=actor))
    if isinstance(finding, dict):
        # Dict findings (DAST) cannot preserve a full transition history; only
        # ever move forward through defensible states.
        allowed_from = {
            "DETECTED": {"ANALYSED", "CORROBORATED", "VALIDATED", "INCONCLUSIVE",
                         "FALSE_POSITIVE", "BLOCKED_BY_SCOPE",
                         "VALIDATION_NOT_PERMITTED", "REQUIRES_MANUAL_REVIEW"},
            "ANALYSED": {"CORROBORATED", "VALIDATED", "INCONCLUSIVE",
                         "REQUIRES_MANUAL_REVIEW", "BLOCKED_BY_SCOPE"},
            "CORROBORATED": {"VALIDATED", "INCONCLUSIVE", "REQUIRES_MANUAL_REVIEW"},
        }
        if outcome.status not in allowed_from.get(current, set()):
            return False
        finding["validation_status"] = outcome.status
        finding.setdefault("validation_history", []).append(
            {"state": outcome.status, "reason": outcome.reason, "actor": actor}
        )
        return True
    return False


def correlate_confidence(sources: Iterable[str], *, independent_evidence: int = 0) -> str:
    """Confidence from independent provenance, never from duplicate signatures.

    Severity is intentionally not an input: a critical scanner label with one
    source is still low-confidence.
    """
    unique = {s for s in sources if s}
    if len(unique) >= 2 and independent_evidence >= 1:
        return "high"
    if unique or independent_evidence:
        return "medium"
    return "low"
