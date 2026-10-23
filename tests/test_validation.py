"""Validation engine: separation of detection, corroboration and confirmation."""

from __future__ import annotations

from veyron.assessment import (
    PROFILE_CONTROLLED_VALIDATION,
    PROFILE_PASSIVE,
    PROFILE_SAFE_ACTIVE,
)
from veyron.finding import Finding, stable_finding_id
from veyron.validation import (
    CLASS_ACCESS_CONTROL,
    CLASS_DEPENDENCY,
    CLASS_INJECTION,
    CLASS_PROMPT_INJECTION,
    ValidationEvidence,
    apply_outcome,
    correlate_confidence,
    evaluate,
)


def evidence(**kw) -> ValidationEvidence:
    base = dict(
        endpoint="http://127.0.0.1:8080/search?q=vyn-test",
        method="GET",
        request="GET /search?q=vyn-test",
        response="<html><body>vyn-test</body></html>",
        status_code=200,
        reproducible=True,
        reproductions=2,
        preconditions="test account only",
        expected="marker is HTML-encoded",
        observed="vyn-reflect marker returned raw in HTML context",
        validation_method="reflected-marker",
        independent_sources=["scanner-xss", "manual-differential"],
    )
    base.update(kw)
    return ValidationEvidence(**base)


def test_passive_cannot_validate_injection():
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(),
        profile=PROFILE_PASSIVE,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "VALIDATION_NOT_PERMITTED"
    assert outcome.validated is False


def test_unauthorized_is_not_a_negative_result():
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=False,
        in_scope=True,
    )
    assert outcome.status == "VALIDATION_NOT_PERMITTED"


def test_out_of_scope_is_blocked():
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=False,
    )
    assert outcome.status == "BLOCKED_BY_SCOPE"


def test_safe_active_corroborates_but_does_not_validate():
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(reproductions=1),
        profile=PROFILE_SAFE_ACTIVE,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "CORROBORATED"


def test_controlled_validation_with_full_evidence_validates():
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "VALIDATED"
    assert outcome.confidence in {"medium", "high"}


def test_single_reproduction_is_not_enough():
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(reproducible=False, reproductions=1),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "INCONCLUSIVE"
    assert any("two independent" in m for m in outcome.missing)


def test_missing_observation_is_not_enough():
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(observed="", expected=""),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "INCONCLUSIVE"


def test_dependency_advisory_never_validates():
    outcome = evaluate(
        category=CLASS_DEPENDENCY,
        evidence=ValidationEvidence(
            endpoint="requirements.txt",
            validation_method="version-correlation",
            observed="version 1.2.3 is affected by OSV-2024-1",
            expected="version 1.2.4",
        ),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "ANALYSED"


def test_access_control_requires_identity_comparison():
    outcome = evaluate(
        category=CLASS_ACCESS_CONTROL,
        evidence=evidence(
            validation_method="control-identity-comparison",
            control_identity_comparison=False,
        ),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "INCONCLUSIVE"


def test_access_control_with_identity_comparison_validates():
    outcome = evaluate(
        category=CLASS_ACCESS_CONTROL,
        evidence=evidence(
            validation_method="control-identity-comparison",
            control_identity_comparison=True,
            observed="low privilege identity received another user's record "
                     "(different response from the authorized higher-privilege identity)",
        ),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "VALIDATED"


def test_dict_finding_transition():
    finding = {"validation_status": "DETECTED"}
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert apply_outcome(finding, outcome) is True
    assert finding["validation_status"] == "VALIDATED"
    assert finding["validation_history"][0]["actor"] == "validation-engine"


def test_finding_transition_and_history():
    finding = Finding(
        id=stable_finding_id("dast.xss", "reflection", "http://x", None, "Reflected XSS"),
        title="Reflected XSS",
        description="marker reflected raw",
        category="xss",
        severity="high",
        confidence="medium",
        validation_status="CORROBORATED",
        source="dast.xss",
        file_path=None,
        line=None,
        evidence="vyn-reflect",
    )
    outcome = evaluate(
        category=CLASS_INJECTION,
        evidence=evidence(),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert apply_outcome(finding, outcome) is True
    assert finding.validation_status == "VALIDATED"
    assert finding.validation_history[-1]["state"] == "VALIDATED"


def test_secret_values_are_redacted_from_evidence():
    e = ValidationEvidence(
        endpoint="http://example.test/?token=abc123456",
        request="Authorization: Bearer abc123456789012345",
        response="session=abcdef123456",
        response_headers={"Set-Cookie": "session=abc; HttpOnly"},
        observed="vyn-reflect token=secretvalue123",
    )
    safe = e.sanitized("redacted")
    blob = str(safe)
    assert "abc123456789012345" not in blob
    assert "secretvalue123" not in blob
    assert "***" in safe["response_headers"]["Set-Cookie"]


def test_confidence_uses_independent_sources():
    assert correlate_confidence([]) == "low"
    assert correlate_confidence(["scanner"]) == "medium"
    assert correlate_confidence(["scanner", "manual"], independent_evidence=1) == "high"

def test_prompt_injection_requires_observed_instruction_following():
    outcome = evaluate(
        category=CLASS_PROMPT_INJECTION,
        evidence=ValidationEvidence(
            endpoint="http://127.0.0.1:8080/chat",
            method="POST",
            request="POST /chat",
            response='{"reply":"vynpiTOKEN"}',
            status_code=200,
            reproducible=True,
            reproductions=2,
            expected="model treats user text as data",
            observed="instruction followed: model returned the injected canary",
            validation_method="prompt-instruction-following",
            independent_sources=["instruction-following-canary"],
        ),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "VALIDATED"
    assert outcome.validated is True


def test_prompt_injection_narrative_only_is_manual_review():
    outcome = evaluate(
        category=CLASS_PROMPT_INJECTION,
        evidence=ValidationEvidence(
            endpoint="http://127.0.0.1:8080/chat",
            method="POST",
            request="POST /chat",
            response="the assistant might be manipulable",
            status_code=200,
            reproducible=True,
            reproductions=2,
            expected="model treats user text as data",
            observed="looks risky",
            validation_method="prompt-instruction-following",
            independent_sources=["opinion"],
        ),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "REQUIRES_MANUAL_REVIEW"


def test_prompt_injection_single_reproduction_is_not_enough():
    outcome = evaluate(
        category=CLASS_PROMPT_INJECTION,
        evidence=ValidationEvidence(
            endpoint="http://127.0.0.1:8080/chat",
            method="POST",
            request="POST /chat",
            response='{"reply":"vynpiTOKEN"}',
            status_code=200,
            reproducible=False,
            reproductions=1,
            expected="model treats user text as data",
            observed="instruction followed: canary returned once",
            validation_method="prompt-instruction-following",
            independent_sources=["instruction-following-canary"],
        ),
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized=True,
        in_scope=True,
    )
    assert outcome.status == "INCONCLUSIVE"
