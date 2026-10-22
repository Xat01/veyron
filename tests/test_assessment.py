"""Tests for the authorization model and assessment profiles."""

from __future__ import annotations

import pytest

from veyron.assessment import (
    AssessmentSpec,
    Identity,
    PROFILE_PASSIVE,
    PROFILE_SAFE_ACTIVE,
    PROFILE_CONTROLLED_VALIDATION,
    PROFILE_LAB_EXPLOIT,
    normalize_profile,
)
from veyron.net.proxy import ProxyConfig


def test_profile_normalization():
    assert normalize_profile("passive") == PROFILE_PASSIVE
    assert normalize_profile("safe-active") == PROFILE_SAFE_ACTIVE
    assert normalize_profile("safe_active") == PROFILE_SAFE_ACTIVE
    assert normalize_profile("controlled-validation") == PROFILE_CONTROLLED_VALIDATION
    assert normalize_profile("lab-exploit") == PROFILE_LAB_EXPLOIT
    assert normalize_profile("PASSIVE") == PROFILE_PASSIVE


def test_unknown_profile_raises():
    with pytest.raises(ValueError):
        normalize_profile("aggressive")


def test_passive_profile_defaults():
    spec = AssessmentSpec(authorized_hosts=["localhost:8080"])
    assert spec.profile == PROFILE_PASSIVE
    assert spec.can_send_payloads() is False
    assert spec.can_validate() is False


def test_safe_active_can_send_payloads():
    spec = AssessmentSpec(
        profile=PROFILE_SAFE_ACTIVE,
        authorized_hosts=["localhost:8080"],
    )
    assert spec.can_send_payloads() is True
    assert spec.can_validate() is False


def test_controlled_validation_can_validate():
    spec = AssessmentSpec(
        profile=PROFILE_CONTROLLED_VALIDATION,
        authorized_hosts=["localhost:8080"],
    )
    assert spec.can_send_payloads() is True
    assert spec.can_validate() is True


def test_lab_exploit_requires_lab_environment():
    spec = AssessmentSpec(
        profile=PROFILE_LAB_EXPLOIT,
        authorized_hosts=["localhost:8080"],
    )
    issues = spec.issues()
    assert any("lab_environment" in i for i in issues)

    spec = AssessmentSpec(
        profile=PROFILE_LAB_EXPLOIT,
        authorized_hosts=["localhost:8080"],
        lab_environment=True,
    )
    issues = spec.issues()
    assert not any("lab_environment" in i for i in issues)


def test_no_authorized_hosts_fails():
    spec = AssessmentSpec()
    assert "no authorised hosts" in " ".join(spec.issues())


def test_wildcard_not_accepted():
    spec = AssessmentSpec(authorized_hosts=["*.example.com"])
    assert any("wildcard" in i for i in spec.issues())


def test_bad_scheme_rejected():
    spec = AssessmentSpec(authorized_hosts=["localhost:8080"], permitted_schemes=("ftp",))
    assert any("unsupported scheme" in i for i in spec.issues())


def test_port_range_validation():
    spec = AssessmentSpec(authorized_hosts=["localhost:8080"], permitted_ports=[0, 70000])
    assert any("permitted port" in i for i in spec.issues())


def test_proxy_validation():
    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
        proxy=ProxyConfig(enabled=True),
    )
    assert any("proxy is enabled but has no valid host" in i for i in spec.issues())


def test_callback_url_validation():
    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
        callback_url="ftp://example.com",
    )
    assert any("callback_url must be an http(s) URL" in i for i in spec.issues())

    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
        callback_url="http://169.254.169.254",
    )
    assert any("link-local" in i for i in spec.issues())


def test_identity_sanitization():
    ident = Identity(
        name="test-user",
        headers={"Authorization": "Bearer secret", "Cookie": "session=abc"},
        privilege="high",
    )
    sanitized = ident.sanitized()
    assert sanitized == {"name": "test-user", "privilege": "high"}
    assert "secret" not in str(sanitized)


def test_authorize_requires_explicit_confirmation():
    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
    )
    ok, reasons = spec.authorize(execute=True, confirmation=False)
    assert ok is False
    assert any("explicit authorisation confirmation" in r for r in reasons)

    ok, reasons = spec.authorize(execute=True, confirmation=True)
    assert ok is True


def test_scope_builds_correctly():
    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080", "127.0.0.1:9000"],
        permitted_ports=[8080, 9000],
        permitted_schemes=("http", "https"),
    )
    scope = spec.scope()
    assert "localhost:8080" in scope.allowed_hosts
    assert "127.0.0.1:9000" in scope.allowed_hosts


def test_stop_file_detection(tmp_path):
    stop_file = tmp_path / "stop.txt"
    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
        stop_file=str(stop_file),
    )
    assert spec.stop_requested() is False
    stop_file.write_text("stop")
    assert spec.stop_requested() is True


def test_summary_contains_all_fields():
    spec = AssessmentSpec(
        profile=PROFILE_SAFE_ACTIVE,
        authorized_hosts=["localhost:8080"],
    )
    summary = spec.summary()
    assert summary["profile"] == PROFILE_SAFE_ACTIVE
    assert summary["authorized_hosts"] == ["localhost:8080"]
    assert "proxy_configured" in summary


def test_can_validate_without_hosts_fails():
    spec = AssessmentSpec(
        profile=PROFILE_CONTROLLED_VALIDATION,
    )
    issues = spec.issues()
    assert any("validation profile requires an authorised target" in i for i in issues)


def test_evidence_retention_modes():
    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
        evidence_retention="none",
    )
    assert "unknown evidence retention" not in " ".join(spec.issues())

    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
        evidence_retention="unknown",
    )
    assert any("unknown evidence retention" in i for i in spec.issues())


def test_callback_on_link_local_rejected():
    spec = AssessmentSpec(
        authorized_hosts=["localhost:8080"],
        callback_url="http://[fe80::1]",
    )
    issues = spec.issues()
    assert any("link-local" in i for i in issues)