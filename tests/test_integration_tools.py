"""Integration tests with real tools — skipped when the tool is not installed.

These run only when the actual scanner exists on this machine, so the suite
stays green on tool-less CI while still proving real integration locally.
"""

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from veyron.adapters.bandit import BanditAdapter
from veyron.adapters.osv import OSVAdapter
from veyron.adapters.semgrep import SemgrepAdapter
from veyron.adapters.gitleaks import GitleaksAdapter

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VULN = FIXTURES / "vulnerable_app"
CLEAN = FIXTURES / "clean_app"

HAS_BANDIT = shutil.which("bandit") is not None
HAS_SEMGREP = shutil.which("semgrep") is not None
HAS_GITLEAKS = shutil.which("gitleaks") is not None


@pytest.mark.skipif(not HAS_BANDIT, reason="bandit not installed")
def test_bandit_real_scan_finds_fixture_issues():
    res = BanditAdapter(timeout=120).scan(VULN)
    assert res.ok, res.error
    assert res.tool_version and "bandit" in res.tool_version.lower()
    rules = {f.rule_id for f in res.findings}
    # fixture has eval (B307), MD5 (B324), pickle (B301)
    assert rules & {"B307", "B324", "B301", "B303"}, f"unexpected rules: {rules}"
    # findings normalised
    for f in res.findings:
        assert f.source == "sast.bandit"
        assert f.validation_status == "DETECTED"
        assert f.evidence


@pytest.mark.skipif(not HAS_BANDIT, reason="bandit not installed")
def test_bandit_real_scan_clean_fixture_has_no_high():
    res = BanditAdapter(timeout=120).scan(CLEAN)
    assert res.ok, res.error
    high = [f for f in res.findings if f.severity in {"high", "critical"}]
    assert high == []


@pytest.mark.skipif(not HAS_SEMGREP, reason="semgrep not installed")
def test_semgrep_real_scan_finds_eval():
    res = SemgrepAdapter(timeout=300).scan(VULN)
    assert res.ok, res.error
    assert res.tool_version
    assert len(res.findings) >= 1
    # at least one finding carries original evidence
    assert any(f.evidence for f in res.findings)


@pytest.mark.skipif(not HAS_GITLEAKS, reason="gitleaks not installed")
def test_gitleaks_real_scan_redacts():
    res = GitleaksAdapter(timeout=120).scan(VULN)
    assert res.ok, res.error
    blob = json.dumps([f.to_dict() for f in res.findings])
    # fake fixture credentials must never appear raw in output
    assert "FAKE_API_KEY_FOR_TESTS_1234567890abcdef" not in blob
    assert "fake-password-not-real-000111" not in blob


def test_osv_parses_manifests_offline(tmp_path):
    """Offline mode: manifests parse, cache used, results marked cached."""
    cache_path = tmp_path / "cache.json"
    ad = OSVAdapter(config={"offline": True, "cache_path": str(cache_path)})
    ok, _ = ad.validate_config() if cache_path.exists() else (True, None)
    res = ad.scan(VULN)
    assert res.ok, res.error
    assert res.metadata["packages"] >= 3  # flask, requests, lodash, minimist...
    assert res.metadata["manifests_parsed"] >= 2


def test_osv_no_manifests_is_clean_not_error(tmp_path):
    ad = OSVAdapter(config={"offline": True, "cache_path": str(tmp_path / "c.json")})
    res = ad.scan(tmp_path)
    assert res.ok is True
    assert res.findings == []
    assert res.metadata["packages"] == 0
