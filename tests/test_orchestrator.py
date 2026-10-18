"""Orchestrator end-to-end behaviour with deterministic mocked adapters."""

import json
from pathlib import Path

import pytest

import veyron.orchestrator as orch_mod
from veyron.adapters.base import ScanResult
from veyron.config import Config
from veyron.finding import stable_finding_id
from veyron.orchestrator import Orchestrator

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def cfg(tmp_path):
    c = Config()
    c.reports_dir = tmp_path / "reports"
    c.history_path = tmp_path / "history.jsonl"
    c.ai.enabled = False  # deterministic by default
    return c


def fake_finding(rule="rule.a", path="app.py", line=1, source="sast.semgrep", title="t"):
    from veyron.finding import Finding
    return Finding(
        id=stable_finding_id(source, rule, path, line, title),
        title=title, description="d", category="c", severity="high",
        confidence="medium", validation_status="DETECTED",
        source=source, file_path=path, line=line, evidence="ev", rule_id=rule,
    )


class FakeAdapter:
    name = "fake"
    kind = "sast"

    def __init__(self, result=None, unavailable_reason=None):
        self._result = result
        self._reason = unavailable_reason

    def validate_config(self):
        if self._reason:
            return False, self._reason
        return True, None

    def version(self):
        return "fake-1.0"

    def scan(self, root, files=None):
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def patch_adapters(monkeypatch, mapping: dict):
    monkeypatch.setattr(orch_mod, "build_adapters", lambda cfg: mapping)


# -- happy path ----------------------------------------------------------------

def test_full_run_produces_reports_and_history(cfg, monkeypatch, tmp_path):
    ok = ScanResult(scanner="semgrep", ok=True, findings=[fake_finding()],
                    tool_version="1.0", duration_seconds=0.1)
    patch_adapters(monkeypatch, {"semgrep": FakeAdapter(ok)})
    orch = Orchestrator(cfg)
    outcome = orch.run(FIXTURES / "vulnerable_app")
    assert outcome.findings and outcome.findings[0].source == "sast.semgrep"
    assert set(outcome.reports) == {"markdown", "json", "sarif"}
    for p in outcome.reports.values():
        assert p.exists()
    # history appended
    entries = [json.loads(x) for x in cfg.history_path.read_text().splitlines() if x.strip()]
    assert entries[-1]["assessment_id"] == outcome.assessment_id
    # report context agrees with findings
    assert outcome.context["severity_counts"] == {"high": 1}


# -- scanner failure honesty ----------------------------------------------------

def test_failed_scanner_reported_not_silent(cfg, monkeypatch):
    fail = ScanResult(scanner="bandit", ok=False, failure_kind="missing_executable",
                      error="bandit not found")
    patch_adapters(monkeypatch, {"bandit": FakeAdapter(fail)})
    outcome = Orchestrator(cfg).run(FIXTURES / "vulnerable_app")
    assert any(not t["ok"] for t in outcome.scan_results)
    assert outcome.context["coverage_warning"]
    assert any("bandit" in lim for lim in outcome.context["limitations"])


def test_unavailable_adapter_short_circuits(cfg, monkeypatch):
    patch_adapters(monkeypatch, {"gitleaks": FakeAdapter(unavailable_reason="not on PATH")})
    outcome = Orchestrator(cfg).run(FIXTURES / "vulnerable_app")
    assert outcome.scan_results[0]["failure_kind"] == "missing_executable"
    assert outcome.scan_results[0]["ok"] is False


def test_adapter_crash_does_not_kill_run(cfg, monkeypatch):
    boom = ScanResult(scanner="semgrep", ok=False, failure_kind="adapter_error",
                      error="RuntimeError: boom")
    patch_adapters(monkeypatch, {"semgrep": FakeAdapter(RuntimeError("boom"))})
    outcome = Orchestrator(cfg).run(FIXTURES / "vulnerable_app")
    assert outcome.scan_results[0]["failure_kind"] == "adapter_error"


# -- dedup integration -----------------------------------------------------------

def test_duplicates_across_adapters_merged(cfg, monkeypatch):
    f1 = fake_finding(source="sast.semgrep", rule="r")
    # identical provenance from the same source+rule+file+line merges
    f2 = fake_finding(source="sast.semgrep", rule="r")
    r1 = ScanResult(scanner="semgrep", ok=True, findings=[f1])
    r2 = ScanResult(scanner="semgrep2", ok=True, findings=[f2])
    patch_adapters(monkeypatch, {"a": FakeAdapter(r1), "b": FakeAdapter(r2)})
    outcome = Orchestrator(cfg).run(FIXTURES / "vulnerable_app")
    assert len(outcome.findings) == 1
    assert outcome.grouping_log  # grouping is explained, not silent


# -- invalid target / config -----------------------------------------------------

def test_missing_target_raises(cfg, monkeypatch):
    patch_adapters(monkeypatch, {})
    with pytest.raises(FileNotFoundError):
        orchestrator_missing(cfg)


def orchestrator_missing(cfg):
    return Orchestrator(cfg).run(Path(__file__).resolve().parent / "does-not-exist")


def test_invalid_config_raises(cfg, monkeypatch):
    cfg.ai.enabled = True
    cfg.ai.base_url = "not-a-url"
    patch_adapters(monkeypatch, {})
    with pytest.raises(ValueError) as ei:
        Orchestrator(cfg).run(FIXTURES / "vulnerable_app")
    assert "invalid configuration" in str(ei.value)


# -- interruption -------------------------------------------------------------------

def test_interrupted_run_writes_partial_flagged_reports(cfg, monkeypatch):
    results = [
        ScanResult(scanner="semgrep", ok=True, findings=[fake_finding()]),
        ScanResult(scanner="bandit", ok=True, findings=[fake_finding(source="sast.bandit")]),
    ]
    adapters = {n: FakeAdapter(r) for n, r in zip(["semgrep", "bandit"], results)}
    patch_adapters(monkeypatch, adapters)

    orch = Orchestrator(cfg)
    calls = {"n": 0}

    def cancelling_progress(msg):
        calls["n"] += 1
        if calls["n"] >= 2:  # cancel after discovery + first scan start
            orch.cancel()

    orch.progress = cancelling_progress
    outcome = orch.run(FIXTURES / "vulnerable_app")
    assert outcome.interrupted is True
    assert outcome.context["interrupted"] is True
    # partial reports written, flagged as interrupted in markdown
    md_path = next(p for k, p in outcome.reports.items() if k == "markdown")
    assert "INTERRUPTED" in md_path.read_text(encoding="utf-8")


# -- AI optional ---------------------------------------------------------------------

def test_run_succeeds_without_ai(cfg, monkeypatch):
    ok = ScanResult(scanner="osv", ok=True, findings=[])
    patch_adapters(monkeypatch, {"osv": FakeAdapter(ok)})
    cfg.ai.enabled = False
    outcome = Orchestrator(cfg).run(FIXTURES / "vulnerable_app")
    assert outcome.context["ai_enabled"] is False
    assert any("AI-assisted analysis was disabled" in lim
               for lim in outcome.context["limitations"])


def test_ai_failure_does_not_abort_assessment(cfg, monkeypatch):
    ok = ScanResult(scanner="semgrep", ok=True, findings=[fake_finding()])
    patch_adapters(monkeypatch, {"semgrep": FakeAdapter(ok)})
    cfg.ai.enabled = True

    class DeadAI:
        enabled = True

        def analyse_findings(self, *a, **k):
            from veyron.ai import AIResult
            return AIResult(ok=False, failure_kind="unreachable", error="connection refused")

    orch = Orchestrator(cfg, ai=DeadAI())
    outcome = orch.run(FIXTURES / "vulnerable_app")
    assert outcome.findings  # assessment completed
    assert any(n.get("ok") is False for n in outcome.context["ai_notes"])
    assert all(f.validation_status == "DETECTED" for f in outcome.findings)
