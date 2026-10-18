"""Report generation: Markdown, JSON, SARIF; partial/failed coverage honesty."""

import json

import pytest

from veyron.finding import Finding, stable_finding_id
from veyron.report.core import build_context, render_json, render_markdown, render_sarif, write_reports


def make_finding(**kw) -> Finding:
    base = dict(
        id=stable_finding_id("sast.semgrep", "rule.a", "app.py", 10, "eval usage"),
        title="Possible call to eval()",
        description="User input reaches eval()",
        category="CWE-95",
        severity="high",
        confidence="medium",
        validation_status="DETECTED",
        source="sast.semgrep",
        file_path="app.py",
        line=10,
        evidence="return eval(user_input)",
        remediation="Use ast.literal_eval or a parser",
        rule_id="rule.a",
        tool="semgrep",
        advisory_refs=["https://example.test/cwe-95"],
    )
    base.update(kw)
    return Finding(**base)


def ctx(findings=None, scan_results=None, summary=None, **kw):
    findings = findings if findings is not None else [make_finding()]
    scan_results = scan_results if scan_results is not None else [
        {"scanner": "semgrep", "ok": True, "version": "1.0", "duration_seconds": 1.5,
         "error": None, "failure_kind": None, "exit_code": 0, "raw_findings": 1, "metadata": {}}
    ]
    summary = summary if summary is not None else {
        "file_count": 3, "total_bytes": 100, "excluded_dirs": [],
        "skipped_files": [], "unsupported_extensions": [], "components": [],
    }
    return build_context(target="C:/repo", findings=findings, grouping_log=[],
                         discovery_summary=summary, scan_results=scan_results,
                         ai_enabled=False, assessment_id="testid01", **kw)


# -- JSON ----------------------------------------------------------------------

def test_json_report_valid_and_complete():
    c = ctx()
    data = json.loads(render_json(c))
    assert data["tool"] == "VEYRON"
    assert len(data["findings"]) == 1
    assert data["severity_counts"] == {"high": 1}
    assert data["validation_counts"] == {"DETECTED": 1}
    assert data["limitations"]


def test_json_report_redacts_secrets():
    f = make_finding(evidence="api_key = 'FAKE_REPORT_KEY_1234567890'")
    data = json.loads(render_json(ctx(findings=[f])))
    assert "FAKE_REPORT_KEY_1234567890" not in json.dumps(data)
    assert "[REDACTED]" in json.dumps(data)


# -- Markdown ------------------------------------------------------------------

def test_markdown_sections_present():
    md = render_markdown(ctx())
    for section in ["# VEYRON Assessment Report", "Executive summary", "Scope",
                    "Tools and versions", "Findings", "Known limitations"]:
        assert section in md
    assert "Possible call to eval()" in md
    assert "remediation" in md.lower()


def test_markdown_reports_scanner_failure_not_clean():
    failed = [
        {"scanner": "semgrep", "ok": False, "version": None, "duration_seconds": 0.0,
         "error": "semgrep not found", "failure_kind": "missing_executable",
         "exit_code": None, "raw_findings": 0, "metadata": {}},
    ]
    c = ctx(findings=[], scan_results=failed)
    md = render_markdown(c)
    assert "FAILED" in md
    assert c["coverage_warning"] is not None
    assert "NOT evidence of a clean result" in md


def test_markdown_marks_interrupted():
    md = render_markdown(ctx(interrupted=True))
    assert "INTERRUPTED" in md


def test_markdown_lists_unsupported_coverage():
    c = ctx(summary={
        "file_count": 1, "total_bytes": 10, "excluded_dirs": ["node_modules"],
        "skipped_files": ["big.bin"], "unsupported_extensions": [".png"], "components": [],
    })
    md = render_markdown(c)
    assert ".png" in md
    assert c["coverage_warning"]


# -- SARIF ---------------------------------------------------------------------

def test_sarif_structure_valid():
    doc = json.loads(render_sarif(ctx()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "VEYRON"
    assert run["results"][0]["ruleId"] == "rule.a"
    assert run["results"][0]["level"] == "error"  # high -> error
    assert run["results"][0]["properties"]["validationStatus"] == "DETECTED"
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 10


def test_sarif_records_failed_scanners():
    failed = [{"scanner": "bandit", "ok": False, "error": "not installed",
               "failure_kind": "missing_executable", "version": None,
               "duration_seconds": 0, "exit_code": None, "raw_findings": 0, "metadata": {}}]
    doc = json.loads(render_sarif(ctx(scan_results=failed)))
    inv = doc["runs"][0]["invocations"][0]
    assert inv["properties"]["failedScanners"][0]["scanner"] == "bandit"


def test_sarif_secret_redaction():
    tok = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    f = make_finding(description="token " + tok)
    doc = json.dumps(json.loads(render_sarif(ctx(findings=[f]))))
    assert tok not in doc


# -- writers ---------------------------------------------------------------------

def test_write_reports_all_formats(tmp_path):
    written = write_reports(ctx(), tmp_path, ("markdown", "json", "sarif"))
    assert set(written) == {"markdown", "json", "sarif"}
    for p in written.values():
        assert p.exists()
        assert p.stat().st_size > 0


def test_write_reports_subset(tmp_path):
    written = write_reports(ctx(), tmp_path, ("json",))
    assert set(written) == {"json"}
