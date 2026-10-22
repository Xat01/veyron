"""Report generation: Markdown, JSON, SARIF.

Every report distinguishes successful analysis from missing analysis:
scanner failures are listed explicitly, and a failed scan is never
presented as a clean result. Secrets are redacted before rendering.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import __version__
from ..constants import SEVERITY_TO_SARIF_LEVEL
from ..finding import Finding, prioritise
from ..redact import redact_text


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_context(
    *,
    target: str,
    findings: list[Finding],
    grouping_log: list[dict[str, Any]],
    discovery_summary: dict[str, Any],
    scan_results: list[dict[str, Any]],
    ai_enabled: bool,
    scope_notes: list[str] | None = None,
    assessment_id: str = "",
    interrupted: bool = False,
    profile: str = "PASSIVE",
    assessment_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the shared report context (already normalised)."""

    failed = [s for s in scan_results if not s.get("ok")]
    severity_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        status_counts[f.validation_status] = status_counts.get(f.validation_status, 0) + 1

    for f in findings:
        f.description = redact_text(f.description)
        f.evidence = redact_text(f.evidence)

    return {
        "tool": "VEYRON",
        "tool_version": __version__,
        "assessment_id": assessment_id,
        "generated_at": _utcnow(),
        "target": target,
        "interrupted": interrupted,
        "ai_enabled": ai_enabled,
        "profile": profile,
        "assessment_authorization": assessment_scope or {},
        "scope": {
            "root": target,
            "files_assessed": discovery_summary.get("file_count", 0),
            "bytes_assessed": discovery_summary.get("total_bytes", 0),
            "excluded_directories": discovery_summary.get("excluded_dirs", []),
            "skipped_files": discovery_summary.get("skipped_files", []),
            "unsupported_extensions": discovery_summary.get("unsupported_extensions", []),
            "components": discovery_summary.get("components", []),
            "notes": scope_notes or [],
        },
        "tools": scan_results,
        "coverage_warning": _coverage_warning(failed, discovery_summary),
        "findings": [f.to_dict() for f in findings],
        "severity_counts": severity_counts,
        "validation_counts": status_counts,
        "grouping_log": grouping_log,
        "prioritisation": {f.id: prioritise(f) for f in findings},
        "limitations": _limitations(failed, ai_enabled, discovery_summary),
    }


def _coverage_warning(failed: list[dict[str, Any]], summary: dict[str, Any]) -> str | None:
    parts: list[str] = []
    if failed:
        names = ", ".join(str(s.get("scanner")) for s in failed)
        parts.append(f"Scanner(s) failed and did not complete: {names}. "
                     "Absence of findings from these scanners is NOT evidence of a clean result.")
    if summary.get("unsupported_extensions"):
        parts.append("Some file types were not analysed: "
                     + ", ".join(summary["unsupported_extensions"]) + ".")
    if summary.get("skipped_files"):
        parts.append(f"{len(summary['skipped_files'])} files skipped (size limits or exclusions).")
    return " ".join(parts) if parts else None


def _limitations(failed: list[dict[str, Any]], ai_enabled: bool, summary: dict[str, Any]) -> list[str]:
    out = [
        "Static analysis cannot establish exploitability; findings are candidates until validated.",
        "Dependency advisories indicate affected version ranges, not confirmed exploitability in this application.",
    ]
    for s in failed:
        out.append(f"Scanner '{s.get('scanner')}': {s.get('error') or 'failed'} ({s.get('failure_kind') or 'unknown'}).")
    if not ai_enabled:
        out.append("AI-assisted analysis was disabled for this assessment; no AI context was generated.")
    if summary.get("unsupported_extensions"):
        out.append("Unsupported file types were excluded from analysis; coverage is not complete.")
    return out


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def render_json(context: dict[str, Any]) -> str:
    return json.dumps(context, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

_SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
_STATE_ORDER = [
    "VALIDATED", "CORROBORATED", "ANALYSED", "DETECTED", "INCONCLUSIVE",
    "REQUIRES_MANUAL_REVIEW", "VALIDATION_NOT_PERMITTED", "BLOCKED_BY_SCOPE",
    "FALSE_POSITIVE",
]


def render_markdown(context: dict[str, Any]) -> str:
    f = context
    lines: list[str] = []
    w = lines.append
    w(f"# {f['tool']} Assessment Report")
    w("")
    w(f"- **Target:** `{f['target']}`")
    w(f"- **Assessment ID:** `{f['assessment_id'] or 'n/a'}`")
    w(f"- **Generated:** {f['generated_at']}")
    w(f"- **VEYRON version:** {f['tool_version']}")
    w(f"- **AI-assisted analysis:** {'enabled' if f['ai_enabled'] else 'disabled'}")
    if f.get("interrupted"):
        w("- **Status:** ⚠ INTERRUPTED — results are incomplete")
    w("")
    w("## 1. Executive summary")
    w("")
    total = len(f["findings"])
    if total == 0:
        w("No findings were reported by the scanners that completed successfully.")
    else:
        w(f"**{total} finding(s)** normalised from all sources.")
        w("")
        w("| Severity | Count |")
        w("|---|---|")
        for sev in _SEV_ORDER:
            if sev in f["severity_counts"]:
                w(f"| {sev.capitalize()} | {f['severity_counts'][sev]} |")
    if f.get("coverage_warning"):
        w("")
        w(f"> ⚠ **Coverage warning:** {f['coverage_warning']}")
    w("")
    w("## 2. Scope")
    w("")
    s = f["scope"]
    w(f"- Files assessed: **{s['files_assessed']}** ({s['bytes_assessed']} bytes)")
    w(f"- Excluded directories: {', '.join('`%s`' % d for d in s['excluded_directories']) or 'none'}")
    w(f"- Skipped files: {len(s['skipped_files'])}")
    w(f"- Unsupported extensions: {', '.join(s['unsupported_extensions']) or 'none'}")
    if s["notes"]:
        w("- Notes:")
        for note in s["notes"]:
            w(f"  - {note}")
    w("")
    w("## 3. Tools and versions")
    w("")
    w("| Scanner | Status | Version | Duration (s) | Failure reason |")
    w("|---|---|---|---|---|")
    for t in f["tools"]:
        status = "✅ ok" if t.get("ok") else "❌ FAILED"
        w(f"| {t.get('scanner')} | {status} | {t.get('version') or 'n/a'} | "
          f"{t.get('duration_seconds', 0):.1f} | {t.get('error') or '-'} |")
    w("")
    if f["grouping_log"]:
        w("## 3.1 Correlation decisions")
        w("")
        for g in f["grouping_log"]:
            w(f"- Representative `{g['representative']}` groups {g['members']}: {g['reason']}")
        w("")
    w("## 4. Findings")
    w("")
    if not f["findings"]:
        w("_No findings. Note the coverage warning above before interpreting this as clean._")
        w("")
    ranked = sorted(
        f["findings"],
        key=lambda d: (f["prioritisation"].get(d["id"], {}).get("score", 0)),
        reverse=True,
    )
    for i, fd in enumerate(ranked, 1):
        prio = f["prioritisation"].get(fd["id"], {})
        w(f"### {i}. {fd['title']}")
        w("")
        w(f"- **ID:** `{fd['id']}`  ")
        w(f"- **Severity:** {fd['severity'].upper()} | **Confidence:** {fd['confidence'].upper()} | "
          f"**State:** {fd['validation_status']} | **Priority score:** {prio.get('score', 'n/a')}")
        w(f"- **Source:** `{fd['source']}` (tool: {fd.get('tool') or 'n/a'}, rule: `{fd.get('rule_id') or 'n/a'}`)")
        if fd.get("asset"):
            w(f"- **Affected asset:** `{fd['asset']}`")
        if fd.get("endpoint"):
            w(f"- **Endpoint:** `{fd['endpoint']}`")
        if fd.get("file_path"):
            loc = f"`{fd['file_path']}`"
            if fd.get("line"):
                loc += f" line {fd['line']}"
            w(f"- **Location:** {loc}")
        if fd.get("advisory_refs"):
            w(f"- **Advisories:** {', '.join(fd['advisory_refs'])}")
        w("")
        w(f"{fd['description']}")
        w("")
        w("**Evidence**")
        w("")
        w("```")
        w(str(fd.get("evidence") or "")[:1500])
        w("```")
        w("")
        ve = fd.get("validation_evidence") or {}
        if ve:
            w("**Validation evidence**")
            w("")
            for label, key in (
                ("Method", "validation_method"),
                ("Expected", "expected"),
                ("Observed", "observed"),
                ("Preconditions", "preconditions"),
                ("Reproductions", "reproductions"),
                ("Environment", "environment"),
                ("Limitations", "limitations"),
            ):
                if ve.get(key) not in (None, "", []):
                    w(f"- **{label}:** {ve[key]}")
            if ve.get("request"):
                w("- **Sanitised request:**")
                w("")
                w("```")
                w(str(ve["request"])[:800])
                w("```")
            w("")
        if fd.get("expected_behavior") and not ve.get("expected"):
            w(f"**Expected secure behaviour:** {fd['expected_behavior']}")
            w("")
        if fd.get("impact"):
            w(f"**Potential impact:** {fd['impact']}")
            w("")
        if fd.get("preconditions"):
            w(f"**Reproduction prerequisites:** {fd['preconditions']}")
            w("")
        if fd.get("reproduction"):
            w(f"**Safe reproduction:** {fd['reproduction']}")
            w("")
        if fd.get("remediation"):
            w(f"**Remediation:** {fd['remediation']}")
            w("")
        if fd.get("verification"):
            w(f"**Verification after remediation:** {fd['verification']}")
            w("")
        if prio.get("assumptions"):
            w("**Prioritisation assumptions:**")
            for a in prio["assumptions"]:
                w(f"- {a}")
            w("")
        if fd.get("validation_history"):
            w("**Validation history**")
            for vh in fd["validation_history"]:
                w(f"- `{vh.get('at')}` → **{vh.get('state')}** by {vh.get('actor')}: {vh.get('reason')}")
            w("")
    w("## 5. Validation status distribution")
    w("")
    w("| State | Count |")
    w("|---|---|")
    for st in _STATE_ORDER:
        if st in f["validation_counts"]:
            w(f"| {st} | {f['validation_counts'][st]} |")
    w("")
    w("## 6. Known limitations")
    w("")
    for lim in f["limitations"]:
        w(f"- {lim}")
    w("")
    w("---")
    w(f"_Generated by {f['tool']} v{f['tool_version']} — evidence over speculation._")
    w("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML report (self-contained, escaped, no external resources)
# ---------------------------------------------------------------------------

def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def render_html(context: dict[str, Any]) -> str:
    """Render a self-contained HTML report.

    Every dynamic value is escaped and the document declares a restrictive
    CSP, so findings/scanner output cannot execute script in the report.
    """
    f = context
    rows: list[str] = []
    ranked = sorted(
        f["findings"],
        key=lambda d: f["prioritisation"].get(d["id"], {}).get("score", 0),
        reverse=True,
    )
    for fd in ranked:
        ve = fd.get("validation_evidence") or {}
        rows.append(
            "<section class='finding'>"
            f"<h2>{_esc(fd.get('title'))}</h2>"
            f"<p><strong>ID:</strong> <code>{_esc(fd.get('id'))}</code> "
            f"<strong>Severity:</strong> {_esc(fd.get('severity'))} "
            f"<strong>Confidence:</strong> {_esc(fd.get('confidence'))} "
            f"<strong>Validation:</strong> {_esc(fd.get('validation_status'))}</p>"
            f"<p><strong>Category:</strong> {_esc(fd.get('category'))} "
            f"<strong>Asset:</strong> {_esc(fd.get('asset') or fd.get('target') or f.get('target'))} "
            f"<strong>Endpoint:</strong> {_esc(fd.get('endpoint') or fd.get('file_path') or 'n/a')}</p>"
            f"<p>{_esc(fd.get('description'))}</p>"
            f"<h3>Evidence</h3><pre>{_esc(str(fd.get('evidence') or '')[:4000])}</pre>"
            f"<h3>Validation evidence</h3><pre>{_esc(json.dumps(ve, indent=2, default=str)[:6000])}</pre>"
            f"<h3>Impact</h3><p>{_esc(fd.get('impact') or 'Not separately assessed.')}</p>"
            f"<h3>Reproduction prerequisites</h3><p>{_esc(fd.get('preconditions') or 'None recorded.')}</p>"
            f"<h3>Safe reproduction</h3><pre>{_esc(fd.get('reproduction') or 'Not recorded.')}</pre>"
            f"<h3>Remediation</h3><p>{_esc(fd.get('remediation') or 'Not recorded.')}</p>"
            f"<h3>Verification</h3><p>{_esc(fd.get('verification') or 'Not recorded.')}</p>"
            "</section>"
        )
    if not rows:
        rows.append("<p>No findings were reported by the scanners that completed.</p>")
    auth = f.get("assessment_authorization") or {}
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        "<meta name='referrer' content='no-referrer'>"
        f"<title>{_esc(f['tool'])} assessment report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;"
        "line-height:1.5;padding:0 1rem}pre{white-space:pre-wrap;background:#f4f4f4;"
        "padding:.75rem;overflow-wrap:anywhere}.finding{border-top:2px solid #ccc;"
        "margin-top:2rem;padding-top:1rem}.muted{color:#666}</style></head><body>"
        f"<h1>{_esc(f['tool'])} Assessment Report</h1>"
        f"<p><strong>Target:</strong> {_esc(f['target'])}<br>"
        f"<strong>Assessment ID:</strong> {_esc(f['assessment_id'] or 'n/a')}<br>"
        f"<strong>Generated:</strong> {_esc(f['generated_at'])}<br>"
        f"<strong>Profile:</strong> {_esc(f.get('profile') or 'n/a')}<br>"
        f"<strong>AI assistance:</strong> {'enabled' if f['ai_enabled'] else 'disabled'}</p>"
        + ("<p><strong>INTERRUPTED:</strong> results are incomplete.</p>"
           if f.get("interrupted") else "")
        + f"<p class='muted'>{_esc(f.get('coverage_warning') or '')}</p>"
        f"<h2>Authorisation and limits</h2><pre>{_esc(json.dumps(auth, indent=2, default=str))}</pre>"
        f"<h2>Findings ({len(f['findings'])})</h2>"
        + "".join(rows)
        + f"<h2>Limitations</h2><p>{_esc(f.get('limitations') or 'None recorded.')}</p>"
        "</body></html>"
    )


def render_finding_markdown(context: dict[str, Any], fd: dict[str, Any]) -> str:
    """Individual report for one finding (same evidence, no invention)."""
    ve = fd.get("validation_evidence") or {}
    prio = context.get("prioritisation", {}).get(fd.get("id"), {})
    lines = [
        f"# {fd.get('title')}",
        "",
        f"- **ID:** `{fd.get('id')}`",
        f"- **Category:** {fd.get('category')}",
        f"- **Severity / confidence:** {fd.get('severity')} / {fd.get('confidence')}",
        f"- **Validation status:** {fd.get('validation_status')}",
        f"- **Priority (internal heuristic):** {prio.get('score', 'n/a')}",
        f"- **Assessment:** `{context.get('assessment_id') or 'n/a'}`",
        f"- **Target:** `{context.get('target')}`",
        f"- **Profile:** {context.get('profile', 'n/a')}",
        "",
        "## Affected asset and endpoint",
        "",
        f"- Asset: `{fd.get('asset') or context.get('target')}`",
        f"- Endpoint / source: `{fd.get('endpoint') or fd.get('file_path') or 'n/a'}"
        + (f":{fd.get('line')}" if fd.get("line") else "") + "`",
        "",
        "## Technical explanation",
        "",
        str(fd.get("description") or "Not recorded."),
        "",
        "## Evidence",
        "",
        "```",
        str(fd.get("evidence") or "")[:4000],
        "```",
        "",
        "## Validation",
        "",
        f"- Method: {ve.get('validation_method') or 'n/a'}",
        f"- Expected: {ve.get('expected') or fd.get('expected_behavior') or 'n/a'}",
        f"- Observed: {ve.get('observed') or fd.get('observed_behavior') or 'n/a'}",
        f"- Preconditions: {ve.get('preconditions') or fd.get('preconditions') or 'n/a'}",
        f"- Reproductions: {ve.get('reproductions', 'n/a')}",
        f"- Environment: {ve.get('environment') or 'n/a'}",
        f"- Limitations: {ve.get('limitations') or fd.get('limitations') or 'n/a'}",
        "",
        "## Safe reproduction",
        "",
        str(fd.get("reproduction") or ve.get("request") or "Not recorded."),
        "",
        "## Impact",
        "",
        str(fd.get("impact") or "Not separately assessed."),
        "",
        "## Remediation and verification",
        "",
        f"- Remediation: {fd.get('remediation') or 'Not recorded.'}",
        f"- Verification: {fd.get('verification') or 'Not recorded.'}",
        "",
        "## References",
        "",
        *(f"- {ref}" for ref in (fd.get("advisory_refs") or [])),
        "",
        f"_Scope and limitations: {context.get('limitations') or 'see consolidated report'}_",
    ]
    return "\n".join(lines)


def render_disclosure_draft(context: dict[str, Any]) -> str:
    """Editable responsible-disclosure draft. Never submitted automatically."""
    confirmed = [f for f in context["findings"] if f.get("validation_status") == "VALIDATED"]
    suspected = [
        f for f in context["findings"]
        if f.get("validation_status") in {"CORROBORATED", "ANALYSED", "DETECTED", "INCONCLUSIVE"}
    ]
    lines = [
        "# Responsible disclosure draft (owner must review and send)",
        "",
        "> This is a draft only. VEYRON did not contact anyone and did not look up a",
        "> security contact. Replace the placeholders, confirm the facts, and send it",
        "> yourself through an appropriate channel.",
        "",
        "To: [SECURITY CONTACT — supplied by the asset owner]",
        f"Subject: Security assessment findings for {context.get('target')}",
        "",
        "Hello,",
        "",
        "We assessed the above asset under explicit authorisation. The following",
        "issues were reproduced with non-destructive tests.",
        "",
        "## Confirmed findings",
        "",
    ]
    if confirmed:
        for fd in confirmed:
            ve = fd.get("validation_evidence") or {}
            lines += [
                f"- **{fd.get('title')}** (`{fd.get('id')}`, {fd.get('severity')})",
                f"  - Endpoint: {fd.get('endpoint') or fd.get('file_path') or 'n/a'}",
                f"  - Observed: {ve.get('observed') or fd.get('evidence') or 'n/a'}",
                f"  - Suggested fix: {fd.get('remediation') or 'n/a'}",
            ]
    else:
        lines.append("- None confirmed by the validation engine.")
    lines += ["", "## Suspected / needs review", ""]
    if suspected:
        for fd in suspected:
            lines.append(
                f"- **{fd.get('title')}** ({fd.get('validation_status')}, "
                f"{fd.get('severity')}) — evidence is not sufficient for confirmation."
            )
    else:
        lines.append("- None.")
    lines += [
        "",
        "## Scope and limitations",
        "",
        str(context.get("limitations") or "Not recorded."),
        "",
        "We are available to provide sanitised reproduction details and to verify fixes.",
        "",
        "[SENDER NAME / CONTACT — supplied by the operator]",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# SARIF (2.1.0) — best-effort, structured correctly
# ---------------------------------------------------------------------------

def render_sarif(context: dict[str, Any]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for fd in context["findings"]:
        rule_id = fd.get("rule_id") or "veyron.generic"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": (fd.get("tool") or "veyron") + ":" + rule_id,
                "shortDescription": {"text": fd["title"][:200]},
                "fullDescription": {"text": redact_text(fd["description"])[:4000]},
                "defaultConfiguration": {"level": SEVERITY_TO_SARIF_LEVEL.get(fd["severity"], "note")},
                "properties": {
                    "security-severity": {"severity": fd["severity"], "confidence": fd["confidence"]},
                    "tags": ["security", fd["category"]],
                },
            }
        loc_uri = fd.get("file_path") or "unknown"
        loc: dict[str, Any] = {
            "physicalLocation": {"artifactLocation": {"uri": loc_uri.replace("\\", "/")}}
        }
        if fd.get("line"):
            loc["physicalLocation"]["region"] = {"startLine": fd["line"]}
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF_LEVEL.get(fd["severity"], "note"),
            "message": {"text": redact_text(fd["description"])[:2000]},
            "locations": [loc],
            "partialFingerprints": {"veyronFindingId": fd["id"]},
            "properties": {
                "confidence": fd["confidence"],
                "validationStatus": fd["validation_status"],
                "priorityScore": context["prioritisation"].get(fd["id"], {}).get("score"),
                "advisories": fd.get("advisory_refs", []),
            },
        })

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VEYRON",
                    "version": context["tool_version"],
                    "informationUri": "https://github.com/VEYRON/veyron",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": not context.get("interrupted", False),
                "properties": {
                    "assessmentId": context.get("assessment_id"),
                    "coverageWarning": context.get("coverage_warning"),
                    "failedScanners": [
                        {"scanner": t.get("scanner"), "error": t.get("error")}
                        for t in context.get("tools", []) if not t.get("ok")
                    ],
                },
            }],
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_reports(
    context: dict[str, Any],
    out_dir: str | Path,
    formats: tuple[str, ...] = ("markdown", "json", "sarif"),
    *,
    include_finding_reports: bool = False,
    include_disclosure: bool = False,
) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"veyron-{context.get('assessment_id') or 'report'}"
    written: dict[str, Path] = {}
    if "json" in formats:
        p = out / f"{stem}.json"
        p.write_text(render_json(context), encoding="utf-8")
        written["json"] = p
    if "markdown" in formats:
        p = out / f"{stem}.md"
        p.write_text(render_markdown(context), encoding="utf-8")
        written["markdown"] = p
    if "sarif" in formats:
        p = out / f"{stem}.sarif"
        p.write_text(render_sarif(context), encoding="utf-8")
        written["sarif"] = p
    if "html" in formats:
        p = out / f"{stem}.html"
        p.write_text(render_html(context), encoding="utf-8")
        written["html"] = p

    if include_finding_reports and context.get("findings"):
        findings_dir = out / "findings"
        findings_dir.mkdir(exist_ok=True)
        for fd in context["findings"]:
            safe_id = "".join(ch for ch in str(fd.get("id", "finding"))
                              if ch.isalnum() or ch in "-_") or "finding"
            md = findings_dir / f"{safe_id}.md"
            md.write_text(render_finding_markdown(context, fd), encoding="utf-8")
            js = findings_dir / f"{safe_id}.json"
            js.write_text(json.dumps(fd, indent=2, ensure_ascii=False, default=str),
                          encoding="utf-8")
            written[f"finding:{safe_id}:md"] = md
            written[f"finding:{safe_id}:json"] = js
    if include_disclosure:
        p = out / f"{stem}-disclosure-draft.md"
        p.write_text(render_disclosure_draft(context), encoding="utf-8")
        written["disclosure"] = p
    return written
