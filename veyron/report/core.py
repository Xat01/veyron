"""Report generation: Markdown, JSON, SARIF.

Every report distinguishes successful analysis from missing analysis:
scanner failures are listed explicitly, and a failed scan is never
presented as a clean result. Secrets are redacted before rendering.
"""

from __future__ import annotations

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
_STATE_ORDER = ["VALIDATED", "CORROBORATED", "ANALYSED", "DETECTED", "INCONCLUSIVE", "FALSE_POSITIVE"]


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
        if fd.get("remediation"):
            w(f"**Remediation:** {fd['remediation']}")
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
    return written
