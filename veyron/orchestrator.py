"""Assessment orchestration: discovery → scans → normalise → dedupe → report."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .adapters.base import ScanResult
from .ai import AIAdapter
from .config import Config
from .discovery import Discovery, DiscoveryResult
from .finding import Finding, deduplicate, prioritise
from .registry import build_adapters
from .redact import redact_text
from .report.core import build_context, write_reports


ProgressFn = Callable[[str], None]


@dataclass
class AssessmentOutcome:
    assessment_id: str
    target: str
    findings: list[Finding]
    grouping_log: list[dict[str, Any]]
    scan_results: list[dict[str, Any]]
    discovery: DiscoveryResult
    reports: dict[str, Path] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)
    interrupted: bool = False
    duration_seconds: float = 0.0


class Orchestrator:
    """Runs a bounded, cancellable assessment over a local repository."""

    def __init__(self, cfg: Config, *, progress: ProgressFn | None = None, ai: AIAdapter | None = None):
        self.cfg = cfg
        self.progress = progress or (lambda msg: None)
        self.ai = ai if ai is not None else AIAdapter(cfg.ai)
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    # -- main entry -----------------------------------------------------------

    def run(self, target: str | Path, *, formats: tuple[str, ...] = ("markdown", "json", "sarif")) -> AssessmentOutcome:
        started = time.monotonic()
        assessment_id = uuid.uuid4().hex[:12]
        target_path = Path(target).resolve()

        problems = self.cfg.validate()
        if problems:
            raise ValueError("invalid configuration: " + "; ".join(problems))
        if not target_path.is_dir():
            raise FileNotFoundError(f"target is not a directory: {target_path}")

        self.progress(f"[{assessment_id}] discovery: {target_path}")
        discovery = Discovery(
            target_path,
            exclusions=self.cfg.exclusions,
            max_file_size=self.cfg.scanners.max_file_size_bytes,
        ).run()
        self.progress(
            f"[{assessment_id}] discovery complete: {len(discovery.files)} files, "
            f"{len(discovery.components)} components, {len(discovery.skipped_files)} skipped"
        )

        adapters = build_adapters(self.cfg)
        scan_results: list[ScanResult] = []
        all_findings: list[Finding] = []

        for name, adapter in adapters.items():
            if self._cancel:
                break
            ok, reason = adapter.validate_config()
            if not ok:
                self.progress(f"[{assessment_id}] {name}: UNAVAILABLE — {reason}")
                scan_results.append(
                    ScanResult(scanner=name, ok=False, failure_kind="missing_executable", error=reason)
                )
                continue
            self.progress(f"[{assessment_id}] {name}: scanning…")
            try:
                result = adapter.scan(target_path, discovery.files)
            except Exception as exc:  # adapter bugs must not kill the run
                result = ScanResult(
                    scanner=name, ok=False, failure_kind="adapter_error",
                    error=f"{type(exc).__name__}: {exc}",
                )
            scan_results.append(result)
            if result.ok:
                all_findings.extend(result.findings)
                self.progress(
                    f"[{assessment_id}] {name}: ok, {len(result.findings)} raw findings "
                    f"({result.duration_seconds:.1f}s, version={result.tool_version or 'n/a'})"
                )
            else:
                self.progress(f"[{assessment_id}] {name}: FAILED — {result.error}")

        if self._cancel:
            self.progress(f"[{assessment_id}] cancelled by user")

        # Normalisation + dedup (spec 6.7)
        deduped, grouping_log = deduplicate(all_findings)
        deduped.sort(key=lambda f: (f.severity, f.id))

        for f in deduped:
            f.prio = prioritise(f)  # type: ignore[attr-defined]

        # Optional AI enrichment (failures are recorded, never fatal)
        ai_notes: list[dict[str, Any]] = []
        if self.ai.enabled and deduped and not self._cancel:
            ai_notes = self._enrich_with_ai(deduped)

        scan_dicts = [
            {
                "scanner": r.scanner,
                "ok": r.ok,
                "version": r.tool_version,
                "duration_seconds": round(r.duration_seconds, 2),
                "error": r.error,
                "failure_kind": r.failure_kind,
                "exit_code": r.exit_code,
                "raw_findings": len(r.findings),
                "metadata": r.metadata,
            }
            for r in scan_results
        ]

        context = build_context(
            target=str(target_path),
            findings=deduped,
            grouping_log=grouping_log,
            discovery_summary=discovery.summary(),
            scan_results=scan_dicts,
            ai_enabled=self.ai.enabled,
            assessment_id=assessment_id,
            interrupted=self._cancel,
            scope_notes=[
                f"Assessment scope: files under {target_path} after configured exclusions.",
                "Repository scripts were not executed during discovery.",
            ],
        )
        context["ai_notes"] = ai_notes

        outcome = AssessmentOutcome(
            assessment_id=assessment_id,
            target=str(target_path),
            findings=deduped,
            grouping_log=grouping_log,
            scan_results=scan_dicts,
            discovery=discovery,
            context=context,
            interrupted=self._cancel,
            duration_seconds=time.monotonic() - started,
        )

        if not self._cancel:
            out_dir = self.cfg.reports_dir / assessment_id
            outcome.reports = write_reports(context, out_dir, formats)
            self._append_history(context, outcome.reports)
            self.progress(f"[{assessment_id}] reports written: "
                          + ", ".join(str(p) for p in outcome.reports.values()))
        else:
            # Interrupted assessment: still write partial reports, flagged.
            out_dir = self.cfg.reports_dir / f"{assessment_id}-partial"
            outcome.reports = write_reports(context, out_dir, formats)
            self._append_history(context, outcome.reports)
            self.progress(f"[{assessment_id}] partial reports written to {out_dir}")

        return outcome

    # -- AI enrichment ---------------------------------------------------------

    def _enrich_with_ai(self, findings: list[Finding], *, limit: int = 5) -> list[dict[str, Any]]:
        """Bounded AI enrichment: top-N findings only, minimal context.

        Never marks findings VALIDATED: AI text is advisory only.
        """
        notes: list[dict[str, Any]] = []
        ranked = sorted(findings, key=lambda f: (f.severity != "critical", f.severity != "high"))[:limit]
        for f in ranked:
            ctx = (
                f"Finding {f.id}\nTitle: {f.title}\nCategory: {f.category}\n"
                f"Severity: {f.severity}\nConfidence: {f.confidence}\n"
                f"State: {f.validation_status}\nSource: {f.source}\n"
                f"File: {f.file_path}:{f.line}\nEvidence:\n{f.evidence[:1200]}\n"
            )
            res = self.ai.analyse_findings(
                ctx,
                "Explain likely root cause, suggest remediation and one safe regression-test idea. "
                "State explicitly when information is missing. Output at most 6 short bullet lines.",
            )
            if res.ok:
                f.ai_summary = redact_text(res.text.strip())[:2000]
                notes.append({"finding": f.id, "ok": True, "model": res.model})
            else:
                notes.append({"finding": f.id, "ok": False, "error": res.error,
                              "kind": res.failure_kind})
                # AI unavailability never blocks the assessment.
        return notes

    # -- history ---------------------------------------------------------------

    def _append_history(self, context: dict[str, Any], reports: dict[str, Path]) -> None:
        try:
            self.cfg.history_path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "assessment_id": context.get("assessment_id"),
                "generated_at": context.get("generated_at"),
                "target": context.get("target"),
                "findings": len(context.get("findings", [])),
                "severity_counts": context.get("severity_counts", {}),
                "interrupted": context.get("interrupted", False),
                "coverage_warning": context.get("coverage_warning"),
                "failed_scanners": [
                    t.get("scanner") for t in context.get("tools", []) if not t.get("ok")
                ],
                "reports": {k: str(v) for k, v in reports.items()},
            }
            with self.cfg.history_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # history failures never corrupt an assessment
