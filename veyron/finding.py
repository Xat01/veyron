"""Normalised finding model, correlation, deduplication, and risk handling.

Every scanner emits a different structure. VEYRON normalises all findings
into :class:`Finding` so downstream code (dedup, risk, reports, AI) has one
contract. Provenance (source, tool, rule id, raw evidence) is preserved.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .constants import CONFIDENCE_LEVELS, FINDING_STATES, SEVERITY_LEVELS

# Reasons acceptable as evidence for a VALIDATED transition. A bare "scanner
# said so" or a model opinion is deliberately NOT sufficient (spec 6.9):
# validation requires concrete, reproducible evidence language.
VALIDATION_EVIDENCE_KEYWORDS = re.compile(
    r"(?i)\b(evidence|reproduc\w*|confirm\w*|verified|verification|payload|"
    r"test case|regression test|observed response|hash)\b"
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stable_finding_id(
    source: str,
    rule_id: str,
    file_path: str,
    line: int | None,
    title: str,
) -> str:
    """Deterministic id derived from provenance, not from mutable content."""
    raw = "|".join(
        [
            source,
            rule_id or "",
            file_path.replace("\\", "/"),
            str(line or 0),
            title.strip().lower(),
        ]
    )
    return "VYN-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12].upper()


@dataclass
class Finding:
    """Normalised, evidence-preserving security finding."""

    id: str
    title: str
    description: str
    category: str
    severity: str
    confidence: str
    validation_status: str
    source: str  # e.g. "sast.semgrep", "sca.osv", "secret.gitleaks", "ai"
    file_path: str | None
    line: int | None
    evidence: str
    remediation: str | None = None
    rule_id: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    advisory_refs: list[str] = field(default_factory=list)
    detected_at: str = field(default_factory=_utcnow_iso)
    validation_history: list[dict[str, Any]] = field(default_factory=list)
    related_ids: list[str] = field(default_factory=list)
    ai_summary: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_LEVELS:
            self.severity = "unknown"
        if self.confidence not in CONFIDENCE_LEVELS:
            self.confidence = "unknown"
        if self.validation_status not in FINDING_STATES:
            self.validation_status = "DETECTED"

    # --- transition criteria -------------------------------------------------

    def transition(self, new_state: str, reason: str, actor: str = "system") -> bool:
        """Attempt a validation state transition. Returns True when applied.

        Rules (spec 6.9):
        - VALIDATED requires evidence-backed reason (non-empty, not a bare
          scanner+AI agreement — the caller must pass concrete evidence).
        - FALSE_POSITIVE requires an explicit reason.
        """
        if new_state not in FINDING_STATES:
            return False
        allowed = {
            "DETECTED": {"ANALYSED", "INCONCLUSIVE", "FALSE_POSITIVE", "CORROBORATED", "VALIDATED"},
            "ANALYSED": {"CORROBORATED", "INCONCLUSIVE", "FALSE_POSITIVE", "VALIDATED"},
            "CORROBORATED": {"VALIDATED", "INCONCLUSIVE", "FALSE_POSITIVE"},
            "INCONCLUSIVE": {"ANALYSED", "CORROBORATED", "VALIDATED", "FALSE_POSITIVE"},
            "VALIDATED": {"INCONCLUSIVE"},
            "FALSE_POSITIVE": {"INCONCLUSIVE"},
        }
        if new_state == self.validation_status:
            return False
        if new_state not in allowed.get(self.validation_status, set()):
            return False
        if new_state == "VALIDATED":
            # Evidence-backed reason required: minimum length AND language
            # that points at concrete evidence, not bare agreement.
            reason_text = reason.strip()
            if len(reason_text) < 10 or not VALIDATION_EVIDENCE_KEYWORDS.search(reason_text):
                return False
        self.validation_status = new_state
        self.validation_history.append(
            {
                "state": new_state,
                "reason": reason.strip(),
                "actor": actor,
                "at": _utcnow_iso(),
            }
        )
        return True

    # --- serialisation -------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["file_path"] = self.file_path
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(**d)


# --------------------------------------------------------------------------
# Correlation / deduplication
# --------------------------------------------------------------------------

def correlation_key(f: Finding) -> tuple:
    """Correlation key: same category + same file + same rule lineage.

    Title alone is never used to merge distinct vulnerabilities (spec 6.7).
    """
    return (
        f.source,
        f.category.lower(),
        (f.file_path or "").replace("\\", "/").lower(),
        (f.rule_id or f.title).lower(),
    )


def deduplicate(findings: Iterable[Finding]) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Merge exact-provenance duplicates, keep every source of evidence.

    Returns (deduplicated_findings, grouping_log). The grouping log explains
    *why* findings were grouped (spec 6.7).
    """
    groups: dict[tuple, list[Finding]] = {}
    order: list[tuple] = []
    for f in findings:
        key = correlation_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    merged: list[Finding] = []
    grouping_log: list[dict[str, Any]] = []

    for key in order:
        group = groups[key]
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Keep the highest-severity, most-evidenced representative; retain
        # every contributing provenance in `raw.merged_provenance`.
        rank = {s: i for i, s in enumerate(reversed(SEVERITY_LEVELS))}
        group_sorted = sorted(group, key=lambda f: rank.get(f.severity, 99))
        rep = group_sorted[0]
        for extra in group_sorted[1:]:
            rep.related_ids.append(extra.id)
            rep.raw.setdefault("merged_provenance", []).append(
                {
                    "id": extra.id,
                    "source": extra.source,
                    "tool": extra.tool,
                    "rule_id": extra.rule_id,
                    "evidence": extra.evidence,
                }
            )
        rep.confidence = "high" if len({g.source for g in group}) > 1 else rep.confidence
        merged.append(rep)
        grouping_log.append(
            {
                "representative": rep.id,
                "members": [g.id for g in group],
                "reason": (
                    "Same detection source, category, file, and rule lineage; "
                    "original evidence for every member preserved in "
                    "raw.merged_provenance."
                ),
                "sources": sorted({g.source for g in group}),
            }
        )

    return merged, grouping_log


# --------------------------------------------------------------------------
# Risk prioritisation (transparent, evidence-driven)
# --------------------------------------------------------------------------

SEVERITY_BASE = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
    "unknown": 3.0,
}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.85, "low": 0.7, "unknown": 0.75}
VALIDATION_FACTOR = {
    "VALIDATED": 1.0,
    "CORROBORATED": 0.95,
    "ANALYSED": 0.85,
    "DETECTED": 0.8,
    "INCONCLUSIVE": 0.6,
    "FALSE_POSITIVE": 0.0,
}


def prioritise(f: Finding) -> dict[str, Any]:
    """Compute a transparent priority score with explicit assumptions.

    This is NOT a CVSS score. It is a bounded internal ranking heuristic:
    base severity x confidence factor x validation factor. Unknown values
    stay unknown and are reported as assumptions.
    """
    base = SEVERITY_BASE.get(f.severity, SEVERITY_BASE["unknown"])
    conf = CONFIDENCE_FACTOR.get(f.confidence, CONFIDENCE_FACTOR["unknown"])
    val = VALIDATION_FACTOR.get(f.validation_status, 0.8)
    score = round(base * conf * val, 2)
    assumptions: list[str] = []
    if f.severity == "unknown":
        assumptions.append("Severity unknown; base weight of 3.0 applied provisionally.")
    if f.confidence == "unknown":
        assumptions.append("Confidence unknown; medium-low factor 0.75 applied.")
    if f.validation_status in {"DETECTED", "INCONCLUSIVE"}:
        assumptions.append(
            f"Validation status {f.validation_status}; score discounted pending evidence."
        )
    return {
        "score": score,
        "base_severity": f.severity,
        "confidence_factor": conf,
        "validation_factor": val,
        "assumptions": assumptions,
        "note": "Internal ranking heuristic, not a CVSS calculation.",
    }
