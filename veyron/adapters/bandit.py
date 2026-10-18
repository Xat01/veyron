"""Bandit adapter — Python-focused SAST (LGPL-3.0, free)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..finding import Finding, stable_finding_id
from ..subproc import run_command, which
from .base import ScannerAdapter, ScanResult

SEVERITY_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
CONFIDENCE_MAP = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class BanditAdapter(ScannerAdapter):
    name = "bandit"
    kind = "sast"

    def __init__(self, *, executable: str | None = None, timeout: int = 600, config: dict[str, Any] | None = None):
        super().__init__(executable=executable or "bandit", timeout=timeout, config=config)

    def validate_config(self) -> tuple[bool, str | None]:
        if not self.executable:
            return False, "bandit executable not configured"
        if which(self.executable) is None and not Path(self.executable).exists():
            return False, f"bandit not found: {self.executable}"
        return True, None

    def version(self) -> str | None:
        res = run_command([self.executable, "--version"], timeout=30)
        if res.error:
            return None
        combined = (res.stdout or "") + (res.stderr or "")
        for line in combined.splitlines():
            line = line.strip()
            if "bandit" in line.lower():
                return line
        return None

    def scan(self, root: Path, files: list[Path] | None = None) -> ScanResult:
        started = time.monotonic()
        ok, reason = self.validate_config()
        if not ok:
            return ScanResult(scanner=self.name, ok=False, failure_kind="missing_executable", error=reason)

        args = [self.executable, "-r", "-f", "json", "--quiet", str(root)]
        res = run_command(args, timeout=self.timeout)
        duration = time.monotonic() - started

        if res.timed_out:
            return ScanResult(scanner=self.name, ok=False, failure_kind="timeout",
                              error=f"bandit timed out after {self.timeout}s", duration_seconds=duration)
        if res.error:
            return ScanResult(scanner=self.name, ok=False, failure_kind="missing_executable",
                              error=res.error, duration_seconds=duration)

        # bandit exits 1 when issues are found; 0 clean; >1 error.
        if res.returncode not in (0, 1):
            return ScanResult(scanner=self.name, ok=False, failure_kind="nonzero_exit",
                              error=f"bandit exit {res.returncode}: {res.stderr.strip()[:400]}",
                              duration_seconds=duration, exit_code=res.returncode)

        if not res.stdout.strip():
            if res.returncode == 0:
                return ScanResult(scanner=self.name, ok=True, findings=[],
                                   tool_version=self.version(), duration_seconds=duration,
                                   exit_code=res.returncode)
            return ScanResult(scanner=self.name, ok=False, failure_kind="malformed_output",
                              error="bandit produced no JSON output", duration_seconds=duration,
                              exit_code=res.returncode, raw_output=res.stderr[:1000])

        try:
            payload = json.loads(res.stdout)
        except json.JSONDecodeError:
            return ScanResult(scanner=self.name, ok=False, failure_kind="malformed_output",
                              error="bandit output is not valid JSON", duration_seconds=duration,
                              exit_code=res.returncode, raw_output=res.stdout[:1000])

        results = payload.get("results", []) if isinstance(payload, dict) else []
        findings = [f for f in (self._to_finding(r) for r in results) if f]
        return ScanResult(scanner=self.name, ok=True, findings=findings,
                          tool_version=self.version(), duration_seconds=duration,
                          exit_code=res.returncode,
                          metadata={"metrics": payload.get("metrics", {}).get("_totals", {}) if isinstance(payload, dict) else {}})

    def _to_finding(self, item: dict[str, Any]) -> Finding | None:
        try:
            test_id = item.get("test_id") or "B000"
            msg = (item.get("issue_text") or test_id).strip()
            fname = item.get("filename") or ""
            line = item.get("line_number")
            sev = SEVERITY_MAP.get(str(item.get("issue_severity", "")).upper(), "unknown")
            conf = CONFIDENCE_MAP.get(str(item.get("issue_confidence", "")).upper(), "unknown")
            fid = stable_finding_id("sast.bandit", test_id, fname, line, msg)
            return Finding(
                id=fid,
                title=msg.splitlines()[0][:200],
                description=msg,
                category=str(item.get("issue_cwe", {}).get("id", "generic")) if isinstance(item.get("issue_cwe"), dict) else "generic",
                severity=sev,
                confidence=conf,
                validation_status="DETECTED",
                source="sast.bandit",
                file_path=fname,
                line=line,
                evidence=f"rule={test_id}\n{item.get('code', '').strip()}",
                remediation=item.get("more_info"),
                rule_id=test_id,
                tool="bandit",
                raw=item,
            )
        except (KeyError, TypeError, ValueError):
            return None
