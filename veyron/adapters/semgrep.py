"""Semgrep Community Edition adapter (SAST).

Invokes `semgrep scan --json` with an argument array, parses its JSON
output, and normalises results into VEYRON findings while preserving the
original rule match as evidence.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..finding import Finding, stable_finding_id
from ..subproc import run_command, which
from .base import ScannerAdapter, ScanResult

# Free Semgrep registry ruleset used when no config is given. `auto` cannot
# be combined with --metrics=off (privacy default), so we pin a named
# registry ruleset instead. Rules download once and are cached by semgrep.
DEFAULT_CONFIG = "p/default"


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    kind = "sast"

    def __init__(self, *, executable: str | None = None, timeout: int = 600, config: dict[str, Any] | None = None):
        super().__init__(executable=executable or "semgrep", timeout=timeout, config=config)

    def validate_config(self) -> tuple[bool, str | None]:
        if not self.executable:
            return False, "semgrep executable not configured"
        if which(self.executable) is None and not Path(self.executable).exists():
            return False, f"semgrep not found: {self.executable}"
        return True, None

    def version(self) -> str | None:
        res = run_command([self.executable, "--version"], timeout=30)
        if res.error or res.returncode != 0:
            return None
        first = (res.stdout or res.stderr).strip().splitlines()
        return first[0].strip() if first else None

    def scan(self, root: Path, files: list[Path] | None = None) -> ScanResult:
        started = time.monotonic()
        ok, reason = self.validate_config()
        if not ok:
            return ScanResult(
                scanner=self.name, ok=False, failure_kind="missing_executable",
                error=reason, duration_seconds=0.0,
            )

        config = str(self.config.get("config", DEFAULT_CONFIG))
        args = [
            self.executable, "scan",
            "--json", "--quiet",
            "--config", config,
            "--timeout", str(int(self.timeout)),
        ]
        if self.config.get("metrics_off", True):
            args.append("--metrics=off")
        args.append(str(root))

        res = run_command(args, timeout=self.timeout + 30)
        duration = time.monotonic() - started

        if res.timed_out:
            return ScanResult(
                scanner=self.name, ok=False, failure_kind="timeout",
                error=f"semgrep timed out after {self.timeout}s",
                duration_seconds=duration, tool_version=self.version(),
            )
        if res.error:
            return ScanResult(
                scanner=self.name, ok=False, failure_kind="missing_executable",
                error=res.error, duration_seconds=duration,
            )

        payload: Any
        try:
            payload = json.loads(res.stdout) if res.stdout.strip() else None
        except json.JSONDecodeError:
            err = res.stderr.strip()[:500] or res.stdout.strip()[:500]
            return ScanResult(
                scanner=self.name, ok=False, failure_kind="malformed_output",
                error="semgrep produced non-JSON output", raw_output=res.stdout[:2000],
                duration_seconds=duration, exit_code=res.returncode,
                metadata={"stderr": err},
            )

        if payload is None:
            # Empty stdout: distinguish scanner error (bad exit) from silence.
            if res.returncode not in (0, 1):
                err = res.stderr.strip()[:500]
                return ScanResult(
                    scanner=self.name, ok=False, failure_kind="nonzero_exit",
                    error=f"semgrep exit {res.returncode}: {err}",
                    duration_seconds=duration, exit_code=res.returncode,
                )
            return ScanResult(
                scanner=self.name, ok=False, failure_kind="malformed_output",
                error="empty semgrep JSON payload", duration_seconds=duration,
                exit_code=res.returncode,
            )

        if res.returncode not in (0, 1) or (isinstance(payload, dict) and payload.get("errors") and not payload.get("results")):
            # semgrep exits 1 when findings exist under --error; other codes
            # with error payload mean the scan did not complete.
            if res.returncode not in (0, 1):
                errs = payload.get("errors", []) if isinstance(payload, dict) else []
                return ScanResult(
                    scanner=self.name, ok=False, failure_kind="nonzero_exit",
                    error=f"semgrep exit {res.returncode}: {json.dumps(errs)[:400]}",
                    duration_seconds=duration, exit_code=res.returncode,
                )

        results = payload.get("results", []) if isinstance(payload, dict) else []
        findings = [self._to_finding(item) for item in results]
        findings = [f for f in findings if f is not None]

        return ScanResult(
            scanner=self.name, ok=True, findings=findings,
            tool_version=self.version(), duration_seconds=duration,
            exit_code=res.returncode,
            metadata={
                "config": config,
                "errors": payload.get("errors", []) if isinstance(payload, dict) else [],
                "paths_scanned": len(payload.get("paths", {}).get("scanned", [])) if isinstance(payload, dict) else None,
            },
        )

    def _to_finding(self, item: dict[str, Any]) -> Finding | None:
        try:
            check = item.get("check_id", "semgrep.unknown")
            extra = item.get("extra", {}) or {}
            message = (extra.get("message") or check).strip()
            start = (item.get("start") or {})
            path = item.get("path") or ""
            line = start.get("line")
            severity_raw = (extra.get("severity") or "INFO")
            severity = {
                "ERROR": "high",
                "WARNING": "medium",
                "INFO": "info",
            }.get(str(severity_raw).upper(), "unknown")
            metadata = extra.get("metadata", {}) or {}
            category = str(metadata.get("cwe") or metadata.get("category") or "generic").split("(")[0].strip()
            lines = extra.get("lines") or ""
            remediation = None
            fix = extra.get("fix") or metadata.get("fix")
            if fix:
                remediation = str(fix)
            fid = stable_finding_id("sast.semgrep", check, path, line, message)
            return Finding(
                id=fid,
                title=message.splitlines()[0][:200],
                description=message,
                category=category,
                severity=severity,
                confidence="medium",  # static rule match; not yet validated
                validation_status="DETECTED",
                source="sast.semgrep",
                file_path=path,
                line=line,
                evidence=f"rule={check}\n{lines}".strip(),
                remediation=remediation,
                rule_id=check,
                tool="semgrep",
                advisory_refs=[str(m) for m in metadata.get("references", []) or []][:10],
                raw=item,
            )
        except (KeyError, TypeError, ValueError):
            return None
