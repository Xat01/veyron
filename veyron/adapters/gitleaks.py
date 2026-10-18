"""Gitleaks adapter — secret detection (MIT, free).

Secrets are detected locally. Values are redacted from the finding
evidence; they are never transmitted, never used to authenticate, and
never validated against external services.
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from ..finding import Finding, stable_finding_id
from ..redact import redact_text
from ..subproc import run_command, which
from .base import ScannerAdapter, ScanResult


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    kind = "secret"

    def __init__(self, *, executable: str | None = None, timeout: int = 600, config: dict[str, Any] | None = None):
        super().__init__(executable=executable or "gitleaks", timeout=timeout, config=config)

    def validate_config(self) -> tuple[bool, str | None]:
        if not self.executable:
            return False, "gitleaks executable not configured"
        if which(self.executable) is None and not Path(self.executable).exists():
            return False, f"gitleaks not found: {self.executable}"
        return True, None

    def version(self) -> str | None:
        res = run_command([self.executable, "version"], timeout=30)
        if res.error or res.returncode != 0:
            return None
        out = (res.stdout or res.stderr).strip()
        return out.splitlines()[0] if out else None

    def scan(self, root: Path, files: list[Path] | None = None) -> ScanResult:
        started = time.monotonic()
        ok, reason = self.validate_config()
        if not ok:
            return ScanResult(scanner=self.name, ok=False, failure_kind="missing_executable", error=reason)

        scan_history = bool(self.config.get("scan_history", False))
        scope = "git history (all refs)" if scan_history else "working tree"
        args = [self.executable, "detect", "--report-format=json", "--no-banner",
                "--exit-code=1", "--source", str(root)]
        if scan_history:
            args.append("--log-opts=all")  # scope made explicit in metadata
        else:
            # Scan only the working tree. Without --no-git, gitleaks inspects
            # git history by default, which makes findings depend on what has
            # been committed rather than on the files being assessed.
            args.append("--no-git")

        # gitleaks writes its JSON report to --report-path (stdout is not a
        # reliable channel across versions), so capture it explicitly. The
        # file must be read while the temp directory still exists.
        with tempfile.TemporaryDirectory(prefix="veyron-gl-") as td:
            report_path = Path(td) / "report.json"
            args += ["--report-path", str(report_path)]
            res = run_command(args, timeout=self.timeout)
            duration = time.monotonic() - started
            raw = report_path.read_text(encoding="utf-8", errors="replace").strip() if report_path.exists() else ""

        if res.timed_out:
            return ScanResult(scanner=self.name, ok=False, failure_kind="timeout",
                              error=f"gitleaks timed out after {self.timeout}s",
                              duration_seconds=duration)
        if res.error:
            return ScanResult(scanner=self.name, ok=False, failure_kind="missing_executable",
                              error=res.error, duration_seconds=duration)

        # gitleaks exit codes: 0 = no leaks, 1 = leaks found, >=2 = error
        if res.returncode not in (0, 1):
            return ScanResult(scanner=self.name, ok=False, failure_kind="nonzero_exit",
                              error=f"gitleaks exit {res.returncode}: {res.stderr.strip()[:400]}",
                              duration_seconds=duration, exit_code=res.returncode)

        if not raw:
            # exit 0 = clean. exit 1 with no report means an error the
            # binary did not surface as a nonzero-exit failure.
            if res.returncode == 0:
                return ScanResult(scanner=self.name, ok=True, findings=[],
                                  tool_version=self.version(), duration_seconds=duration,
                                  exit_code=res.returncode,
                                  metadata={"scan_scope": scope})
            return ScanResult(scanner=self.name, ok=False, failure_kind="malformed_output",
                              error="gitleaks exit 1 with empty report", duration_seconds=duration,
                              exit_code=res.returncode)

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return ScanResult(scanner=self.name, ok=False, failure_kind="malformed_output",
                              error="gitleaks output is not valid JSON", duration_seconds=duration,
                              exit_code=res.returncode, raw_output=raw[:1000])

        if not isinstance(payload, list):
            return ScanResult(scanner=self.name, ok=False, failure_kind="malformed_output",
                              error="gitleaks JSON report is not a list", duration_seconds=duration,
                              exit_code=res.returncode)

        findings = [f for f in (self._to_finding(x) for x in payload) if f]
        return ScanResult(scanner=self.name, ok=True, findings=findings,
                          tool_version=self.version(), duration_seconds=duration,
                          exit_code=res.returncode,
                          metadata={"scan_scope": scope, "leak_count": len(findings)})

    def _to_finding(self, item: dict[str, Any]) -> Finding | None:
        try:
            rule_id = item.get("RuleID") or item.get("rule") or "gitleaks.unknown"
            desc = item.get("Description") or rule_id
            fname = item.get("File") or ""
            line = item.get("StartLine")
            # Redact everything: never store the raw secret value.
            commit = item.get("Commit", "")
            # The detected value exists but is always replaced: the report
            # records THAT a value was found, never WHAT it was.
            raw_secret = str(item.get("Secret") or item.get("Match") or "")
            evidence = redact_text(
                f"rule={rule_id}\ndescription={desc}\nfile={fname}:{line}\n"
                f"commit={str(commit)[:12]}\nvalue={raw_secret}"
            )
            fid = stable_finding_id("secret.gitleaks", rule_id, fname, line, desc)
            return Finding(
                id=fid,
                title=f"Potential secret: {desc}",
                description=(f"A potential secret was detected matching rule '{rule_id}'. "
                             "Value redacted. This is a candidate, not a verified active credential."),
                category="secret-exposure",
                severity="high",
                confidence="medium",
                validation_status="DETECTED",
                source="secret.gitleaks",
                file_path=fname,
                line=line,
                evidence=evidence,
                remediation="Rotate the credential, remove it from history where feasible, "
                            "and load future secrets from a secret manager or environment variable.",
                rule_id=rule_id,
                tool="gitleaks",
                raw={"File": fname, "StartLine": line, "RuleID": rule_id,
                     "Entropy": item.get("Entropy"), "Tags": item.get("Tags", [])},
            )
        except (KeyError, TypeError, ValueError):
            return None
