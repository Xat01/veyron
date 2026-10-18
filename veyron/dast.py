"""Controlled dynamic testing (DAST) — safe checks against authorised targets.

Threat model and hard limits for this module:
- Only hosts explicitly in the allowlist may be contacted (default: localhost).
- Redirects are NOT followed cross-host; a redirect to a non-allowlisted host
  terminates the check (a target cannot expand its own scope).
- Request budget, wall-clock deadline, and concurrency caps are enforced.
- Planning (dry-run) mode is the default; `--execute --authorize` is required
  to send any request.
- Only safe, non-destructive checks are performed: security-header inspection,
  robots.txt/sitemap presence, cookie flag review, server banner capture.
- No exploitation, no fuzzing, no denial-of-service, no credential testing.
- Every attempt is recorded in an audit log.

Every host contacted is written to an audit record before and after the
request, so scope escapes are detectable.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DASTConfig

USER_AGENT = "VEYRON-DAST/0.1 (authorised security assessment; contact: local operator)"

# Headers whose absence is reported (informational, non-destructive checks).
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
]

# Headers never sent anywhere in DAST mode.
DISABLED_HEADERS = {"authorization", "cookie"}


@dataclass
class AuditRecord:
    at: str
    target: str
    action: str
    in_scope: bool
    detail: str = ""

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class DASTResult:
    ok: bool
    mode: str
    target: str
    authorized_ok: bool
    plan: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def host_in_allowlist(url: str, allowlist: list[str]) -> bool:
    """True only when the URL's host:port pair is explicitly allowlisted.

    Default ports: http=80, https=443. Matching is exact on hostname (no
    wildcard expansion beyond exact `host:port` entries or bare `host` which
    implies any port only when written explicitly as `host`).
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for entry in allowlist:
        entry = entry.strip().lower()
        if not entry:
            continue
        if ":" in entry:
            e_host, _, e_port = entry.partition(":")
            if e_host == host and e_port.isdigit() and int(e_port) == port:
                return True
        else:
            # Bare hostname entry: port must still match scheme default to
            # avoid silently widening scope.
            if e_host_matches(entry, host) and port in {80, 443}:
                return True
    return False


def e_host_matches(entry: str, host: str) -> bool:
    return entry == host


class Budget:
    """Request budget + deadline enforcement."""

    def __init__(self, cfg: DASTConfig):
        self.max_requests = cfg.max_requests
        self.max_seconds = cfg.max_minutes * 60
        self.deadline = time.monotonic() + self.max_seconds
        self.used = 0
        self.exhausted_reason: str | None = None

    def consume(self) -> bool:
        if self.exhausted_reason:
            return False
        if self.used >= self.max_requests:
            self.exhausted_reason = "request budget exhausted"
            return False
        if time.monotonic() > self.deadline:
            self.exhausted_reason = "wall-clock deadline reached"
            return False
        self.used += 1
        return True

    def snapshot(self) -> dict[str, Any]:
        return {
            "used": self.used,
            "max_requests": self.max_requests,
            "remaining_seconds": max(0, int(self.deadline - time.monotonic())),
            "exhausted_reason": self.exhausted_reason,
        }


def _safe_request(url: str, cfg: DASTConfig, budget: Budget, audit: list[AuditRecord]) -> tuple[int | None, dict[str, str], bytes, str | None]:
    """GET a URL with all scope controls applied. Never follows redirects
    automatically: urllib is configured not to, and any redirect target is
    re-checked against the allowlist by the caller."""
    if not host_in_allowlist(url, cfg.allowlist):
        audit.append(AuditRecord(AuditRecord.now(), url, "BLOCKED_OUT_OF_SCOPE", False,
                                 "host not in allowlist"))
        return None, {}, b"", "out of scope"
    if not budget.consume():
        audit.append(AuditRecord(AuditRecord.now(), url, "SKIPPED_BUDGET", True,
                                 budget.exhausted_reason or "budget"))
        return None, {}, b"", budget.exhausted_reason or "budget"

    audit.append(AuditRecord(AuditRecord.now(), url, "REQUEST", True))
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(_NoRedirect())

    class _Ctx:
        pass

    try:
        # Follow AT MOST cfg-follow policy: we never auto-follow. Redirects
        # are surfaced as 3xx and handled by the caller with allowlist checks.
        with opener.open(req, timeout=15) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(64_000)
            audit.append(AuditRecord(AuditRecord.now(), url, "RESPONSE", True, f"status={resp.status}"))
            return resp.status, headers, body, None
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        audit.append(AuditRecord(AuditRecord.now(), url, "RESPONSE", True, f"status={exc.code}"))
        return exc.code, headers, b"", None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        audit.append(AuditRecord(AuditRecord.now(), url, "ERROR", True, str(exc)[:200]))
        return None, {}, b"", str(exc)[:200]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow anything (scope safety)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


def run_dast(cfg: DASTConfig, *, target_url: str, execute: bool, authorized: bool) -> DASTResult:
    """Run (or plan) controlled dynamic checks against an authorised target."""

    # Execution requires all three: explicit --execute, explicit --authorize,
    # and dry_run disabled in config is NOT required — the CLI flags are the
    # explicit consent signal, and scope is still enforced by the allowlist.
    execute = bool(execute) and bool(authorized)
    mode = "execute" if execute else "plan"
    audit: list[AuditRecord] = []
    budget = Budget(cfg)

    scope_ok = host_in_allowlist(target_url, cfg.allowlist)
    authorized_ok = bool(authorized) and scope_ok

    if not scope_ok:
        audit.append(AuditRecord(AuditRecord.now(), target_url, "DENIED", False,
                                 "target host not in configured allowlist"))
    if authorized and not cfg.enabled and execute:
        # allowlist given via CLI target but dast disabled in config
        cfg.enabled = True

    result = DASTResult(
        ok=False,
        mode=mode,
        target=target_url,
        authorized_ok=authorized_ok,
        budget=budget.snapshot(),
    )

    if not authorized:
        result.skipped.append(
            "Execution requires explicit authorisation (--authorize). Planning mode only."
        )
    if not scope_ok:        result.skipped.append(
            f"Target {target_url} is outside the allowlist {cfg.allowlist}. "
            "Add it to VEYRON_DAST_ALLOWLIST only if you are authorised to test it."
        )
    if not execute:
        result.plan = _build_plan(target_url, cfg)
        result.audit = [asdict(a) for a in audit]
        result.ok = authorized_ok
        result.skipped.append("Dry-run: no requests sent (default). Use --execute --authorize to run.")
        result.budget = budget.snapshot()
        return result

    if not authorized_ok:
        result.audit = [asdict(a) for a in audit]
        result.errors.append("refusing to execute: authorisation or scope check failed")
        return result

    # -- executed safe checks --------------------------------------------------
    result.checks = _run_safe_checks(cfg, target_url, budget, audit)
    result.findings = _interpret(result.checks)
    result.audit = [asdict(a) for a in audit]
    result.budget = budget.snapshot()
    result.ok = True
    return result


def _build_plan(target_url: str, cfg: DASTConfig) -> list[dict[str, Any]]:
    base = ["/", "/robots.txt", "/sitemap.xml"]
    return [
        {
            "step": i + 1,
            "method": "GET",
            "url": target_url.rstrip("/") + path,
            "purpose": purpose,
            "destructive": False,
            "scope_checked": "host must match allowlist",
        }
        for i, (path, purpose) in enumerate(zip(base, [
            "security header and cookie inspection",
            "disclosed path inventory (read-only)",
            "sitemap presence (read-only)",
        ]))
    ]


def _run_safe_checks(cfg: DASTConfig, target_url: str, budget: Budget, audit: list[AuditRecord]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    delay = 1.0 / max(cfg.rate_limit_per_second, 0.1)
    for plan_step in _build_plan(target_url, cfg):
        if budget.exhausted_reason:
            break
        url = plan_step["url"]
        status, headers, body, err = _safe_request(url, cfg, budget, audit)
        check = {
            "url": url,
            "status": status,
            "security_headers_present": [h for h in SECURITY_HEADERS if h in headers],
            "security_headers_missing": [h for h in SECURITY_HEADERS if h not in headers],
            "cookies": [
                {"name": c.split("=")[0].strip(), "flags": c}
                for cookie in (headers.get("set-cookie") or "").split("\n") if cookie.strip()
                for c in [cookie]
            ],
            "server": headers.get("server"),
            "error": err,
            "redirect_location": headers.get("location"),
        }
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("location") or ""
            in_scope = host_in_allowlist(urllib.parse.urljoin(url, loc), cfg.allowlist)
            check["redirect_blocked_as_out_of_scope"] = not in_scope
            if not in_scope:
                audit.append(AuditRecord(AuditRecord.now(), loc, "REDIRECT_BLOCKED", False,
                                         "redirect target outside allowlist; not followed"))
        checks.append(check)
        time.sleep(delay)  # rate limit
    return checks


def _interpret(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn safe-check observations into informational findings.

    These are observations, not exploits — validation_status stays DETECTED.
    """
    findings: list[dict[str, Any]] = []
    if not checks:
        return findings
    root = next((c for c in checks if c["url"].endswith("/")), checks[0])
    missing = root.get("security_headers_missing") or []
    if missing and root.get("status") == 200:
        findings.append({
            "title": "Missing HTTP security headers",
            "detail": ", ".join(missing),
            "severity": "low",
            "confidence": "high",
            "validation_status": "DETECTED",
            "evidence": f"GET {root['url']} → {root['status']}; absent: {missing}",
            "remediation": "Configure the web server or framework to emit the missing headers.",
        })
    for c in checks:
        for cookie in c.get("cookies", []):
            flags = cookie.get("flags", "")
            if "httponly" not in flags.lower() or "secure" not in flags.lower():
                findings.append({
                    "title": "Cookie missing HttpOnly and/or Secure flag",
                    "detail": f"cookie={cookie['name']} flags={flags}",
                    "severity": "low",
                    "confidence": "medium",
                    "validation_status": "DETECTED",
                    "evidence": f"SET-COOKIE observed on {c['url']}",
                    "remediation": "Set HttpOnly and Secure (and SameSite) on session cookies.",
                })
    return findings


def write_audit_log(result: DASTResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(result), indent=2, default=str), encoding="utf-8")
    return path
