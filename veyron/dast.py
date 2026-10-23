"""Controlled dynamic testing (DAST) — safe checks against authorised targets.

Transport now uses the shared `HttpClient` (`veyron.net.client`) so that every
outbound request benefits from scope enforcement, proxy routing with fail-closed
proxy behaviour, redirect validation, request budgets, timeouts and TLS
verification — consistent with the rest of VEYRON.

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
import re
import time
from html.parser import HTMLParser
from typing import Any

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .net.client import HttpClient, HttpResponse, SENSITIVE_KEYS, redact_url
from .net.scope import Scope

from .assessment import (
    AssessmentSpec,
    Identity,
    PROFILE_CONTROLLED_VALIDATION,
    PROFILE_LAB_EXPLOIT,
    PROFILE_PASSIVE,
    PROFILE_SAFE_ACTIVE,
    normalize_profile,
)
from .checks import CheckContext, run_checks
from .checks.callback import CallbackListener
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

# Standard disclosure endpoint checked by the safe-active profile.
SECURITY_TXT_PATH = "/.well-known/security.txt"

# Read-only fingerprint patterns for accidental information disclosure in
# response bodies. These match *diagnostic text*, never user content.
DISCLOSURE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)traceback \(most recent call last\)", "Python traceback"),
    (r"(?i)fatal error:", "PHP fatal error"),
    (r"(?i)you have an error in your sql syntax", "SQL syntax error"),
    (r"(?i)warning:\s*mysql", "MySQL warning"),
    (r"(?i)\bORA-\d{5}\b", "Oracle error code"),
    (r"(?i)stack trace:", "stack trace"),
    (r"(?i)\bdebug\s*=\s*true\b", "debug flag enabled"),
    (r"(?i)at\s+[\w.$]+\([\w.]+\.java:\d+\)", "Java stack frame"),
]


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
    profile: str = "passive"
    plan: list[dict[str, Any]] = field(default_factory=list)
    checks: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    audit: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    authorization: dict[str, Any] = field(default_factory=dict)


def host_in_allowlist(url: str, allowlist: list[str]) -> bool:
    """True only when the URL's host:port pair is explicitly allowlisted.

    Default ports: http=80, https=443. Matching is exact on hostname (no
    wildcard expansion beyond exact `host:port` entries or bare `host` which
    implies any port only when written explicitly as `host`).
    """
    parsed = urlparse(url)
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


def allowlist_entry_for_url(url: str) -> str | None:
    """Return the explicit ``host:port`` entry for an http(s) URL.

    Used by the CLI so an operator can authorise the exact URL they typed
    without editing the persistent allowlist first.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.hostname.lower()}:{port}"


class Budget:
    """Request budget + deadline + emergency-stop enforcement."""

    def __init__(self, cfg: DASTConfig):
        self.max_requests = cfg.max_requests
        self.max_seconds = cfg.max_minutes * 60
        self.deadline = time.monotonic() + self.max_seconds
        self.used = 0
        self.stop_file = cfg.stop_file
        self.exhausted_reason: str | None = None

    def consume(self) -> bool:
        if self.exhausted_reason:
            return False
        if self.stop_file and Path(self.stop_file).exists():
            self.exhausted_reason = "emergency stop requested"
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


def _cookie_summary(set_cookie: str) -> list[dict[str, str]]:
    """Summarise Set-Cookie headers without retaining cookie values.

    A cookie value is a session credential — it must never reach a report.
    Only the cookie NAME and its security-relevant attributes (HttpOnly,
    Secure, SameSite) are kept, which is exactly what the cookie-flag
    analysis needs.

    The previous implementation put the whole Set-Cookie string into the
    "flags" field, which leaked session tokens into DAST reports.
    """
    out: list[dict[str, str]] = []
    for raw in (set_cookie or "").split("\n"):
        raw = raw.strip()
        if not raw:
            continue
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].partition("=")[0].strip()
        if not name:
            continue
        attrs = [a for a in parts[1:]
                 if a.partition("=")[0].strip().lower() in {"httponly", "secure", "samesite"}]
        out.append({"name": name, "flags": "; ".join(attrs)})
    return out


def _redact_location(loc: str) -> str:
    """Mask sensitive query values in a Location header.

    Redirect targets are recorded in the check output, so any token carried
    in the query string has to be masked first.
    """
    if not loc or "?" not in loc:
        return loc
    base, _, query = loc.partition("?")
    pairs: list[str] = []
    for pair in query.split("&"):
        name, sep, _value = pair.partition("=")
        if sep and name.lower() in SENSITIVE_KEYS:
            pairs.append(f"{name}=***")
        else:
            pairs.append(pair)
    return base + "?" + "&".join(pairs)


def _origin(url: str) -> tuple[str, str, int]:
    """Return (scheme, host, port) with scheme-default ports normalised."""
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


class _PageParser(HTMLParser):
    """Extract links, subresources, and forms from an HTML page.

    Parsing is strictly passive: nothing here fetches a resource, executes
    script, or submits a form.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.resources: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.title = ""
        self._current_form: dict[str, Any] | None = None
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in {"a", "area"} and a.get("href"):
            self.links.append(a["href"])
        if tag == "title":
            self._in_title = True
        if tag in {"script", "img", "iframe", "frame", "source", "video",
                   "audio", "embed", "object", "link"}:
            for key in ("src", "href", "data"):
                if a.get(key):
                    self.resources.append(a[key])
        if tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "has_credential_field": False,
                "fields": [],
            }
            self.forms.append(self._current_form)
        elif self._current_form is not None and tag in {"input", "select", "textarea", "button"}:
            name = a.get("name", "")
            ftype = (a.get("type") or tag).lower()
            if name:
                self._current_form["fields"].append({"name": name, "type": ftype})
            if ftype == "password":
                self._current_form["has_credential_field"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 300:
            self.title += data


def _looks_like_html(headers: dict[str, str], body: bytes) -> bool:
    content_type = headers.get("content-type", "").lower()
    if "html" in content_type:
        return True
    head = body[:512].lstrip().lower()
    return head.startswith(b"<!doctype html") or head.startswith(b"<html")


def _analyse_page(page_url: str, body: bytes, headers: dict[str, str], root_url: str) -> dict[str, Any]:
    """Passive HTML analysis for one in-scope page."""
    analysis: dict[str, Any] = {
        "title": "",
        "links": [],
        "forms": [],
        "mixed_content": [],
        "external_resources": [],
        "disclosure": [],
        "plaintext_login_form": False,
        "cross_origin_form_actions": [],
    }
    if not _looks_like_html(headers, body):
        return analysis

    parser = _PageParser()
    try:
        parser.feed(body.decode("utf-8", "replace"))
    except Exception as exc:  # defensive: malformed markup must not abort a run
        analysis["parse_error"] = type(exc).__name__
    analysis["title"] = " ".join(parser.title.split())[:200]

    root_origin = _origin(root_url)
    page_origin = _origin(page_url)
    https_page = page_url.startswith("https://")

    seen_links: set[str] = set()
    for raw in parser.links:
        absolute = urljoin(page_url, raw.strip()).split("#", 1)[0]
        if not absolute.startswith(("http://", "https://")):
            continue
        embedded = urlparse(absolute)
        if embedded.username or embedded.password:
            # Never send or record URL-embedded credentials, even if a page
            # author put them there.
            continue
        if _origin(absolute) != root_origin:
            # Off-target links are evidence of external coupling, never crawl
            # targets. Record the host only, never the full query string.
            host = urlparse(absolute).hostname or ""
            if host and host not in analysis["external_resources"]:
                analysis["external_resources"].append(host)
            continue
        if absolute not in seen_links:
            seen_links.add(absolute)
            analysis["links"].append(absolute)

    for resource in parser.resources:
        absolute = urljoin(page_url, resource.strip())
        if https_page and absolute.startswith("http://"):
            redacted = redact_url(absolute)
            if redacted not in analysis["mixed_content"]:
                analysis["mixed_content"].append(redacted)
        elif _origin(absolute) != root_origin:
            host = urlparse(absolute).hostname or ""
            if host and host not in analysis["external_resources"]:
                analysis["external_resources"].append(host)

    for form in parser.forms:
        action = urljoin(page_url, form["action"] or page_url)
        cross_origin = _origin(action) != root_origin
        record = {
            "action": redact_url(action),
            "method": form["method"],
            "has_credential_field": form["has_credential_field"],
            "field_count": len(form["fields"]),
            "cross_origin": cross_origin,
        }
        analysis["forms"].append(record)
        if cross_origin:
            analysis["cross_origin_form_actions"].append(redact_url(action))
        if form["has_credential_field"] and page_origin[0] == "http" and not action.startswith("https://"):
            analysis["plaintext_login_form"] = True

    text = body.decode("utf-8", "replace")
    for pattern, label in DISCLOSURE_PATTERNS:
        if re.search(pattern, text):
            if label not in analysis["disclosure"]:
                analysis["disclosure"].append(label)

    return analysis


def _scope_for_allowlist(cfg: DASTConfig) -> Scope:
    """Build a Scope from the DAST allowlist entries.

    `Scope.from_allowlist` uses the same rule as `host_in_allowlist`: a bare
    host covers only the scheme default ports (80/443), and a `host:port`
    entry covers exactly that port. Both are derived from the same
    `cfg.allowlist`, so the set of hosts DAST is willing to talk to and the
    set the HTTP client will actually contact are identical.
    """
    return Scope.from_allowlist([entry for entry in cfg.allowlist if entry.strip()])


def assessment_spec_from_dast(cfg: DASTConfig) -> AssessmentSpec:
    """Convert DAST settings into the shared authorization model."""
    identities = []
    for item in cfg.identities:
        if isinstance(item, dict) and item.get("name"):
            identities.append(Identity(
                name=str(item["name"]),
                headers={str(k): str(v) for k, v in dict(item.get("headers", {})).items()},
                privilege=str(item.get("privilege", "low")),
            ))
    return AssessmentSpec(
        profile=normalize_profile(cfg.profile),
        authorized_hosts=list(cfg.allowlist),
        permitted_paths=list(cfg.permitted_paths),
        exclusions=list(cfg.exclusions),
        max_requests=cfg.max_requests,
        max_rate_per_second=cfg.rate_limit_per_second,
        connection_timeout_seconds=float(cfg.timeout_seconds),
        deadline_seconds=cfg.max_minutes * 60,
        max_concurrency=cfg.max_concurrency,
        evidence_retention=cfg.evidence_retention,
        stop_file=cfg.stop_file,
        lab_environment=cfg.lab_environment,
        identities=identities,
        callback_url=cfg.callback_url,
        access_control_rules=list(cfg.access_control_rules),
    )


def _build_http_client(cfg: DASTConfig, spec: AssessmentSpec | None = None) -> HttpClient:
    """Build the one shared client used for the whole DAST run."""
    try:
        from .config import Config as _Cfg

        _live_cfg = _Cfg.load()
        _proxy = getattr(_live_cfg, "proxy", None)
        proxy_cfg = _proxy if _proxy is not None and _proxy.configured else None
        _network = getattr(_live_cfg, "network", None)
        verify_tls = getattr(_network, "verify_tls", True)
    except Exception:  # pragma: no cover — config load failure means proxy unset
        proxy_cfg = None
        verify_tls = True
    return HttpClient(
        scope=(spec or assessment_spec_from_dast(cfg)).scope(),
        proxy=proxy_cfg,
        timeout=cfg.timeout_seconds,
        verify_tls=verify_tls,
        max_requests=cfg.max_requests,
        rate_limit_per_second=cfg.rate_limit_per_second,
        max_redirects=cfg.max_redirects,
        user_agent=USER_AGENT,
    )


def _safe_request(url: str, cfg: DASTConfig, budget: Budget, audit: list[AuditRecord],
                  *, method: str = "GET",
                  client: HttpClient | None = None) -> tuple[int | None, dict[str, str], bytes, str | None]:
    """GET a URL via the shared HttpClient, preserving the same return shape.

    Scope, proxy routing with fail-closed behaviour, redirect validation,
    request budgets, timeouts, cancellation and TLS verification are
    enforced by HttpClient; only the DAST audit and check models are kept.
    The old urllib path is gone.
    """
    if not host_in_allowlist(url, cfg.allowlist):
        audit.append(AuditRecord(AuditRecord.now(), url, "BLOCKED_OUT_OF_SCOPE", False,
                                 "host not in allowlist"))
        return None, {}, b"", "out of scope"
    if not budget.consume():
        audit.append(AuditRecord(AuditRecord.now(), url, "SKIPPED_BUDGET", True,
                                 budget.exhausted_reason or "budget"))
        return None, {}, b"", budget.exhausted_reason or "budget"

    audit.append(AuditRecord(AuditRecord.now(), url, "REQUEST", True))

    client = client or _build_http_client(cfg)
    response: HttpResponse = client.request(method, url, allow_redirects=False)

    status = response.status if response.ok else None
    # Raw headers are returned (matching the previous contract) but every
    # value that reaches the check output is sanitised by the caller.
    headers = {k.lower(): v for k, v in response.headers.items()}
    error = response.error
    if error and response.error_kind:
        # Keep the transport failure kind visible: "proxy_error: ..." tells
        # the operator the request never left the proxy layer.
        error = f"{response.error_kind}: {error}"
    if status is None:
        audit.append(AuditRecord(AuditRecord.now(), url, "ERROR", True, (error or "")[:200]))
    else:
        audit.append(AuditRecord(AuditRecord.now(), url, "RESPONSE", True, f"status={status}"))
    return status, headers, response.body, error


def run_dast(cfg: DASTConfig, *, target_url: str, execute: bool, authorized: bool,
             profile: str | None = None) -> DASTResult:
    """Run (or plan) controlled dynamic checks against an authorised target."""

    cfg.profile = normalize_profile(profile or cfg.profile).lower().replace("_", "-")
    # Execution requires all three: explicit --execute, explicit --authorize,
    # and dry_run disabled in config is NOT required — the CLI flags are the
    # explicit consent signal, and scope is still enforced by the allowlist.
    if cfg.profile in {"controlled-validation", "lab-exploit"} and not (
        execute and authorized
    ):
        # Validation profiles are never silently downgraded to passive: the
        # caller is told that validation was not permitted.
        cfg.profile = PROFILE_CONTROLLED_VALIDATION.lower().replace("_", "-")
    execute = bool(execute) and bool(authorized)
    mode = "execute" if execute else "plan"
    audit: list[AuditRecord] = []
    budget = Budget(cfg)
    spec = assessment_spec_from_dast(cfg)
    spec_problems: list[str] = []
    if execute:
        allowed, spec_problems = spec.authorize(execute=True, confirmation=True)
        if not allowed:
            execute = False
            mode = "plan"
            spec_problems = list(spec_problems)

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
        profile=cfg.profile,
        budget=budget.snapshot(),
        authorization=spec.summary(),
    )

    if not authorized:
        result.skipped.append(
            "Execution requires explicit authorisation (--authorize). Planning mode only."
        )
    if not scope_ok:
        result.skipped.append(
            f"Target {target_url} is outside the allowlist {cfg.allowlist}. "
            "Add it to VEYRON_DAST_ALLOWLIST only if you are authorised to test it."
        )
    if spec_problems:
        result.skipped.append(
            "Authorisation model rejected active execution: " + "; ".join(spec_problems)
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

    # -- modular active checks (profile-gated) --------------------------------
    if cfg.profile in {"safe-active", "controlled-validation", "lab-exploit"} \
            and not budget.exhausted_reason:
        urls: list[str] = []
        for check in result.checks:
            if check.get("url"):
                urls.append(check["url"])
            urls.extend(check.get("links", []))
        client = _build_http_client(cfg, spec)
        # SSRF validation needs a concrete, observable callback signal. VEYRON
        # runs its own loopback listener for this; it never probes cloud
        # metadata or third-party infrastructure. An operator-supplied
        # callback_url cannot be observed by us, so it is recorded as a run
        # note rather than treated as a validating signal.
        listener = None
        callback = None
        if cfg.callback_url:
            result.skipped.append(
                "callback_url is set but is not observed by VEYRON; SSRF "
                "call-back validation is skipped for this run"
            )
        else:
            listener = CallbackListener().start()
            callback = listener
        ctx = CheckContext(
            client=client,
            spec=spec,
            consume=budget.consume,
            stop=lambda: bool(cfg.stop_file and Path(cfg.stop_file).exists()),
            callback=callback,
        )
        try:
            extra, check_errors = run_checks(
                ctx, urls, prompt_injection_endpoints=list(cfg.prompt_injection_endpoints)
            )
            result.findings.extend(extra)
            result.errors.extend(check_errors)
        except Exception as exc:  # noqa: BLE001 - never lose the passive results
            result.errors.append(f"active checks failed: {type(exc).__name__}: {exc}")
        finally:
            if listener is not None:
                listener.stop()

    result.audit = [asdict(a) for a in audit]
    result.budget = budget.snapshot()
    result.ok = True
    return result


def _build_plan(target_url: str, cfg: DASTConfig) -> list[dict[str, Any]]:
    root = target_url.rstrip("/")
    fixed = [
        ("/", "GET", "security header and cookie inspection"),
        ("/robots.txt", "GET", "disclosed path inventory (read-only)"),
        ("/sitemap.xml", "GET", "sitemap presence (read-only)"),
    ]
    if cfg.profile == "safe-active":
        fixed.append((SECURITY_TXT_PATH, "GET", "security disclosure policy presence"))
        fixed.append(("/", "OPTIONS", "advertised HTTP methods (read-only)"))
    plan = [
        {
            "step": i + 1,
            "method": method,
            "url": root + path,
            "purpose": purpose,
            "destructive": False,
            "scope_checked": "host must match allowlist",
        }
        for i, (path, method, purpose) in enumerate(fixed)
    ]
    if cfg.profile == "safe-active":
        plan.append({
            "step": len(plan) + 1,
            "method": "GET",
            "url": root + "/{same-origin link}",
            "purpose": f"crawl discovered same-origin pages (max {cfg.max_pages})",
            "destructive": False,
            "scope_checked": "host must match allowlist",
            "crawl": True,
        })
    return plan


def _canonical(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{parsed.netloc.lower()}{path}{query}"


def _make_check(url: str, method: str, status: int | None, headers: dict[str, str],
                body: bytes, err: str | None, cfg: DASTConfig, root_url: str) -> dict[str, Any]:
    check: dict[str, Any] = {
        "url": url,
        "method": method,
        "status": status,
        "security_headers_present": [h for h in SECURITY_HEADERS if h in headers],
        "security_headers_missing": [h for h in SECURITY_HEADERS if h not in headers],
        # Cookie values are session credentials: only the name and the
        # security-relevant attributes are recorded.
        "cookies": _cookie_summary(headers.get("set-cookie") or ""),
        "server": headers.get("server"),
        "error": err,
        "redirect_location": _redact_location(headers.get("location") or ""),
    }
    if method == "OPTIONS":
        check["allowed_methods"] = headers.get("allow")
    elif method == "GET" and status is not None:
        check.update(_analyse_page(url, body, headers, root_url))
    if status in (301, 302, 303, 307, 308):
        loc = headers.get("location") or ""
        check["redirect_blocked_as_out_of_scope"] = not host_in_allowlist(
            urljoin(url, loc), cfg.allowlist
        )
    return check


def _run_safe_checks(cfg: DASTConfig, target_url: str, budget: Budget,
                     audit: list[AuditRecord]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    delay = 1.0 / max(cfg.rate_limit_per_second, 0.1)
    seen: set[str] = set()
    queue: list[str] = []
    client = _build_http_client(cfg)
    safe_active = cfg.profile == "safe-active"
    # The root page is always fetched; count it against the crawl cap.
    pages_fetched = 1 if safe_active else 0
    root_url = target_url.rstrip("/") + "/"

    for plan_step in _build_plan(target_url, cfg):
        if plan_step.get("crawl"):
            continue
        if budget.exhausted_reason:
            break
        url = plan_step["url"]
        method = plan_step["method"]
        status, headers, body, err = _safe_request(
            url, cfg, budget, audit, method=method, client=client
        )
        check = _make_check(url, method, status, headers, body, err, cfg, root_url)
        if check.get("redirect_blocked_as_out_of_scope"):
            audit.append(AuditRecord(AuditRecord.now(), headers.get("location") or "",
                                     "REDIRECT_BLOCKED", False,
                                     "redirect target outside allowlist; not followed"))
        checks.append(check)
        seen.add(_canonical(url))
        if safe_active and method == "GET":
            queue.extend(link for link in check.get("links", [])
                         if _canonical(link) not in seen)
        if delay:
            time.sleep(delay)  # rate limit

    if safe_active:
        while queue and not budget.exhausted_reason:
            if pages_fetched >= cfg.max_pages:
                audit.append(AuditRecord(AuditRecord.now(), target_url, "CRAWL_CAP", True,
                                         f"crawl limited to {cfg.max_pages} pages"))
                break
            url = queue.pop(0)
            key = _canonical(url)
            if key in seen:
                continue
            seen.add(key)
            if not host_in_allowlist(url, cfg.allowlist):
                audit.append(AuditRecord(AuditRecord.now(), url, "BLOCKED_OUT_OF_SCOPE", False,
                                         "discovered link outside allowlist"))
                continue
            status, headers, body, err = _safe_request(
                url, cfg, budget, audit, client=client
            )
            check = _make_check(url, "GET", status, headers, body, err, cfg, root_url)
            checks.append(check)
            pages_fetched += 1
            queue.extend(link for link in check.get("links", [])
                         if _canonical(link) not in seen)
            if delay:
                time.sleep(delay)

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

    # -- website-assessment observations (safe-active profile) -----------------
    mixed = [c["url"] for c in checks if c.get("mixed_content")]
    if mixed:
        findings.append({
            "title": "HTTPS page loads plaintext HTTP resources",
            "detail": f"{len(mixed)} page(s) reference http:// subresources",
            "severity": "medium",
            "confidence": "high",
            "validation_status": "DETECTED",
            "evidence": "mixed content on: " + ", ".join(mixed[:10]),
            "remediation": "Serve every subresource over HTTPS and add a CSP upgrade-insecure-requests rule.",
        })

    plaintext_passwords = [c["url"] for c in checks if c.get("plaintext_login_form")]
    if plaintext_passwords:
        findings.append({
            "title": "Password form submitted over plaintext HTTP",
            "detail": "A password field is served and posted without TLS",
            "severity": "high",
            "confidence": "high",
            "validation_status": "DETECTED",
            "evidence": "password form on: " + ", ".join(plaintext_passwords[:10]),
            "remediation": "Serve the form and its action over HTTPS and redirect HTTP to HTTPS.",
        })

    cross_origin = [
        (c["url"], action)
        for c in checks
        for action in c.get("cross_origin_form_actions", [])
    ]
    if cross_origin:
        findings.append({
            "title": "Form posts to a different origin",
            "detail": f"{len(cross_origin)} form action(s) leave the assessed origin",
            "severity": "medium",
            "confidence": "medium",
            "validation_status": "DETECTED",
            "evidence": "; ".join(f"{page} -> {action}" for page, action in cross_origin[:5]),
            "remediation": "Confirm the destination is trusted; otherwise post to a same-origin handler.",
        })

    disclosed = [
        (c["url"], label)
        for c in checks
        for label in c.get("disclosure", [])
    ]
    if disclosed:
        findings.append({
            "title": "Diagnostic information disclosed in response body",
            "detail": ", ".join(sorted({label for _, label in disclosed})),
            "severity": "low",
            "confidence": "medium",
            "validation_status": "DETECTED",
            "evidence": "; ".join(f"{page}: {label}" for page, label in disclosed[:5]),
            "remediation": "Disable debug output and return generic error pages in production.",
        })

    return findings


def write_audit_log(result: DASTResult, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(result), indent=2, default=str), encoding="utf-8")
    return path
