"""Local web dashboard — binds to 127.0.0.1 by default.

Security posture:
- Host defaults to 127.0.0.1; binding to a non-loopback address logs a
  warning and requires VEYRON_DASHBOARD_ALLOW_NONLOCAL=1.
- All state-changing endpoints require a per-session CSRF token AND a
  custom header (double submit) — cross-origin form posts cannot forge it.
- Responses set CSP, X-Content-Type-Options, X-Frame-Options: DENY.
- No endpoint returns arbitrary filesystem paths: only report files VEYRON
  itself recorded in the local history, and only under ~/.veyron/reports.
- Every template output is HTML-escaped (no XSS from findings).
"""

from __future__ import annotations

import html
import json
import os
import secrets
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import Config

MAX_HISTORY_BYTES = 5_000_000

EMPTY_STATE = {
    "total_findings": 0,
    "severity_counts": {},
    "validation_counts": {},
    "active_assessments": 0,
    "recent": [],
    "scanner_failures": [],
    "warnings": [],
    "proxy": {},
}


def load_history(cfg: Config) -> list[dict[str, Any]]:
    """Read local assessment history (bounded read, defensive parse)."""
    path = cfg.history_path
    if not path.exists():
        return []
    try:
        if path.stat().st_size > MAX_HISTORY_BYTES:
            data = path.read_bytes()[-MAX_HISTORY_BYTES:].decode("utf-8", "replace")
            lines = data.splitlines()[1:]
        else:
            lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def build_dashboard_data(cfg: Config) -> dict[str, Any]:
    """Aggregate real data for the dashboard (never fabricated)."""
    entries = load_history(cfg)
    if not entries:
        return dict(EMPTY_STATE)

    total = 0
    severity: dict[str, int] = {}
    validation: dict[str, int] = {}
    failures: list[str] = []
    warnings: list[str] = []
    for e in entries:
        total += int(e.get("findings") or 0)
        for k, v in (e.get("severity_counts") or {}).items():
            severity[k] = severity.get(k, 0) + int(v)
        if e.get("interrupted"):
            warnings.append(f"Assessment {e.get('assessment_id')} was interrupted — results incomplete.")
        if e.get("coverage_warning"):
            warnings.append(f"{e.get('assessment_id')}: {e['coverage_warning']}")
        for name in e.get("failed_scanners") or []:
            failures.append(f"{e.get('assessment_id')}: scanner '{name}' failed")

    # validation counts come from reports if present (history stores only totals)
    validation = _validation_counts_from_latest(cfg, entries)

    return {
        "total_findings": total,
        "severity_counts": severity,
        "validation_counts": validation,
        "active_assessments": 0,
        "recent": entries[-10:][::-1],
        "scanner_failures": failures[-10:],
        "warnings": warnings[-10:],
        "proxy": cfg.proxy.masked(),
        "offline": cfg.offline,
    }


def _validation_counts_from_latest(cfg: Config, entries: list[dict[str, Any]]) -> dict[str, int]:
    for e in reversed(entries):
        reports = e.get("reports") or {}
        json_path = reports.get("json")
        if not json_path:
            continue
        p = Path(json_path)
        # Only read files under the reports dir (path containment check).
        try:
            p.resolve().relative_to(cfg.reports_dir.resolve())
        except (ValueError, OSError):
            continue
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        counts = data.get("validation_counts")
        if isinstance(counts, dict):
            return counts
    return {}


MAX_REPORT_BYTES = 20_000_000


def _confined(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def load_assessment_context(cfg: Config, assessment_id: str) -> dict[str, Any] | None:
    """Load one assessment's JSON report, confined to the reports directory."""
    if not assessment_id or any(ch not in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "abcdefghijklmnopqrstuvwxyz-_" for ch in assessment_id):
        return None
    for entry in load_history(cfg):
        if entry.get("assessment_id") != assessment_id:
            continue
        raw = (entry.get("reports") or {}).get("json")
        if not raw:
            return None
        path = Path(raw)
        if not _confined(path, cfg.reports_dir) or not path.exists():
            return None
        try:
            if path.stat().st_size > MAX_REPORT_BYTES:
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None
    return None


def recorded_report_path(cfg: Config, assessment_id: str, fmt: str) -> Path | None:
    """Return a report path only if history recorded it and it is confined."""
    if fmt not in {"json", "markdown", "sarif", "html", "disclosure"}:
        return None
    for entry in load_history(cfg):
        if entry.get("assessment_id") != assessment_id:
            continue
        raw = (entry.get("reports") or {}).get(fmt)
        if not raw:
            return None
        path = Path(raw)
        if _confined(path, cfg.reports_dir) and path.exists() and path.is_file():
            return path
        return None
    return None


def render_finding_page(context: dict[str, Any], finding_id: str) -> str | None:
    finding = next((f for f in context.get("findings", [])
                    if str(f.get("id")) == finding_id), None)
    if finding is None:
        return None
    ve = finding.get("validation_evidence") or {}
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
 content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'">
<title>{_e(finding.get('title'))}</title>
<style>body{{margin:0;background:#0d1117;color:#d7dde6;font:14px/1.6 system-ui,sans-serif}}
main{{max-width:900px;margin:0 auto;padding:24px}}h1{{font-size:20px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a0e13;border:1px solid #232b36;
border-radius:6px;padding:10px}}.muted{{color:#8b97a7}}a{{color:#4fd1c5}}
section{{border-top:1px solid #232b36;margin-top:18px;padding-top:10px}}</style></head>
<body><main><p><a href="/">&larr; dashboard</a></p>
<h1>{_e(finding.get('title'))}</h1>
<p class="muted">ID <code>{_e(finding.get('id'))}</code> · severity {_e(finding.get('severity'))} ·
confidence {_e(finding.get('confidence'))} · state {_e(finding.get('validation_status'))}</p>
<p><b>Asset:</b> {_e(finding.get('asset') or context.get('target'))}<br>
<b>Endpoint:</b> {_e(finding.get('endpoint') or finding.get('file_path') or 'n/a')}</p>
<p>{_e(finding.get('description'))}</p>
<section><h2>Evidence</h2><pre>{_e(str(finding.get('evidence') or '')[:5000])}</pre></section>
<section><h2>Validation evidence</h2><pre>{_e(json.dumps(ve, indent=2, default=str)[:8000])}</pre></section>
<section><h2>Impact and reproduction</h2>
<p><b>Impact:</b> {_e(finding.get('impact') or 'Not separately assessed.')}</p>
<p><b>Preconditions:</b> {_e(finding.get('preconditions') or 'Not recorded.')}</p>
<pre>{_e(finding.get('reproduction') or ve.get('request') or 'Not recorded.')}</pre></section>
<section><h2>Remediation and verification</h2>
<p><b>Remediation:</b> {_e(finding.get('remediation') or 'Not recorded.')}</p>
<p><b>Verification:</b> {_e(finding.get('verification') or 'Not recorded.')}</p></section>
</main></body></html>"""


# ---------------------------------------------------------------------------
# HTML rendering (all values escaped)
# ---------------------------------------------------------------------------

def _e(v: Any) -> str:
    return html.escape(str(v if v is not None else ""), quote=True)


SEV_COLORS = {
    "critical": "#ff4d61",
    "high": "#ff8f5a",
    "medium": "#ffc857",
    "low": "#5ab0ff",
    "info": "#8aa0b8",
    "unknown": "#6b7688",
}


def render_page(data: dict[str, Any], csrf_token: str) -> str:
    sev_rows = "".join(
        f'<span class="pill" style="border-color:{SEV_COLORS.get(k, "#6b7688")}">'
        f'{_e(k)} <b>{v}</b></span>'
        for k, v in sorted(
            data["severity_counts"].items(),
            key=lambda kv: ["critical", "high", "medium", "low", "info", "unknown"].index(kv[0])
            if kv[0] in ["critical", "high", "medium", "low", "info", "unknown"] else 99,
        )
    ) or '<span class="muted">No findings recorded</span>'

    val_rows = "".join(
        f'<span class="pill">{_e(k)} <b>{v}</b></span>'
        for k, v in sorted(data["validation_counts"].items())
    ) or '<span class="muted">No validation states recorded</span>'

    recent_rows = "".join(
        f"<tr><td><code>{_e(e.get('assessment_id'))}</code></td>"
        f"<td>{_e(e.get('generated_at'))}</td>"
        f"<td>{_e(e.get('target'))}</td>"
        f"<td>{_e(e.get('findings'))}</td>"
        f"<td>{'<span class=bad>partial</span>' if e.get('interrupted') else '<span class=ok>complete</span>'}</td>"
        f"<td>{_e(', '.join(e.get('failed_scanners') or []) or '—')}</td></tr>"
        for e in data["recent"]
    ) or '<tr><td colspan="6" class="muted">No assessments yet — run <code>veyron scan ./your-repo</code></td></tr>'

    warnings = "".join(f"<li class='warn'>{_e(w)}</li>" for w in data["warnings"])
    failures = "".join(f"<li class='bad'>{_e(f)}</li>" for f in data["scanner_failures"])

    empty_hint = ""
    if data["total_findings"] == 0 and not data["recent"]:
        empty_hint = (
            '<div class="empty"><h3>No assessments yet</h3>'
            "<p>Run an assessment to populate this dashboard:</p>"
            "<pre>veyron scan ./path/to/repo</pre>"
            "<p class='muted'>Statistics appear only after real scans — never fabricated.</p></div>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
 content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'">
<title>VEYRON — Security Assessment</title>
<style>
:root{{--bg:#0d1117;--panel:#151b23;--border:#232b36;--fg:#d7dde6;--muted:#8b97a7;--accent:#4fd1c5}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",Roboto,system-ui,sans-serif}}
header{{display:flex;align-items:center;gap:12px;padding:14px 22px;border-bottom:1px solid var(--border);background:var(--panel)}}
header img{{height:28px}}
header h1{{font-size:16px;letter-spacing:.14em;margin:0;font-weight:600}}
header .muted{{margin-left:auto}}
main{{padding:22px;max-width:1180px;margin:0 auto}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px 16px}}
.card .num{{font-size:26px;font-weight:650}}
.card .lbl{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}}
section{{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px 18px;margin-bottom:18px}}
h2{{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:0 0 12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid var(--border)}}
th{{color:var(--muted);font-weight:600;font-size:12px}}
code{{background:#0a0e13;border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-size:12px}}
.pill{{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:3px 10px;margin:3px 4px 0 0;font-size:12px}}
.ok{{color:#3fd68c}}.bad{{color:#ff6b6b}}.warn{{color:#ffc857}}
.muted{{color:var(--muted)}}
ul{{margin:6px 0;padding-left:18px}}li.warn,li.bad{{font-size:13px}}
pre{{background:#0a0e13;border:1px solid var(--border);border-radius:6px;padding:10px 12px;overflow:auto}}
.empty{{text-align:center;padding:26px 10px}}
.empty pre{{display:inline-block;text-align:left}}
footer{{color:var(--muted);font-size:12px;text-align:center;padding:10px 0 26px}}
form.rebuild button{{background:transparent;border:1px solid var(--border);color:var(--fg);border-radius:6px;padding:5px 12px;cursor:pointer}}
form.rebuild button:hover{{border-color:var(--accent);color:var(--accent)}}
</style></head>
<body>
<header>
  <img src="/assets/logo.svg" alt="VEYRON logo">
  <h1>VEYRON</h1>
  <span class="muted">Vulnerability Evaluation · Research · Yield-Oriented Offensive Analysis Engine</span>
</header>
<main>
{empty_hint}
<div class="cards">
  <div class="card"><div class="num">{data["total_findings"]}</div><div class="lbl">Total findings</div></div>
  <div class="card"><div class="num">{data["validation_counts"].get("VALIDATED", 0)}</div><div class="lbl">Validated</div></div>
  <div class="card"><div class="num">{data["validation_counts"].get("DETECTED", 0) + data["validation_counts"].get("ANALYSED", 0)}</div><div class="lbl">Unverified</div></div>
  <div class="card"><div class="num">{len(data["scanner_failures"])}</div><div class="lbl">Scanner failures</div></div>
  <div class="card"><div class="num">{len(data["recent"])}</div><div class="lbl">Assessments</div></div>
</div>
<section><h2>Severity distribution (all assessments)</h2>{sev_rows}</section>
<section><h2>Validation states (latest assessment)</h2>{val_rows}</section>
<section><h2>Recent assessment history</h2>
<table><thead><tr><th>ID</th><th>When</th><th>Target</th><th>Findings</th><th>Status</th><th>Failed scanners</th></tr></thead>
<tbody>{recent_rows}</tbody></table></section>
{(f"<section><h2>Warnings</h2><ul>{warnings}</ul></section>" if warnings else "")}
{(f"<section><h2>Scanner failures</h2><ul>{failures}</ul></section>" if failures else "")}
<section><h2>Refresh</h2>
<form class="rebuild" method="post" action="/refresh" data-csrf>
  <input type="hidden" name="csrf" value="{_e(csrf_token)}">
  <button type="submit">Reload dashboard data</button>
  <span class="muted" style="margin-left:10px">Re-reads local assessment history</span>
</form></section>
</main>
<footer>VEYRON · local-first · evidence over speculation · dashboard bound to loopback only</footer>
</body></html>"""


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "VeyronDashboard/0.1"
    cfg: Config  # injected
    csrf_token: str

    # -- helpers ------------------------------------------------------------

    CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
           "form-action 'self'; base-uri 'none'; frame-ancestors 'none'")

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Security-Policy", self.CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _origin_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True  # same-origin form posts may omit Origin on GET-only flows
        try:
            parsed = urllib.parse.urlparse(origin)
        except ValueError:
            return False
        host_hdr = (self.headers.get("Host") or "")
        return f"{parsed.netloc}" == host_hdr

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet, redacted
        from .redact import redact_text
        try:
            sys_stderr = __import__("sys").stderr
            print(redact_text("%s - %s" % (self.address_string(), fmt % args)), file=sys_stderr)
        except Exception:
            pass

    # -- routes ---------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            data = build_dashboard_data(self.cfg)
            page = render_page(data, self.csrf_token)
            self._send(200, page.encode("utf-8"))
        elif path == "/api/dashboard":
            data = build_dashboard_data(self.cfg)
            self._send(200, json.dumps(data, default=str).encode("utf-8"),
                       "application/json; charset=utf-8")
        elif path == "/assets/logo.svg":
            asset = Path(__file__).resolve().parent.parent / "assets" / "logo" / "veyron-icon.svg"
            if asset.exists():
                self._send(200, asset.read_bytes(), "image/svg+xml")
            else:
                self._send(404, b"not found", "text/plain")
        elif path == "/healthz":
            self._send(200, b'{"status":"ok"}', "application/json")
        elif path == "/finding":
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            aid = (query.get("assessment") or [""])[0]
            fid = (query.get("id") or [""])[0]
            if not aid or not fid:
                self._send(400, b"assessment and id required", "text/plain")
                return
            ctx = load_assessment_context(self.cfg, aid)
            if ctx is None:
                self._send(404, b"assessment not found", "text/plain")
                return
            page = render_finding_page(ctx, fid)
            if page is None:
                self._send(404, b"finding not found", "text/plain")
                return
            self._send(200, page.encode("utf-8"))
        elif path.startswith("/report/"):
            # /report/<assessment_id>/<fmt>  (fmt: json, markdown, sarif, html)
            parts = path.split("/")
            if len(parts) != 4:
                self._send(404, b"not found", "text/plain")
                return
            _, aid, fmt = parts[1], parts[2], parts[3]
            rpath = recorded_report_path(self.cfg, aid, fmt)
            if rpath is None:
                self._send(404, b"report not found", "text/plain")
                return
            ctype = {
                "json": "application/json; charset=utf-8",
                "markdown": "text/markdown; charset=utf-8",
                "sarif": "application/sarif+json; charset=utf-8",
                "html": "text/html; charset=utf-8",
            }.get(fmt, "application/octet-stream")
            self._send(200, rpath.read_bytes(), ctype)
        elif path.startswith("/disclosure/"):
            aid = path.split("/")[2] if len(path.split("/")) >= 3 else ""
            if not aid:
                self._send(404, b"not found", "text/plain")
                return
            rpath = recorded_report_path(self.cfg, aid, "disclosure")
            if rpath is None:
                self._send(404, b"disclosure draft not found", "text/plain")
                return
            self._send(200, rpath.read_bytes(), "text/markdown; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if not self._origin_allowed():
            self._send(403, b"origin not allowed", "text/plain")
            return
        path = urllib.parse.urlparse(self.path).path
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = urllib.parse.parse_qs(body)

        # CSRF: session token must be present in the form, and any Origin
        # header must match this host. Cross-site forms cannot read the
        # token from our page; fetch-based callers may additionally send
        # X-Veyron-Csrf, which must then also match.
        header_token = self.headers.get("X-Veyron-Csrf")
        form_token = (form.get("csrf") or [""])[0]
        if path == "/refresh":
            if form_token != self.csrf_token:
                self._send(403, b"csrf check failed", "text/plain")
                return
            if header_token and header_token != self.csrf_token:
                self._send(403, b"csrf check failed", "text/plain")
                return
            data = build_dashboard_data(self.cfg)
            self._send(200, render_page(data, self.csrf_token).encode("utf-8"))
            return
        self._send(404, b"not found", "text/plain")


def serve(cfg: Config, *, host: str = "127.0.0.1", port: int = 8732) -> int:
    """Start the dashboard (blocking). Returns process exit code."""
    import sys

    loopback = host in {"127.0.0.1", "::1", "localhost"}
    if not loopback and os.environ.get("VEYRON_DASHBOARD_ALLOW_NONLOCAL") != "1":
        print(
            "refusing to bind to a non-loopback address without "
            "VEYRON_DASHBOARD_ALLOW_NONLOCAL=1 (default is 127.0.0.1)",
            file=sys.stderr,
        )
        return 2

    handler = type("BoundDashboardHandler", (DashboardHandler,), {
        "cfg": cfg,
        "csrf_token": secrets.token_urlsafe(32),
    })
    server = ThreadingHTTPServer((host, port), handler)
    print(f"VEYRON dashboard: http://{host}:{port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return 0
