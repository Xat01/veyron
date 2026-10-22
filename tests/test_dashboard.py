"""Dashboard: empty state honesty, path containment, CSRF, security headers."""

import json
import threading
import urllib.error
import urllib.request
from http.client import HTTPResponse

import pytest

from veyron.config import Config
from veyron.dashboard import (
    DashboardHandler,
    build_dashboard_data,
    render_page,
    serve,
)


@pytest.fixture
def cfg(tmp_path):
    c = Config()
    c.history_path = tmp_path / "history.jsonl"
    c.reports_dir = tmp_path / "reports"
    return c


# -- data honesty ---------------------------------------------------------------

def test_empty_state_has_no_fabricated_stats(cfg):
    data = build_dashboard_data(cfg)
    assert data["total_findings"] == 0
    assert data["recent"] == []
    assert data["severity_counts"] == {}


def test_history_aggregation_real(cfg):
    entry = {"assessment_id": "abc", "generated_at": "2026-01-01T00:00:00+00:00",
             "target": "/repo", "findings": 4,
             "severity_counts": {"high": 2, "low": 2},
             "interrupted": False, "failed_scanners": ["bandit"]}
    cfg.history_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.history_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    data = build_dashboard_data(cfg)
    assert data["total_findings"] == 4
    assert data["severity_counts"] == {"high": 2, "low": 2}
    assert any("bandit" in f for f in data["scanner_failures"])


def test_malformed_history_lines_ignored(cfg):
    cfg.history_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.history_path.write_text('{"findings":1}\nGARBAGE\n{"findings":2}\n', encoding="utf-8")
    data = build_dashboard_data(cfg)
    assert data["total_findings"] == 3


def test_partial_assessment_warning_surfaced(cfg):
    entry = {"assessment_id": "p1", "findings": 0, "interrupted": True,
             "coverage_warning": "semgrep failed"}
    cfg.history_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.history_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    data = build_dashboard_data(cfg)
    assert any("interrupted" in w for w in data["warnings"])


# -- path containment ------------------------------------------------------------

def test_history_cannot_read_files_outside_reports(cfg, tmp_path):
    """A tampered history entry pointing outside ~/.veyron/reports must be
    ignored rather than read."""
    secret = tmp_path / "outside-secret.json"
    secret.write_text('{"validation_counts": {"VALIDATED": 99}}', encoding="utf-8")
    entry = {"assessment_id": "x", "findings": 1, "reports": {"json": str(secret)}}
    cfg.history_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.history_path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    data = build_dashboard_data(cfg)
    assert data["validation_counts"] == {}  # refused: outside reports dir


# -- rendering --------------------------------------------------------------------

def test_render_escapes_html():
    from veyron.config import Config as C
    data = build_dashboard_data(C())
    data["recent"] = [{"assessment_id": "<script>alert(1)</script>",
                       "generated_at": "t", "target": "</td><script>x</script>",
                       "findings": 1, "interrupted": False, "failed_scanners": []}]
    page = render_page(data, "tok")
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_render_shows_empty_state_hint(tmp_path):
    c = Config()
    c.history_path = tmp_path / "no-history.jsonl"
    page = render_page(build_dashboard_data(c), "tok")
    assert "No assessments yet" in page
    assert "veyron scan" in page


# -- live HTTP behaviour ----------------------------------------------------------

class _Server:
    def __init__(self, cfg):
        self.handler = type("H", (DashboardHandler,), {"cfg": cfg, "csrf_token": "SESSION-TOKEN"})
        from http.server import ThreadingHTTPServer
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _post(port, path, body, headers=None):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body.encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_dashboard_csrf_enforced(cfg):
    with _Server(cfg) as srv:
        # missing token -> 403
        code, _ = _post(srv.port, "/refresh", "csrf=wrong")
        assert code == 403
        # correct token -> 200
        code, _ = _post(srv.port, "/refresh", "csrf=SESSION-TOKEN")
        assert code == 200
        # correct form token but wrong header token -> 403
        code, _ = _post(srv.port, "/refresh", "csrf=SESSION-TOKEN",
                        headers={"X-Veyron-Csrf": "wrong"})
        assert code == 403


def test_dashboard_security_headers(cfg):
    with _Server(cfg) as srv:
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/", timeout=5) as resp:
            assert resp.headers.get("X-Frame-Options") == "DENY"
            assert resp.headers.get("X-Content-Type-Options") == "nosniff"
            csp = resp.headers.get("Content-Security-Policy") or ""
            assert "frame-ancestors 'none'" in csp
            assert "default-src 'none'" in csp


def test_dashboard_rejects_foreign_origin(cfg):
    with _Server(cfg) as srv:
        code, _ = _post(srv.port, "/refresh", "csrf=SESSION-TOKEN",
                        headers={"Origin": "http://evil.example"})
        assert code == 403


def test_dashboard_api_and_health(cfg):
    with _Server(cfg) as srv:
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/healthz", timeout=5) as resp:
            assert json.loads(resp.read())["status"] == "ok"
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/api/dashboard", timeout=5) as resp:
            data = json.loads(resp.read())
            assert data["total_findings"] == 0


def test_unknown_path_404(cfg):
    with _Server(cfg) as srv:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/etc/passwd", timeout=5)
            assert False, "expected 404"
        except urllib.error.HTTPError as exc:
            assert exc.code == 404


def test_serve_refuses_nonloopback(tmp_path, monkeypatch):
    monkeypatch.delenv("VEYRON_DASHBOARD_ALLOW_NONLOCAL", raising=False)
    cfg = Config()
    assert serve(cfg, host="0.0.0.0", port=1) == 2

def test_finding_page_escapes_and_loads_confined_report(cfg):
    cfg.reports_dir.mkdir(parents=True)
    report = cfg.reports_dir / "abc.json"
    report.write_text(json.dumps({
        "target": "https://app.test",
        "findings": [{
            "id": "VYN-1", "title": "<script>alert(1)</script>",
            "description": "<img src=x onerror=alert(1)>", "severity": "high",
            "confidence": "high", "validation_status": "VALIDATED",
            "asset": "app.test", "endpoint": "https://app.test/x",
            "evidence": "<svg onload=alert(2)>",
            "validation_evidence": {"observed": "marker", "request": "GET /x"},
        }],
    }), encoding="utf-8")
    cfg.history_path.write_text(json.dumps({
        "assessment_id": "abc",
        "reports": {"json": str(report)},
    }) + "\n", encoding="utf-8")
    with _Server(cfg) as srv:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{srv.port}/finding?assessment=abc&id=VYN-1", timeout=5
        ) as resp:
            body = resp.read().decode()
    assert resp.status == 200
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
    assert "<img src=x" not in body


def test_finding_page_rejects_report_outside_reports_dir(cfg, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    cfg.history_path.write_text(json.dumps({
        "assessment_id": "abc", "reports": {"json": str(outside)},
    }) + "\n", encoding="utf-8")
    with _Server(cfg) as srv:
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{srv.port}/finding?assessment=abc&id=X", timeout=5
            )
            assert False, "expected 404"
        except urllib.error.HTTPError as exc:
            assert exc.code == 404


def test_report_export_route_serves_recorded_file(cfg):
    cfg.reports_dir.mkdir(parents=True)
    md = cfg.reports_dir / "abc.md"
    md.write_text("# report", encoding="utf-8")
    cfg.history_path.write_text(json.dumps({
        "assessment_id": "abc", "reports": {"markdown": str(md)},
    }) + "\n", encoding="utf-8")
    with _Server(cfg) as srv:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{srv.port}/report/abc/markdown", timeout=5
        ) as resp:
            assert resp.status == 200
            assert resp.read() == b"# report"
