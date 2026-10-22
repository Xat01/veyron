"""Website assessment (safe-active profile): crawl bounds, passive analysis.

All traffic stays on a locally started HTTP server. No third-party host is
contacted, and the external-link test only proves the crawler *refuses* to
leave the assessed origin.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from veyron.config import Config, DASTConfig
from veyron.dast import _analyse_page, run_dast


class _Handler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, str, bytes]] = {}

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        status, ctype, body = self.routes.get(
            self.path, (404, "text/plain", b"not found")
        )
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "TestServer/1.0")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib hook
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def log_message(self, *args: object) -> None:  # silence test output
        pass


def _page(title: str, body: str = "") -> bytes:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>".encode()


@pytest.fixture()
def site(monkeypatch):
    # Deterministic network policy: no proxy, loopback allowed.
    monkeypatch.setattr(Config, "load", staticmethod(lambda path=None: Config()))

    _Handler.routes = {
        "/": (200, "text/html", _page(
            "Home",
            '<a href="/about">About</a>'
            '<a href="/login">Login</a>'
            '<a href="/error">Broken</a>'
            '<a href="http://outside.example/remote">External</a>',
        )),
        "/about": (200, "text/html", _page(
            "About", '<a href="/deep">Deep</a><a href="/">Home</a>'
        )),
        "/deep": (200, "text/html", _page("Deep")),
        "/login": (200, "text/html", _page(
            "Login",
            '<form action="/session" method="post">'
            '<input type="text" name="user">'
            '<input type="password" name="pw">'
            "</form>",
        )),
        "/error": (200, "text/html", _page(
            "Error", "Traceback (most recent call last): boom"
        )),
        "/robots.txt": (200, "text/plain", b"User-agent: *\nDisallow: /admin\n"),
        "/sitemap.xml": (200, "application/xml", b"<urlset></urlset>"),
        "/.well-known/security.txt": (200, "text/plain", b"Contact: mailto:sec@example.test\n"),
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.daemon = True
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def cfg(**kw) -> DASTConfig:
    base = dict(
        enabled=True,
        allowlist=[],
        max_requests=50,
        max_minutes=1,
        max_concurrency=1,
        follow_redirects=False,
        dry_run=True,
        rate_limit_per_second=100.0,
        timeout_seconds=5,
    )
    base.update(kw)
    return DASTConfig(**base)


def test_passive_profile_does_not_crawl(site):
    res = run_dast(cfg(allowlist=[site.split("//")[1].rstrip("/")], profile="passive"),
                   target_url=site, execute=True, authorized=True)
    urls = [c["url"] for c in res.checks]
    assert len(urls) == 3
    assert site + "about" not in urls
    assert res.profile == "passive"


def test_safe_active_crawls_only_same_origin(site):
    res = run_dast(cfg(allowlist=[site.split("//")[1].rstrip("/")], profile="safe-active"),
                   target_url=site, execute=True, authorized=True)
    urls = [c["url"] for c in res.checks]

    for expected in ("about", "deep", "login", "error"):
        assert site + expected in urls
    assert all("outside.example" not in url for url in urls)
    assert any(c["method"] == "OPTIONS" and c["allowed_methods"] == "GET, HEAD, OPTIONS"
               for c in res.checks)
    assert any(c["url"].endswith("/.well-known/security.txt") for c in res.checks)


def test_safe_active_findings_from_passive_analysis(site):
    res = run_dast(cfg(allowlist=[site.split("//")[1].rstrip("/")], profile="safe-active"),
                   target_url=site, execute=True, authorized=True)
    titles = {f["title"] for f in res.findings}
    assert "Password form submitted over plaintext HTTP" in titles
    assert "Diagnostic information disclosed in response body" in titles
    assert all(f["validation_status"] == "DETECTED" for f in res.findings)


def test_crawl_respects_max_pages(site):
    res = run_dast(cfg(allowlist=[site.split("//")[1].rstrip("/")], profile="safe-active",
                       max_pages=2),
                   target_url=site, execute=True, authorized=True)
    pages = [c["url"] for c in res.checks if c.get("title")]
    assert len(pages) <= 2
    assert any(a["action"] == "CRAWL_CAP" for a in res.audit)


def test_plan_lists_profile_steps(site):
    res = run_dast(cfg(allowlist=[site.split("//")[1].rstrip("/")], profile="safe-active"),
                   target_url=site, execute=False, authorized=True)
    assert res.mode == "plan"
    assert res.checks == []
    assert any(step.get("crawl") is True for step in res.plan)
    assert any(step["method"] == "OPTIONS" for step in res.plan)
    assert all(step["destructive"] is False for step in res.plan)


# -- passive HTML analysis (no network) ---------------------------------------

def test_mixed_content_detected_only_on_https():
    body = b'<html><script src="http://cdn.example/app.js"></script></html>'
    https = _analyse_page("https://site.test/", body, {"content-type": "text/html"},
                          "https://site.test/")
    http = _analyse_page("http://site.test/", body, {"content-type": "text/html"},
                          "http://site.test/")
    assert https["mixed_content"]
    assert http["mixed_content"] == []


def test_cross_origin_form_action_flagged():
    body = (b'<html><form action="https://pay.example/collect" method="post">'
            b'<input name="card"></form></html>')
    out = _analyse_page("https://site.test/", body, {"content-type": "text/html"},
                        "https://site.test/")
    assert out["cross_origin_form_actions"] == ["https://pay.example/collect"]
    assert out["forms"][0]["cross_origin"] is True


def test_non_html_body_is_not_parsed():
    body = b"User-agent: *\nDisallow: /admin\n"
    out = _analyse_page("https://site.test/robots.txt", body,
                        {"content-type": "text/plain"}, "https://site.test/")
    assert out["links"] == []
    assert out["forms"] == []


def test_query_values_redacted_in_form_actions():
    body = (b'<html><form action="/cb?token=secret&next=/home" method="get">'
            b'<input name="q"></form></html>')
    out = _analyse_page("https://site.test/", body, {"content-type": "text/html"},
                        "https://site.test/")
    action = out["forms"][0]["action"]
    assert "secret" not in action
    assert "token=***" in action


def test_userinfo_links_are_never_followed():
    body = b'<html><a href="http://user:secret@site.test/private">x</a></html>'
    out = _analyse_page("http://site.test/", body, {"content-type": "text/html"},
                        "http://site.test/")
    assert out["links"] == []
    assert all("secret" not in item for item in out["external_resources"])
