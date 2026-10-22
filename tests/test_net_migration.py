"""Tests for the migration of the remaining HTTP paths onto the shared
network layer.

DAST, the AI adapter and the OSV adapter used to open sockets with
``urllib.request``. These tests pin the migrated behaviour:

* every outbound request goes through ``veyron.net.client.HttpClient``;
* scope, proxy routing (fail-closed), budgets, timeouts and TLS
  verification apply to all three;
* no module outside ``veyron/net/`` reintroduces an independent HTTP path.

Nothing here contacts a third-party host: the tests use a local
application server and a local proxy double.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

import veyron.adapters.osv as osv_mod
import veyron.ai as ai_mod
import veyron.dast as dast_mod
from veyron.adapters.osv import OSVAdapter
from veyron.ai import AIAdapter
from veyron.config import AIConfig, DASTConfig
from veyron.dast import run_dast
from veyron.net.client import HttpClient
from veyron.net.proxy import ProxyConfig

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Local application server
# ---------------------------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        server = self.server
        server.hits.append((self.path, dict(self.headers)))
        if self.path.startswith("/redirect-to"):
            self.send_response(302)
            self.send_header("Location", server.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/slow"):
            time.sleep(server.slow_seconds)
        body = b"hello-veyron"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if self.path.startswith("/cookie"):
            self.send_header(
                "Set-Cookie",
                "sessionid=SUPERSECRETSESSIONVALUE; Path=/; HttpOnly; Secure; SameSite=Lax",
            )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:  # silence the default stderr log
        return


class _AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.hits: list[tuple[str, dict[str, str]]] = []
        self.redirect_to = "http://example.invalid/"
        self.slow_seconds = 10.0


@pytest.fixture()
def app_server():
    server = _AppServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _port(server: _AppServer) -> int:
    return server.server_address[1]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _ProxyDouble:
    """A local proxy that records connections and then drops them.

    It proves that a request actually reached the proxy layer — a test that
    only asserts "the call failed" cannot distinguish a proxy failure from
    a direct connection failure.
    """

    def __init__(self) -> None:
        self.connections: list[str] = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._sock.getsockname()[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                self._sock.settimeout(0.2)
                conn, _addr = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                try:
                    data = conn.recv(4096).decode("utf-8", "replace")
                except OSError:
                    data = ""
                self.connections.append(data.split("\r\n", 1)[0])
                # Drop the connection without a response: the client must
                # treat this as a proxy failure.
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


@pytest.fixture()
def proxy_double():
    proxy = _ProxyDouble()
    try:
        yield proxy
    finally:
        proxy.close()


def _dast_cfg(allowlist: list[str], **overrides: Any) -> DASTConfig:
    params: dict[str, Any] = {
        "enabled": True,
        "allowlist": allowlist,
        "max_requests": 20,
        "max_minutes": 1,
        "rate_limit_per_second": 100.0,
        "dry_run": False,
        "timeout_seconds": 5,
    }
    params.update(overrides)
    return DASTConfig(**params)


# ---------------------------------------------------------------------------
# Proxy injection helpers
# ---------------------------------------------------------------------------


def _with_proxy(monkeypatch: pytest.MonkeyPatch, proxy: ProxyConfig) -> None:
    """Make ``Config.load()`` report the given proxy configuration."""
    import veyron.config as config_mod

    class _Global:
        pass

    _Global.proxy = proxy
    monkeypatch.setattr(config_mod.Config, "load", classmethod(lambda cls: _Global()))


def _force_proxy_for_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop the client from exempting loopback destinations from the proxy.

    Without this the client routes 127.0.0.1 directly and the proxy path is
    never exercised.
    """
    original_init = HttpClient.__init__

    def spy_init(self, **kwargs):
        kwargs["proxy_bypass_loopback"] = False
        original_init(self, **kwargs)

    monkeypatch.setattr(HttpClient, "__init__", spy_init)


# ---------------------------------------------------------------------------
# DAST
# ---------------------------------------------------------------------------


def test_dast_uses_shared_http_client(app_server):
    """DAST must issue its requests through HttpClient."""
    assert not hasattr(dast_mod, "urllib")
    port = _port(app_server)
    res = run_dast(_dast_cfg([f"127.0.0.1:{port}"]),
                   target_url=f"http://127.0.0.1:{port}/", execute=True, authorized=True)
    assert res.ok is True
    assert res.checks
    assert any(path == "/" for path, _ in app_server.hits)


def test_dast_rejects_out_of_scope_destination(app_server):
    """A target outside the allowlist is never contacted."""
    port = _port(app_server)
    res = run_dast(_dast_cfg(["example.invalid"]),
                   target_url=f"http://127.0.0.1:{port}/", execute=True, authorized=True)
    assert res.ok is False
    assert res.authorized_ok is False
    assert app_server.hits == []


def test_dast_per_host_port_restriction_enforced(app_server):
    """Allowlisting host:8080 must not permit the same host on another port."""
    port = _port(app_server)
    res = run_dast(_dast_cfg([f"127.0.0.1:{_free_port()}"]),
                   target_url=f"http://127.0.0.1:{port}/", execute=True, authorized=True)
    assert res.authorized_ok is False
    assert app_server.hits == []


def test_dast_redirect_cannot_escape_scope(app_server):
    """A cross-host redirect is flagged and the target is never contacted."""
    port = _port(app_server)
    app_server.redirect_to = "http://example.invalid/elsewhere"
    res = run_dast(_dast_cfg([f"127.0.0.1:{port}"]),
                   target_url=f"http://127.0.0.1:{port}/redirect-to",
                   execute=True, authorized=True)
    check = res.checks[0]
    assert check["status"] == 302
    assert check["redirect_blocked_as_out_of_scope"] is True
    assert not any("example.invalid" in path for path, _ in app_server.hits)


def test_dast_request_budget_respected(app_server):
    """The request budget caps the number of outbound requests."""
    port = _port(app_server)
    res = run_dast(_dast_cfg([f"127.0.0.1:{port}"], max_requests=1),
                   target_url=f"http://127.0.0.1:{port}/", execute=True, authorized=True)
    assert len(app_server.hits) <= 1
    assert res.budget["used"] <= 1


def test_dast_timeout_is_enforced(app_server):
    """A slow handler is cut off at the configured timeout."""
    port = _port(app_server)
    app_server.slow_seconds = 10.0
    res = run_dast(_dast_cfg([f"127.0.0.1:{port}"], timeout_seconds=1),
                   target_url=f"http://127.0.0.1:{port}/slow", execute=True, authorized=True)
    assert res.checks[0]["status"] is None
    assert res.checks[0]["error"]


def test_dast_tls_verification_enabled_by_default(app_server, monkeypatch):
    """verify_tls must never be disabled silently."""
    seen: dict[str, Any] = {}
    original_init = HttpClient.__init__

    def spy_init(self, **kwargs):
        seen.update(kwargs)
        original_init(self, **kwargs)

    monkeypatch.setattr(HttpClient, "__init__", spy_init)
    port = _port(app_server)
    run_dast(_dast_cfg([f"127.0.0.1:{port}"]),
             target_url=f"http://127.0.0.1:{port}/", execute=True, authorized=True)
    assert seen.get("verify_tls") is True


def test_dast_cookie_values_never_reach_the_report(app_server):
    """A session cookie value must not appear in the check output."""
    port = _port(app_server)
    res = run_dast(_dast_cfg([f"127.0.0.1:{port}"]),
                   target_url=f"http://127.0.0.1:{port}/cookie",
                   execute=True, authorized=True)
    assert res.ok is True
    assert "SUPERSECRETSESSIONVALUE" not in json.dumps(res.checks)
    # The cookie NAME and its security attributes are still analysed.
    cookies = res.checks[0]["cookies"]
    assert cookies and cookies[0]["name"] == "sessionid"
    assert "HttpOnly" in cookies[0]["flags"]
    assert "Secure" in cookies[0]["flags"]


def test_dast_redirect_location_query_secrets_are_masked():
    """Tokens in a Location header must not be recorded verbatim."""
    assert dast_mod._redact_location("/next?token=abc123&page=2") == "/next?token=***&page=2"
    assert dast_mod._redact_location("/next") == "/next"
    assert dast_mod._redact_location("") == ""


def test_dast_proxy_failure_does_not_fall_back_to_direct(app_server, monkeypatch, proxy_double):
    """A dead proxy must fail the scan, not reach the target directly or direct-retry."""
    port = _port(app_server)
    _force_proxy_for_loopback(monkeypatch)
    _with_proxy(monkeypatch, ProxyConfig.from_url(proxy_double.url))

    res = run_dast(_dast_cfg([f"127.0.0.1:{port}"]),
                   target_url=f"http://127.0.0.1:{port}/", execute=True, authorized=True)
    # The app server was never contacted — neither through the proxy nor directly.
    assert app_server.hits == []
    assert res.checks[0]["status"] is None
    assert "proxy" in (res.checks[0]["error"] or "").lower()
    # The proxy layer saw every request (but refused them all).
    assert len(proxy_double.connections) >= 1


# ---------------------------------------------------------------------------
# AI adapter
# ---------------------------------------------------------------------------


def _ai_cfg(**overrides: Any) -> AIConfig:
    params: dict[str, Any] = {
        "enabled": True,
        "base_url": "http://127.0.0.1:9/v1",
        "api_key": "sk-test-key",
        "model": "test-model",
        "max_retries": 0,
        "timeout_seconds": 5,
    }
    params.update(overrides)
    return AIConfig(**params)


def test_ai_has_no_independent_http_path():
    """The AI adapter must not carry its own urllib-based transport."""
    assert not hasattr(ai_mod, "urllib")
    source = Path(ai_mod.__file__).read_text(encoding="utf-8")
    for needle in ("urllib.request", "urllib.error", "http.client"):
        assert needle not in source, f"AI still references {needle}"


def test_ai_sends_provider_authorization_header(monkeypatch):
    """The provider API key must be sent as a Bearer token.

    Regression guard: the urllib implementation sent
    ``Authorization: Bearer <key>`` and the HttpClient migration must not
    have dropped it, or every provider call would fail with 401.
    """
    captured: dict[str, Any] = {}

    class _Resp:
        ok = True
        status = 200
        error = None
        error_kind = None
        body = b"{}"

        def json(self) -> Any:
            return {"choices": [{"message": {"content": "ok"}}]}

    def fake_post_json(self, url, payload, **kwargs):
        captured["headers"] = dict(kwargs.get("headers") or {})
        return _Resp()

    monkeypatch.setattr(HttpClient, "post_json", fake_post_json)
    AIAdapter(_ai_cfg()).chat("hi")
    assert captured["headers"].get("Authorization") == "Bearer sk-test-key"


def test_ai_omits_authorization_header_when_no_key(monkeypatch):
    """No key configured means no Authorization header — not an empty one."""
    captured: dict[str, Any] = {}

    class _Resp:
        ok = True
        status = 200
        error = None
        error_kind = None
        body = b"{}"

        def json(self) -> Any:
            return {"choices": [{"message": {"content": "ok"}}]}

    def fake_post_json(self, url, payload, **kwargs):
        captured["headers"] = dict(kwargs.get("headers") or {})
        return _Resp()

    monkeypatch.setattr(HttpClient, "post_json", fake_post_json)
    AIAdapter(_ai_cfg(api_key="")).chat("hi")
    assert "Authorization" not in captured["headers"]


def test_ai_key_never_reaches_the_client_log(monkeypatch):
    """The API key must not be written to the client's log output."""
    logged: list[str] = []

    class _Client(HttpClient):
        def __init__(self, **kwargs):
            kwargs["logger"] = logged.append
            super().__init__(**kwargs)

    monkeypatch.setattr("veyron.ai.HttpClient", _Client)

    class _Resp:
        ok = True
        status = 200
        error = None
        error_kind = None
        body = b"{}"

        def json(self) -> Any:
            return {"choices": [{"message": {"content": "ok"}}]}

    monkeypatch.setattr(HttpClient, "post_json", lambda self, url, p, **k: _Resp())
    AIAdapter(_ai_cfg(api_key="sk-secret-value")).chat("hi")
    assert not any("sk-secret-value" in line for line in logged)


def test_ai_uses_configured_provider_endpoint(monkeypatch):
    """The provider endpoint comes from configuration and is used verbatim."""
    captured: dict[str, Any] = {}

    class _Resp:
        ok = True
        status = 200
        error = None
        error_kind = None
        body = b"{}"

        def json(self) -> Any:
            return {"choices": [{"message": {"content": "ok"}}]}

    def fake_post_json(self, url, payload, **kwargs):
        captured["url"] = url
        return _Resp()

    monkeypatch.setattr(HttpClient, "post_json", fake_post_json)
    AIAdapter(_ai_cfg(base_url="http://gateway.local:3103/v1/")).chat("hi")
    assert captured["url"] == "http://gateway.local:3103/v1/chat/completions"


def test_ai_does_not_apply_website_allowlist(monkeypatch):
    """The AI gateway is a configured endpoint, not a website target."""
    seen: dict[str, Any] = {}
    original_init = HttpClient.__init__

    def spy_init(self, **kwargs):
        seen.update(kwargs)
        original_init(self, **kwargs)

    monkeypatch.setattr(HttpClient, "__init__", spy_init)
    AIAdapter(_ai_cfg())._build_client()
    assert seen.get("scope") is None


def test_ai_client_uses_configured_proxy(monkeypatch):
    """The AI client carries the operator's proxy configuration."""
    proxy = ProxyConfig.from_url(f"http://127.0.0.1:{_free_port()}")
    _with_proxy(monkeypatch, proxy)
    seen: dict[str, Any] = {}
    original_init = HttpClient.__init__

    def spy_init(self, **kwargs):
        seen.update(kwargs)
        original_init(self, **kwargs)

    monkeypatch.setattr(HttpClient, "__init__", spy_init)
    AIAdapter(_ai_cfg())._build_client()
    assert seen.get("proxy") is proxy


def test_ai_proxy_failure_does_not_fall_back_to_direct(monkeypatch, proxy_double):
    """A dead proxy must fail the call, not reach the provider directly."""
    _with_proxy(monkeypatch, ProxyConfig.from_url(proxy_double.url))

    direct_calls: list[str] = []
    original_direct = HttpClient._single_direct

    def spy_direct(self, *args, **kwargs):
        direct_calls.append(args[0] if args else "")
        return original_direct(self, *args, **kwargs)

    monkeypatch.setattr(HttpClient, "_single_direct", spy_direct)

    result = AIAdapter(_ai_cfg(base_url="http://gateway.example.invalid/v1")).chat("hi")
    assert result.ok is False
    assert result.failure_kind == "unreachable"
    assert "proxy_error" in (result.error or "")
    assert direct_calls == []
    assert len(proxy_double.connections) >= 1


def test_ai_healthcheck_succeeds(monkeypatch):
    """The healthcheck must not raise — it used to pass a bad keyword."""
    seen: dict[str, Any] = {}

    class _Resp:
        ok = True
        status = 200
        error = None
        error_kind = None
        body = b"{}"

        def json(self) -> Any:
            return {"choices": [{"message": {"content": "OK"}}]}

    def fake_post_json(self, url, payload, **kwargs):
        seen["messages"] = payload.get("messages")
        return _Resp()

    monkeypatch.setattr(HttpClient, "post_json", fake_post_json)
    result = AIAdapter(_ai_cfg()).healthcheck()
    assert result.ok is True
    assert seen["messages"]


def test_ai_healthcheck_failure_is_reported(monkeypatch):
    """A failing healthcheck is reported, not raised."""
    class _Resp:
        ok = False
        status = None
        error = "connection refused"
        error_kind = "proxy_error"
        body = b""

    monkeypatch.setattr(HttpClient, "post_json", lambda self, url, p, **k: _Resp())
    result = AIAdapter(_ai_cfg()).healthcheck()
    assert result.ok is False
    assert result.failure_kind == "unreachable"


# ---------------------------------------------------------------------------
# OSV adapter
# ---------------------------------------------------------------------------


def test_osv_uses_shared_http_client(tmp_path):
    """OSV must route its queries through HttpClient."""
    assert not hasattr(osv_mod, "urllib")
    ad = OSVAdapter(timeout=5, config={"cache_path": str(tmp_path / "cache.json")})
    assert isinstance(ad._client, HttpClient)


def test_osv_respects_configured_endpoint(monkeypatch, tmp_path):
    """OSV must query its own configured endpoint, not an arbitrary host."""
    captured: dict[str, Any] = {}

    class _Resp:
        ok = True
        status = 200
        error = None
        error_kind = None
        body = b"{}"

        def json(self) -> Any:
            return {"results": []}

    def fake_post_json(self, url, payload, **kwargs):
        captured["url"] = url
        return _Resp()

    monkeypatch.setattr(HttpClient, "post_json", fake_post_json)
    ad = OSVAdapter(timeout=5, config={"cache_path": str(tmp_path / "cache.json")})
    ad._query_osv_batch([("PyPI", "requests", "2.0.0")])
    assert captured["url"] == osv_mod.OSV_BATCH_URL
    assert "api.osv.dev" in captured["url"]


def test_osv_proxy_failure_does_not_fall_back_to_direct(monkeypatch, tmp_path, proxy_double):
    """A dead OSV proxy must fail the scan, not query OSV directly."""
    _with_proxy(monkeypatch, ProxyConfig.from_url(proxy_double.url))

    direct_calls: list[str] = []
    original_direct = HttpClient._single_direct

    def spy_direct(self, *args, **kwargs):
        direct_calls.append(args[0] if args else "")
        return original_direct(self, *args, **kwargs)

    monkeypatch.setattr(HttpClient, "_single_direct", spy_direct)

    ad = OSVAdapter(timeout=2, config={"cache_path": str(tmp_path / "cache.json")})
    assert ad._client.proxy.configured is True
    with pytest.raises(OSError):
        ad._query_osv_batch([("PyPI", "requests", "2.0.0")])
    assert direct_calls == []
    assert len(proxy_double.connections) >= 1


def test_osv_offline_mode_makes_no_external_requests(monkeypatch, tmp_path):
    """Offline mode must issue zero requests — not even one."""
    calls: list[str] = []

    def trap_post(self, url, payload, **kwargs):
        calls.append(url)
        raise AssertionError("offline mode must not POST")

    def trap_get(self, url, **kwargs):
        calls.append(url)
        raise AssertionError("offline mode must not GET")

    monkeypatch.setattr(HttpClient, "post_json", trap_post)
    monkeypatch.setattr(HttpClient, "get", trap_get)

    ad = OSVAdapter(timeout=5, config={"offline": True,
                                       "cache_path": str(tmp_path / "cache.json")})
    result = ad.scan(Path(__file__).resolve().parents[1])
    assert result.ok is True
    assert calls == []


def test_osv_offline_with_no_cache_is_rejected(tmp_path):
    """Offline without a cache is a configuration error."""
    ad = OSVAdapter(timeout=5, config={"offline": True,
                                       "cache_path": str(tmp_path / "missing.json")})
    ok, message = ad.validate_config()
    assert ok is False
    assert message


# ---------------------------------------------------------------------------
# Repo-wide structural audit
# ---------------------------------------------------------------------------

_HTTP_MARKERS = ("urllib.request", "urllib.error", "http.client", "requests", "httpx", "aiohttp")
_RAW_SOCKET_MARKERS = ("socket.socket(", "socket.create_connection(")


def _source_files() -> list[Path]:
    files = [p for p in (REPO_ROOT / "veyron").rglob("*.py")]
    return sorted(files)


def _is_network_layer(rel: Path) -> bool:
    """True for files inside ``veyron/net/`` — the sanctioned transport."""
    return rel.parts[:2] == ("veyron", "net")


def test_no_module_uses_urllib_request_for_http():
    """No module outside the network layer may open an HTTP request itself."""
    offenders: list[str] = []
    for path in _source_files():
        rel = path.relative_to(REPO_ROOT)
        if _is_network_layer(rel):
            continue
        text = path.read_text(encoding="utf-8")
        for marker in _HTTP_MARKERS:
            # A docstring mention is fine; an import or call is not.
            if f"import {marker}" in text or f"{marker}." in text:
                offenders.append(f"{rel}: {marker}")
    assert offenders == [], offenders


def test_no_module_opens_raw_sockets_outside_net_layer():
    """Only the network layer may open a raw socket."""
    offenders: list[str] = []
    for path in _source_files():
        rel = path.relative_to(REPO_ROOT)
        if _is_network_layer(rel):
            continue
        text = path.read_text(encoding="utf-8")
        for marker in _RAW_SOCKET_MARKERS:
            if marker in text:
                offenders.append(f"{rel}: {marker}")
    assert offenders == [], offenders
