"""Shared network layer: scope enforcement, proxy routing, fail-closed proxy
behaviour, budgets, cancellation, timeouts, and redaction.

All network tests use local servers started by the test itself — no test in
this file contacts a third-party host.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from veyron.config import Config
from veyron.net.client import HttpClient, redact_headers, redact_url
from veyron.net.diagnostics import probe_proxy_route, proxy_status
from veyron.net.proxy import ProxyConfig, ProxyConfigError
from veyron.net.scope import Scope
from veyron.net.socks5 import Socks5Error, socks5_connect


# --------------------------------------------------------------------------- #
# local test servers
# --------------------------------------------------------------------------- #


class _AppHandler(BaseHTTPRequestHandler):
    """Minimal application server used as an assessment target."""

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
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence stderr
        pass


class _ProxyHandler(BaseHTTPRequestHandler):
    """Minimal absolute-form HTTP proxy (test double)."""

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        server = self.server
        server.hits.append(self.path)
        if not self.path.startswith("http://"):
            self.send_error(400, "proxy expects an absolute-form request target")
            return
        rest = self.path[len("http://"):]
        hostport, _, path = rest.partition("/")
        host, _, port = hostport.partition(":")
        port = int(port or 80)
        try:
            upstream = socket.create_connection((host, port), timeout=5)
        except OSError:
            self.send_error(502, "upstream unreachable")
            return
        try:
            upstream.sendall(
                f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n".encode()
            )
            data = b""
            while True:
                chunk = upstream.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            upstream.close()
        self.wfile.write(data)

    def log_message(self, *args: object) -> None:
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, handler: type[BaseHTTPRequestHandler]):
        super().__init__(("127.0.0.1", 0), handler)
        self.hits: list = []
        self.redirect_to = "http://example.com/"
        self.slow_seconds = 2.0


@pytest.fixture
def app_server():
    server = _Server(_AppHandler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def proxy_server():
    server = _Server(_ProxyHandler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _Socks5Server:
    """Minimal SOCKS5 CONNECT proxy used as a test double."""

    def __init__(self, *, require_auth: bool = False, fail_reply: int | None = None):
        self.require_auth = require_auth
        self.fail_reply = fail_reply
        self.log: list[tuple] = []
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            header = _recv_exact(conn, 2)
            nmethods = header[1]
            methods = _recv_exact(conn, nmethods)
            if self.require_auth:
                conn.sendall(bytes([0x05, 0x02]))
                version = _recv_exact(conn, 1)[0]
                ulen = _recv_exact(conn, 1)[0]
                user = _recv_exact(conn, ulen).decode()
                plen = _recv_exact(conn, 1)[0]
                password = _recv_exact(conn, plen).decode()
                self.log.append(("auth", user, password))
                conn.sendall(bytes([0x01, 0x00]))
            else:
                conn.sendall(bytes([0x05, 0x00]))
            _ = methods

            request = _recv_exact(conn, 4)
            atyp = request[3]
            if atyp == 0x01:
                host = socket.inet_ntoa(_recv_exact(conn, 4))
            elif atyp == 0x03:
                length = _recv_exact(conn, 1)[0]
                host = _recv_exact(conn, length).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, _recv_exact(conn, 16))
            port = int.from_bytes(_recv_exact(conn, 2), "big")
            self.log.append(("connect", host, port))

            if self.fail_reply is not None:
                conn.sendall(bytes([0x05, self.fail_reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
                return

            upstream = socket.create_connection((host, port), timeout=5)
            conn.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))

            def pump(src: socket.socket, dst: socket.socket) -> None:
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except OSError:
                    pass
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            t1 = threading.Thread(target=pump, args=(conn, upstream), daemon=True)
            t2 = threading.Thread(target=pump, args=(upstream, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join(10)
            t2.join(10)
            upstream.close()
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


@pytest.fixture
def socks5_server():
    server = _Socks5Server()
    try:
        yield server
    finally:
        server.stop()


def _scope_for(port: int, **kwargs) -> Scope:
    return Scope.from_allowlist([f"127.0.0.1:{port}"], **kwargs)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #


def test_scope_allows_allowlisted_host_and_port():
    scope = _scope_for(8080)
    assert scope.check_url("http://127.0.0.1:8080/path").allowed
    assert not scope.check_url("http://127.0.0.1:9090/path").allowed


def test_scope_blocks_unlisted_host():
    scope = _scope_for(8080)
    decision = scope.check_url("http://example.com/")
    assert not decision.allowed
    assert "authorised scope" in decision.reason


def test_scope_blocks_non_http_scheme():
    scope = _scope_for(8080)
    assert not scope.check_url("file:///etc/passwd").allowed


def test_scope_blocks_lookalike_host():
    scope = _scope_for(8080)
    assert not scope.check_url("http://127.0.0.1.evil.com:8080/").allowed


def test_scope_excluded_host_wins_over_allowlist():
    scope = Scope.from_allowlist(["127.0.0.1:8080"])
    scope.excluded_hosts = ["127.0.0.1"]
    assert not scope.check_url("http://127.0.0.1:8080/").allowed


def test_scope_path_rules():
    scope = _scope_for(8080)
    scope.allowed_paths = ["/app/"]
    scope.excluded_paths = ["/app/admin"]
    assert scope.check_url("http://127.0.0.1:8080/app/index").allowed
    assert not scope.check_url("http://127.0.0.1:8080/other").allowed
    assert not scope.check_url("http://127.0.0.1:8080/app/admin/panel").allowed


def test_scope_wildcard_subdomain():
    scope = Scope.from_allowlist(["*.example.com"])
    assert scope.check_url("https://api.example.com/").allowed
    assert not scope.check_url("https://example.com/").allowed
    assert not scope.check_url("https://evil-example.com/").allowed


def test_scope_cross_host_redirect_is_blocked():
    scope = _scope_for(8080)
    decision = scope.check_redirect("http://127.0.0.1:8080/a", "http://example.com/")
    assert not decision.allowed


def test_scope_same_host_redirect_is_allowed():
    scope = _scope_for(8080)
    assert scope.check_redirect("http://127.0.0.1:8080/a", "http://127.0.0.1:8080/b").allowed


def test_scope_blocks_cloud_metadata_address():
    scope = _scope_for(8080)
    decision = scope.check_addresses(["169.254.169.254"])
    assert not decision.allowed
    assert "blocked range" in decision.reason


def test_scope_allowed_cidr_overrides_blocklist():
    scope = _scope_for(8080)
    scope.allowed_cidrs = ["169.254.0.0/16"]
    assert scope.check_addresses(["169.254.169.254"]).allowed


def test_scope_can_refuse_private_addresses():
    scope = _scope_for(8080)
    scope.allow_private_addresses = False
    assert not scope.check_addresses(["10.0.0.5"]).allowed


# --------------------------------------------------------------------------- #
# proxy configuration
# --------------------------------------------------------------------------- #


def test_proxy_parses_http_url():
    proxy = ProxyConfig.from_url("http://127.0.0.1:8080")
    assert proxy.configured and proxy.scheme == "http"
    assert proxy.port == 8080 and not proxy.is_socks


def test_proxy_parses_socks5_url():
    proxy = ProxyConfig.from_url("socks5h://127.0.0.1:9050")
    assert proxy.is_socks and proxy.port == 9050


def test_proxy_parses_credentials():
    proxy = ProxyConfig.from_url("http://user:pass@127.0.0.1:8080")
    assert proxy.username == "user" and proxy.password == "pass"
    assert proxy.has_credentials


def test_proxy_rejects_unsupported_scheme():
    with pytest.raises(ProxyConfigError):
        ProxyConfig.from_url("ftp://127.0.0.1:21")


def test_proxy_rejects_empty_url():
    with pytest.raises(ProxyConfigError):
        ProxyConfig.from_url("   ")


def test_proxy_masking_never_exposes_credentials():
    proxy = ProxyConfig.from_url("http://user:supersecret@127.0.0.1:8080")
    masked = proxy.masked()
    assert masked["password"] == "***"
    assert masked["username"] == "***"
    assert "supersecret" not in json.dumps(masked)


def test_proxy_endpoint_has_no_credentials():
    proxy = ProxyConfig.from_url("http://user:supersecret@127.0.0.1:8080")
    assert "supersecret" not in proxy.endpoint()
    assert proxy.endpoint() == "http://127.0.0.1:8080"


# --------------------------------------------------------------------------- #
# redaction helpers
# --------------------------------------------------------------------------- #


def test_redact_url_masks_credentials_and_secret_query():
    redacted = redact_url("https://user:pw@example.com/a?token=abcdef&page=2")
    assert "pw@" not in redacted
    assert "abcdef" not in redacted
    assert "page=2" in redacted


def test_redact_headers_masks_authorization():
    headers = redact_headers({"Authorization": "Bearer secret", "Accept": "*/*"})
    assert headers["Authorization"] == "***"
    assert headers["Accept"] == "*/*"


# --------------------------------------------------------------------------- #
# client behaviour against a local target
# --------------------------------------------------------------------------- #


def test_client_performs_get(app_server):
    port = app_server.server_address[1]
    client = HttpClient(scope=_scope_for(port))
    response = client.get(f"http://127.0.0.1:{port}/hello")
    assert response.ok and response.status == 200
    assert response.body == b"hello-veyron"
    assert client.stats.requests == 1


def test_client_blocks_out_of_scope_before_connecting(app_server):
    port = app_server.server_address[1]
    client = HttpClient(scope=_scope_for(port))
    response = client.get("http://example.com/")
    assert not response.ok
    assert response.error_kind == "scope"
    assert client.stats.requests == 0
    assert app_server.hits == []


def test_client_blocks_out_of_scope_redirect(app_server):
    port = app_server.server_address[1]
    app_server.redirect_to = "http://example.com/"
    client = HttpClient(scope=_scope_for(port))
    response = client.get(f"http://127.0.0.1:{port}/redirect-to", allow_redirects=True)
    # The 3xx response itself was received, but following it was refused and
    # the out-of-scope hop was never contacted.
    assert response.status == 302
    assert response.error_kind == "redirect_blocked"
    assert response.redirect_in_scope is False
    assert client.stats.blocked == 1
    assert len(app_server.hits) == 1


def test_client_follows_in_scope_redirect(app_server):
    port = app_server.server_address[1]
    app_server.redirect_to = f"http://127.0.0.1:{port}/final"
    client = HttpClient(scope=_scope_for(port))
    response = client.get(f"http://127.0.0.1:{port}/redirect-to", allow_redirects=True)
    assert response.ok and response.status == 200
    assert response.redirects and len(response.redirects) == 2


def test_client_does_not_follow_redirects_by_default(app_server):
    port = app_server.server_address[1]
    app_server.redirect_to = f"http://127.0.0.1:{port}/final"
    client = HttpClient(scope=_scope_for(port))
    response = client.get(f"http://127.0.0.1:{port}/redirect-to")
    assert response.status == 302
    assert response.redirect_in_scope is True
    assert client.stats.requests == 1


def test_client_enforces_request_budget(app_server):
    port = app_server.server_address[1]
    client = HttpClient(scope=_scope_for(port), max_requests=1)
    assert client.get(f"http://127.0.0.1:{port}/a").ok
    second = client.get(f"http://127.0.0.1:{port}/b")
    assert not second.ok and second.error_kind == "budget_exhausted"
    assert client.stats.requests == 1


def test_client_honours_cancellation(app_server):
    port = app_server.server_address[1]
    client = HttpClient(scope=_scope_for(port))
    client.cancel()
    response = client.get(f"http://127.0.0.1:{port}/a")
    assert not response.ok and response.error_kind == "cancelled"
    assert client.stats.requests == 0


def test_client_enforces_timeout(app_server):
    port = app_server.server_address[1]
    app_server.slow_seconds = 2.0
    client = HttpClient(scope=_scope_for(port), timeout=0.4)
    response = client.get(f"http://127.0.0.1:{port}/slow")
    assert not response.ok and response.error_kind == "timeout"


def test_client_truncates_large_bodies(app_server):
    port = app_server.server_address[1]
    client = HttpClient(scope=_scope_for(port), max_body_bytes=4)
    response = client.get(f"http://127.0.0.1:{port}/a")
    assert response.truncated is True
    assert response.body == b"hell"


def test_client_records_request_accounting(app_server):
    port = app_server.server_address[1]
    client = HttpClient(scope=_scope_for(port))
    client.get(f"http://127.0.0.1:{port}/a")
    stats = client.stats.to_dict()
    assert stats["requests"] == 1 and stats["responses"] == 1
    assert stats["by_host"]["127.0.0.1"] == 1


def test_client_blocks_unsupported_scheme():
    client = HttpClient(scope=None)
    response = client.get("file:///etc/passwd")
    assert not response.ok and response.error_kind == "unsupported_scheme"


# --------------------------------------------------------------------------- #
# proxy behaviour — fail closed, never fall back to direct
# --------------------------------------------------------------------------- #


def test_proxy_failure_never_falls_back_to_direct(app_server):
    """A dead proxy must produce a proxy error and zero direct requests."""
    port = app_server.server_address[1]
    dead = _free_port()
    proxy = ProxyConfig.from_url(f"http://127.0.0.1:{dead}")
    client = HttpClient(scope=_scope_for(port), proxy=proxy, proxy_bypass_loopback=False)
    response = client.get(f"http://127.0.0.1:{port}/hello")
    assert not response.ok
    assert response.error_kind == "proxy_error"
    assert app_server.hits == [], "target was contacted directly despite proxy failure"
    assert client.stats.proxy_failures >= 1


def test_proxy_routes_request_through_proxy(app_server, proxy_server):
    port = app_server.server_address[1]
    proxy_port = proxy_server.server_address[1]
    proxy = ProxyConfig.from_url(f"http://127.0.0.1:{proxy_port}")
    client = HttpClient(scope=_scope_for(port), proxy=proxy, proxy_bypass_loopback=False)
    response = client.get(f"http://127.0.0.1:{port}/hello")
    assert response.ok and response.status == 200
    assert response.via_proxy is True
    # the proxy saw an absolute-form request target
    assert proxy_server.hits and proxy_server.hits[0].startswith("http://")


def test_loopback_targets_bypass_the_proxy_by_default(app_server, proxy_server):
    """A local target is not routed through a remote proxy unless asked."""
    port = app_server.server_address[1]
    proxy = ProxyConfig.from_url(f"http://127.0.0.1:{proxy_server.server_address[1]}")
    client = HttpClient(scope=_scope_for(port), proxy=proxy)
    response = client.get(f"http://127.0.0.1:{port}/hello")
    assert response.ok
    assert response.via_proxy is False
    assert proxy_server.hits == []


def test_socks5_proxy_routes_request(app_server, socks5_server):
    port = app_server.server_address[1]
    proxy = ProxyConfig.from_url(f"socks5://127.0.0.1:{socks5_server.port}")
    client = HttpClient(scope=_scope_for(port), proxy=proxy, proxy_bypass_loopback=False)
    response = client.get(f"http://127.0.0.1:{port}/hello")
    assert response.ok and response.status == 200
    assert response.via_proxy is True
    connects = [entry for entry in socks5_server.log if entry[0] == "connect"]
    assert connects, "SOCKS proxy was not asked to connect"
    # the destination is a validated IP literal, not a resolvable name
    assert connects[0][1] == "127.0.0.1"


def test_socks5_authentication_is_forwarded(app_server, socks5_server):
    port = app_server.server_address[1]
    socks5_server.require_auth = True
    proxy = ProxyConfig.from_url(f"socks5://user:secret@127.0.0.1:{socks5_server.port}")
    client = HttpClient(scope=_scope_for(port), proxy=proxy, proxy_bypass_loopback=False)
    response = client.get(f"http://127.0.0.1:{port}/hello")
    assert response.ok
    auth_entries = [entry for entry in socks5_server.log if entry[0] == "auth"]
    assert auth_entries and auth_entries[0][1] == "user"


def test_socks5_refused_connection_surfaces_proxy_error(app_server, socks5_server):
    port = app_server.server_address[1]
    socks5_server.fail_reply = 0x05  # connection refused
    proxy = ProxyConfig.from_url(f"socks5://127.0.0.1:{socks5_server.port}")
    client = HttpClient(scope=_scope_for(port), proxy=proxy, proxy_bypass_loopback=False)
    response = client.get(f"http://127.0.0.1:{port}/hello")
    assert not response.ok and response.error_kind == "proxy_error"
    assert app_server.hits == []


def test_socks5_connect_helper_raises_on_refusal(socks5_server):
    socks5_server.fail_reply = 0x05
    with pytest.raises(Socks5Error):
        socks5_connect("127.0.0.1", socks5_server.port, "127.0.0.1", 80, timeout=5)


def test_socks5_connect_helper_raises_when_proxy_unreachable():
    with pytest.raises(Socks5Error):
        socks5_connect("127.0.0.1", _free_port(), "127.0.0.1", 80, timeout=2)


# --------------------------------------------------------------------------- #
# diagnostics
# --------------------------------------------------------------------------- #


def test_proxy_status_without_proxy_reports_direct_routing():
    status = proxy_status(ProxyConfig())
    assert status["proxy_configured"] is False
    assert status["direct_fallback_possible"] is True
    assert "direct" in status["routing"]
    assert status["limitations"]


def test_proxy_status_with_dead_proxy_is_fail_closed():
    proxy = ProxyConfig.from_url(f"http://127.0.0.1:{_free_port()}")
    status = proxy_status(proxy, timeout=1.0)
    assert status["proxy_configured"] is True
    assert status["reachable"] is False
    assert status["direct_fallback_possible"] is False
    assert status["reachability_error"]


def test_proxy_status_never_exposes_credentials():
    proxy = ProxyConfig.from_url("http://user:supersecret@127.0.0.1:8080")
    status = proxy_status(proxy, timeout=1.0)
    assert "supersecret" not in json.dumps(status)


def test_proxy_probe_reports_fail_closed_when_proxy_down(app_server):
    port = app_server.server_address[1]
    proxy = ProxyConfig.from_url(f"http://127.0.0.1:{_free_port()}")
    result = probe_proxy_route(
        proxy, f"http://127.0.0.1:{port}/hello", timeout=3, proxy_bypass_loopback=False
    )
    assert result["ok"] is False
    assert result["error_kind"] == "proxy_error"
    assert result["direct_fallback_possible"] is False
    assert app_server.hits == []


def test_proxy_probe_confirms_route_when_proxy_up(app_server, proxy_server):
    port = app_server.server_address[1]
    proxy = ProxyConfig.from_url(f"http://127.0.0.1:{proxy_server.server_address[1]}")
    result = probe_proxy_route(
        proxy, f"http://127.0.0.1:{port}/hello", timeout=5, proxy_bypass_loopback=False
    )
    assert result["ok"] is True
    assert result["via_proxy"] is True


# --------------------------------------------------------------------------- #
# configuration wiring
# --------------------------------------------------------------------------- #


def test_config_loads_proxy_from_file(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"proxy": {"url": "socks5://127.0.0.1:9050", "tor": True}}),
        encoding="utf-8",
    )
    cfg = Config.load(path)
    assert cfg.proxy.configured
    assert cfg.proxy.is_socks
    assert cfg.proxy.tor is True


def test_config_records_invalid_proxy_problem(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"proxy": {"url": "ftp://127.0.0.1:21"}}), encoding="utf-8")
    cfg = Config.load(path)
    assert cfg.validate()
    assert any("proxy" in problem for problem in cfg.validate())


def test_config_reads_proxy_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("VEYRON_PROXY_URL", "http://127.0.0.1:3128")
    cfg = Config.load(tmp_path / "missing.json")
    assert cfg.proxy.configured
    assert cfg.proxy.port == 3128


def test_config_tor_environment_enables_tor(tmp_path, monkeypatch):
    monkeypatch.setenv("VEYRON_TOR_SOCKS_PROXY", "socks5://127.0.0.1:9050")
    cfg = Config.load(tmp_path / "missing.json")
    assert cfg.proxy.tor is True and cfg.proxy.is_socks


def test_config_display_masks_proxy_credentials(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"proxy": {"url": "http://user:supersecret@127.0.0.1:8080"}}), encoding="utf-8")
    cfg = Config.load(path)
    display = cfg.to_display()
    assert display["proxy"]["password"] == "***"
    assert "supersecret" not in json.dumps(display)


def test_config_saved_and_reloaded(tmp_path):
    cfg = Config()
    cfg.proxy = ProxyConfig.from_url("http://127.0.0.1:3128")
    cfg.network.timeout_seconds = 20
    saved = cfg.save(tmp_path / "config.json")
    reloaded = Config.load(saved)
    assert reloaded.proxy.host == "127.0.0.1"
    assert reloaded.network.timeout_seconds == 20


def test_config_validate_flags_incomplete_proxy():
    cfg = Config()
    cfg.proxy.enabled = True
    assert any("proxy" in problem for problem in cfg.validate())


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #


def test_cli_proxy_status_json(capsys):
    from veyron.cli import main

    code = main(["proxy", "status", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert "proxy_configured" in data
    assert "direct_fallback_possible" in data
    assert data["limitations"]


def test_cli_proxy_status_never_prints_credentials(capsys, tmp_path, monkeypatch):
    from veyron.cli import main

    config = tmp_path / "config.json"
    config.write_text(
        json.dumps({"proxy": {"url": "http://user:supersecret@127.0.0.1:8080"}}),
        encoding="utf-8",
    )
    main(["--config", str(config), "proxy", "status", "--json"])
    out = capsys.readouterr().out
    assert "supersecret" not in out
    assert json.loads(out)["configured_proxy"]["password"] == "***"


def test_cli_proxy_probe_requires_configured_proxy(capsys, tmp_path, monkeypatch):
    from veyron.cli import main

    for var in ("VEYRON_PROXY_URL", "VEYRON_TOR_SOCKS_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    code = main(["--config", str(tmp_path / "none.json"), "proxy", "probe", "http://127.0.0.1:1/"])
    assert code == 2
    assert "no proxy configured" in capsys.readouterr().err
