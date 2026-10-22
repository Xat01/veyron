"""Shared network layer for every HTTP-based VEYRON module.

All outbound HTTP traffic (dynamic assessment, advisory lookups, AI gateway
calls) goes through :class:`HttpClient` so that no individual scanner can
accidentally bypass the controls:

* proxy routing (HTTP/HTTPS CONNECT, SOCKS5, optional Tor),
* fail-closed proxy behaviour — a proxy failure never falls back to a direct
  connection,
* scope enforcement before a socket is opened,
* destination-address validation (DNS-rebinding defence),
* redirect validation on every hop,
* request budgets, deadlines, timeouts and cancellation,
* TLS verification on by default and never disabled silently,
* safe logging with credential redaction,
* normalised error reporting.

The client is deliberately built on :mod:`http.client` rather than
:mod:`urllib.request` because VEYRON needs to connect to a *validated IP
address* while still presenting the original hostname for SNI and the
``Host`` header. That combination is what makes the DNS-rebinding defence
meaningful, and it is not expressible with the high-level urllib API.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping
from urllib.parse import urljoin, urlsplit

from .proxy import ProxyConfig
from .scope import Scope, ScopeDecision
from .socks5 import Socks5Error, socks5_connect

DEFAULT_USER_AGENT = "VEYRON/0.2 (authorised security assessment)"
DEFAULT_MAX_BODY_BYTES = 2_000_000

# Query/header names whose values must never be logged.
SENSITIVE_KEYS = (
    "password", "passwd", "pwd", "token", "access_token", "api_key", "apikey",
    "secret", "client_secret", "authorization", "auth", "key", "session",
    "sessionid", "sid", "cookie", "csrf", "signature", "sig",
)

Logger = Callable[[str], None]


def redact_url(url: str) -> str:
    """Remove credentials and sensitive query values from a URL for display."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparsable-url>"

    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    if parts.username:
        netloc = f"***@{netloc}"

    query = parts.query
    if query:
        redacted_pairs = []
        for pair in query.split("&"):
            name, sep, _value = pair.partition("=")
            if sep and name.lower() in SENSITIVE_KEYS:
                redacted_pairs.append(f"{name}=***")
            else:
                redacted_pairs.append(pair)
        query = "&".join(redacted_pairs)

    path = parts.path or ""
    return f"{parts.scheme}://{netloc}{path}" + (f"?{query}" if query else "")


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Mask sensitive header values."""
    out: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in ("authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"):
            out[name] = "***"
        else:
            out[name] = value
    return out


@dataclass
class ClientStats:
    """Request accounting for one client instance."""

    requests: int = 0
    responses: int = 0
    blocked: int = 0
    redirects: int = 0
    errors: int = 0
    bytes_read: int = 0
    proxy_failures: int = 0
    by_host: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "responses": self.responses,
            "blocked": self.blocked,
            "redirects": self.redirects,
            "errors": self.errors,
            "bytes_read": self.bytes_read,
            "proxy_failures": self.proxy_failures,
            "by_host": dict(self.by_host),
        }


@dataclass
class HttpResponse:
    """Normalised HTTP result. ``ok`` is False only for transport failures."""

    ok: bool
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    header_list: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    url: str = ""
    final_url: str = ""
    elapsed_ms: int = 0
    error: str | None = None
    error_kind: str | None = None
    truncated: bool = False
    redirects: list[dict[str, Any]] = field(default_factory=list)
    redirect_target: str | None = None
    redirect_in_scope: bool | None = None
    via_proxy: bool = False

    def text(self, limit: int | None = None) -> str:
        raw = self.body[:limit] if limit else self.body
        return raw.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8", "replace"))

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that dials a pre-validated IP address.

    ``connect_port`` differs from the logical ``port`` when the connection
    targets an HTTP proxy: the TCP connection goes to the proxy's port while
    the request itself addresses the original host and port.
    """

    def __init__(self, hostname: str, port: int, ip: str, timeout: float, connect_port: int | None = None):
        super().__init__(hostname, port=port, timeout=timeout)
        self._ip = ip
        self._connect_port = connect_port if connect_port is not None else port

    def connect(self) -> None:  # noqa: D102 - stdlib override
        self.sock = socket.create_connection((self._ip, self._connect_port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that dials a pre-validated IP but keeps SNI/Host."""

    def __init__(self, hostname: str, port: int, ip: str, timeout: float, context: ssl.SSLContext):
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self) -> None:  # noqa: D102 - stdlib override
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _TunneledHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection over an already-established proxy tunnel."""

    def __init__(self, hostname: str, port: int, tunnel: socket.socket, context: ssl.SSLContext):
        super().__init__(hostname, port=port, timeout=tunnel.gettimeout(), context=context)
        self._tunnel = tunnel

    def connect(self) -> None:  # noqa: D102 - stdlib override
        self.sock = self._context.wrap_socket(self._tunnel, server_hostname=self.host)


class HttpClient:
    """Scope-enforcing, proxy-aware, budget-bound HTTP client."""

    def __init__(
        self,
        *,
        scope: Scope | None = None,
        proxy: ProxyConfig | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
        max_requests: int = 200,
        rate_limit_per_second: float = 0.0,
        max_redirects: int = 5,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        deadline_seconds: float | None = None,
        cancel_event: threading.Event | None = None,
        logger: Logger | None = None,
        proxy_bypass_loopback: bool = True,
    ):
        self.scope = scope
        self.proxy = proxy if proxy is not None else ProxyConfig()
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.user_agent = user_agent
        self.max_requests = max_requests
        self.rate_limit_per_second = rate_limit_per_second
        self.max_redirects = max_redirects
        self.max_body_bytes = max_body_bytes
        self.deadline_seconds = deadline_seconds
        self.cancel_event = cancel_event or threading.Event()
        self.logger = logger
        self.proxy_bypass_loopback = proxy_bypass_loopback
        self.stats = ClientStats()
        self._started = time.monotonic()
        self._last_request_at = 0.0
        self._lock = threading.Lock()

    # -- lifecycle ------------------------------------------------------------

    def cancel(self) -> None:
        """Request cancellation of in-flight and future requests."""
        self.cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def close(self) -> None:
        self.cancel_event.set()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- public API -----------------------------------------------------------

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post_json(self, url: str, payload: Any, **kwargs: Any) -> HttpResponse:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(kwargs.pop("headers", None) or {})
        return self.request("POST", url, body=body, headers=headers, **kwargs)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        allow_redirects: bool = False,
        timeout: float | None = None,
    ) -> HttpResponse:
        """Perform an HTTP request under all scope and routing controls."""
        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Connection": "close",
        }
        for name, value in (headers or {}).items():
            request_headers[name] = value

        started = time.monotonic()
        current_url = url
        hops: list[dict[str, Any]] = []
        last_response: HttpResponse | None = None

        for _ in range(self.max_redirects + 1):
            if self.cancelled:
                return self._fail(current_url, "cancelled", "assessment cancelled", started, hops)
            if self._deadline_exceeded():
                return self._fail(current_url, "deadline_exceeded", "assessment deadline reached", started, hops)

            response = self._single(current_url, method, request_headers, body, timeout)
            last_response = response
            hops.append({"url": current_url, "status": response.status, "error_kind": response.error_kind})
            response.redirects = list(hops)

            if response.status and response.status in (301, 302, 303, 307, 308):
                location = response.header("location")
                if location:
                    target = urljoin(current_url, location)
                    response.redirect_target = target
                    decision = self._check_redirect(current_url, target)
                    response.redirect_in_scope = decision.allowed
                    if not decision.allowed:
                        response.error_kind = "redirect_blocked"
                        response.error = decision.reason
                        self.stats.blocked += 1
                        self._log(f"redirect blocked: {redact_url(target)} ({decision.reason})")
                    elif not allow_redirects:
                        response.error = "redirect not followed (redirect following disabled)"
                    else:
                        self.stats.redirects += 1
                        current_url = target
                        continue
            return response

        # Redirect limit reached: surface the last observed response rather
        # than discarding it, but mark the request as failed.
        if last_response is not None:
            last_response.error_kind = "too_many_redirects"
            last_response.error = "redirect limit exceeded"
            last_response.redirects = list(hops)
            self.stats.errors += 1
            return last_response
        return self._fail(current_url, "too_many_redirects", "redirect limit exceeded", started, hops)

    # -- internals ------------------------------------------------------------

    def _fail(
        self,
        url: str,
        kind: str,
        message: str,
        started: float,
        hops: list[dict[str, Any]] | None = None,
    ) -> HttpResponse:
        self.stats.errors += 1
        self._log(f"request failed [{kind}] {redact_url(url)}: {message}")
        return HttpResponse(
            ok=False,
            url=url,
            final_url=url,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            error=message,
            error_kind=kind,
            redirects=list(hops or []),
        )

    def _log(self, message: str) -> None:
        if self.logger:
            try:
                self.logger(message)
            except Exception:  # pragma: no cover - logging must never break a scan
                pass

    def _deadline_exceeded(self) -> bool:
        if self.deadline_seconds is None:
            return False
        return (time.monotonic() - self._started) > self.deadline_seconds

    def _check_redirect(self, current_url: str, target_url: str) -> ScopeDecision:
        if self.scope is None:
            return ScopeDecision(True, "no scope configured")
        return self.scope.check_redirect(current_url, target_url)

    def _rate_limit(self) -> None:
        if self.rate_limit_per_second <= 0:
            return
        interval = 1.0 / self.rate_limit_per_second
        now = time.monotonic()
        wait = interval - (now - self._last_request_at)
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    def _single(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float | None,
    ) -> HttpResponse:
        started = time.monotonic()
        effective_timeout = timeout if timeout is not None else self.timeout

        parts = urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            return self._fail(url, "unsupported_scheme", f"unsupported URL scheme '{scheme}'", started)
        host = (parts.hostname or "").lower()
        if not host:
            return self._fail(url, "invalid_url", "URL has no host", started)
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            return self._fail(url, "invalid_url", "URL has an invalid port", started)

        if self.scope is not None:
            decision = self.scope.check_url(url)
            if not decision.allowed:
                self.stats.blocked += 1
                self._log(f"blocked out-of-scope request: {redact_url(url)} ({decision.reason})")
                return self._fail(url, "scope", decision.reason, started)

        with self._lock:
            if self.stats.requests >= self.max_requests:
                return self._fail(url, "budget_exhausted", "request budget exhausted", started)

        if self.cancelled:
            return self._fail(url, "cancelled", "assessment cancelled", started)

        # Resolve and validate the destination address before connecting.
        addresses: list[str] = []
        if self.scope is not None and self.scope.resolve_dns:
            try:
                addresses = self.scope.resolve(host, port)
            except OSError as exc:
                return self._fail(url, "dns_error", f"cannot resolve '{host}': {exc}", started)
            if not addresses:
                return self._fail(url, "dns_error", f"no addresses for '{host}'", started)
            decision = self.scope.check_addresses(addresses)
            if not decision.allowed:
                self.stats.blocked += 1
                self._log(f"blocked request to disallowed address: {redact_url(url)} ({decision.reason})")
                return self._fail(url, "address_blocked", decision.reason, started)
        else:
            try:
                addresses = [host]
            except Exception:  # pragma: no cover - defensive
                addresses = [host]

        if self.proxy.configured and self._proxy_applies(host):
            return self._single_via_proxy(
                url, scheme, host, port, addresses, method, headers, body, effective_timeout, started
            )
        return self._single_direct(
            url, scheme, host, port, addresses, method, headers, body, effective_timeout, started
        )

    def _proxy_applies(self, host: str) -> bool:
        """Loopback targets bypass the proxy unless explicitly disabled.

        Routing a local AI gateway or a local test service through an
        external proxy is never what the operator wants and would break the
        request, so loopback destinations are exempt. The exemption is
        reported by ``veyron proxy status``.
        """
        if not self.proxy_bypass_loopback:
            return True
        if host in ("localhost", "127.0.0.1", "::1"):
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return True
        return not addr.is_loopback

    # -- transport ------------------------------------------------------------

    def _single_direct(
        self,
        url: str,
        scheme: str,
        host: str,
        port: int,
        addresses: list[str],
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        started: float,
    ) -> HttpResponse:
        last_error: str = "connection failed"
        last_kind: str = "connection_error"
        for address in addresses:
            connection = self._build_connection(scheme, host, port, address, timeout, None)
            try:
                return self._send(connection, url, scheme, host, port, method, headers, body, started, via_proxy=False)
            except _TransportError as exc:
                last_error = str(exc)
                last_kind = exc.kind
                try:
                    connection.close()
                except Exception:
                    pass
                if exc.kind in ("scope", "address_blocked"):
                    break
        return self._fail(url, last_kind, last_error, started)

    def _single_via_proxy(
        self,
        url: str,
        scheme: str,
        host: str,
        port: int,
        addresses: list[str],
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        started: float,
    ) -> HttpResponse:
        proxy = self.proxy
        proxy_auth = self._proxy_authorization()
        last_error = "proxy connection failed"
        last_kind = "proxy_error"

        proxy_addresses = self._proxy_addresses()
        if not proxy_addresses:
            self.stats.proxy_failures += 1
            return self._fail(
                url,
                "proxy_error",
                f"cannot resolve proxy host '{proxy.host}'",
                started,
            )

        for proxy_address in proxy_addresses:
            tunnel: socket.socket | None = None
            connection = None
            try:
                if proxy.is_socks:
                    tunnel = socks5_connect(
                        proxy.host,
                        proxy.port,
                        addresses[0],
                        port,
                        timeout=timeout,
                        username=proxy.username or None,
                        password=proxy.password or None,
                    )
                    if scheme == "https":
                        connection = _TunneledHTTPSConnection(host, port, tunnel, self._ssl_context())
                        tunnel = None
                    else:
                        connection = _PinnedHTTPConnection(host, port, addresses[0], timeout)
                        connection.sock = tunnel
                        tunnel = None
                elif scheme == "https":
                    tunnel = self._http_proxy_tunnel(
                        proxy_address, addresses[0], port, host, proxy_auth, timeout
                    )
                    connection = _TunneledHTTPSConnection(host, port, tunnel, self._ssl_context())
                    tunnel = None
                else:
                    # Plain HTTP through an HTTP proxy: absolute-form request
                    # target, TCP connection to the proxy endpoint.
                    connection = _PinnedHTTPConnection(
                        host, port, proxy_address, timeout, connect_port=proxy.port
                    )
                return self._send(
                    connection, url, scheme, host, port, method, headers, body, started, via_proxy=True
                )
            except Socks5Error as exc:
                self.stats.proxy_failures += 1
                last_error = str(exc)
                last_kind = "proxy_error"
            except _TransportError as exc:
                self.stats.proxy_failures += 1
                last_error = str(exc)
                last_kind = "proxy_error"
            except OSError as exc:
                self.stats.proxy_failures += 1
                last_error = f"proxy transport failure: {exc}"
                last_kind = "proxy_error"
            finally:
                if tunnel is not None:
                    try:
                        tunnel.close()
                    except OSError:
                        pass
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass

        # Fail closed: a proxy failure is never retried over a direct connection.
        self.stats.proxy_failures += 1
        self._log(f"proxy failure (no direct fallback): {proxy.endpoint()} — {last_error}")
        return self._fail(url, "proxy_error", last_error, started)

    def _proxy_addresses(self) -> list[str]:
        """Resolve the proxy endpoint to literal addresses."""
        if not self.proxy.host:
            return []
        try:
            ipaddress.ip_address(self.proxy.host)
            return [self.proxy.host]
        except ValueError:
            pass
        try:
            infos = socket.getaddrinfo(self.proxy.host, self.proxy.port, type=socket.SOCK_STREAM)
        except OSError:
            return []
        addresses: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in addresses:
                addresses.append(addr)
        return addresses

    def _http_proxy_tunnel(
        self,
        proxy_address: str,
        target_address: str,
        port: int,
        host: str,
        proxy_auth: str | None,
        timeout: float,
    ) -> socket.socket:
        """Establish a CONNECT tunnel through an HTTP proxy."""
        proxy = self.proxy
        try:
            sock = socket.create_connection((proxy_address, proxy.port), timeout=timeout)
        except OSError as exc:
            raise _TransportError(f"cannot reach HTTP proxy {proxy.endpoint()}: {exc}", "proxy_error") from exc
        request = [f"CONNECT {target_address}:{port} HTTP/1.1", f"Host: {host}:{port}"]
        if proxy_auth:
            request.append(f"Proxy-Authorization: {proxy_auth}")
        request.append("Connection: keep-alive")
        try:
            sock.sendall(("\r\n".join(request) + "\r\n\r\n").encode("ascii"))
            header_blob = b""
            while b"\r\n\r\n" not in header_blob:
                chunk = sock.recv(4096)
                if not chunk:
                    raise _TransportError("proxy closed the connection during CONNECT", "proxy_error")
                header_blob += chunk
                if len(header_blob) > 64_000:
                    raise _TransportError("proxy sent an oversized CONNECT response", "proxy_error")
        except OSError as exc:
            sock.close()
            raise _TransportError(f"HTTP proxy CONNECT failed: {exc}", "proxy_error") from exc
        status_line = header_blob.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit() or int(parts[1]) not in (200,):
            sock.close()
            raise _TransportError(f"proxy refused CONNECT: {status_line.strip()}", "proxy_error")
        sock.settimeout(timeout)
        return sock

    def _proxy_authorization(self) -> str | None:
        if not self.proxy.has_credentials:
            return None
        token = f"{self.proxy.username}:{self.proxy.password}".encode("utf-8")
        return "Basic " + base64.b64encode(token).decode("ascii")

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if not self.verify_tls:
            # Explicitly requested by the operator only — never silently.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def _build_connection(
        self,
        scheme: str,
        host: str,
        port: int,
        address: str,
        timeout: float,
        tunnel: socket.socket | None,
    ) -> http.client.HTTPConnection:
        if scheme == "https":
            if tunnel is not None:
                return _TunneledHTTPSConnection(host, port, tunnel, self._ssl_context())
            return _PinnedHTTPSConnection(host, port, address, timeout, self._ssl_context())
        connection = _PinnedHTTPConnection(host, port, address, timeout)
        if tunnel is not None:
            connection.sock = tunnel
        return connection

    def _send(
        self,
        connection: http.client.HTTPConnection,
        url: str,
        scheme: str,
        host: str,
        port: int,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        started: float,
        *,
        via_proxy: bool,
    ) -> HttpResponse:
        self._rate_limit()
        if self.cancelled:
            raise _TransportError("assessment cancelled", "cancelled")

        path = urlsplit(url).path or "/"
        query = urlsplit(url).query
        if query:
            path = f"{path}?{query}"

        with self._lock:
            self.stats.requests += 1
            self.stats.by_host[host] = self.stats.by_host.get(host, 0) + 1

        request_headers = dict(headers)
        request_headers.setdefault("Host", f"{host}:{port}" if port not in (80, 443) else host)
        if body is not None:
            request_headers.setdefault("Content-Length", str(len(body)))
        if via_proxy and not self.proxy.is_socks and scheme == "http":
            # Absolute-form request target, as required for HTTP proxies.
            target = f"{scheme}://{host}:{port}{path}"
            request_headers["Host"] = f"{host}:{port}" if port not in (80, 443) else host
        else:
            target = path

        try:
            connection.putrequest(method, target, skip_host="Host" in request_headers)
            for name, value in request_headers.items():
                connection.putheader(name, value)
            connection.endheaders(body if body else None)
            raw = connection.getresponse()
        except socket.timeout as exc:
            raise _TransportError(f"request timed out after {self.timeout}s", "timeout") from exc
        except TimeoutError as exc:
            raise _TransportError(f"request timed out after {self.timeout}s", "timeout") from exc
        except ssl.SSLCertVerificationError as exc:
            raise _TransportError(f"TLS certificate verification failed: {exc}", "tls_error") from exc
        except ssl.SSLError as exc:
            raise _TransportError(f"TLS error: {exc}", "tls_error") from exc
        except http.client.HTTPException as exc:
            raise _TransportError(f"malformed HTTP response: {exc}", "http_error") from exc
        except OSError as exc:
            kind = "connection_error"
            if via_proxy:
                kind = "proxy_error"
            raise _TransportError(f"connection failed: {exc}", kind) from exc

        payload = raw.read(self.max_body_bytes + 1)
        truncated = len(payload) > self.max_body_bytes
        if truncated:
            payload = payload[: self.max_body_bytes]

        header_list = [(k, v) for k, v in raw.getheaders()]
        header_map: dict[str, str] = {}
        for name, value in header_list:
            key = name.lower()
            if key in header_map:
                header_map[key] = f"{header_map[key]}, {value}"
            else:
                header_map[key] = value

        self.stats.responses += 1
        self.stats.bytes_read += len(payload)
        self._log(f"{method} {redact_url(url)} -> {raw.status} (via_proxy={via_proxy})")

        return HttpResponse(
            ok=True,
            status=raw.status,
            headers=header_map,
            header_list=header_list,
            body=payload,
            url=url,
            final_url=url,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            truncated=truncated,
            via_proxy=via_proxy,
        )


class _TransportError(Exception):
    """Internal transport failure carrying a normalised error kind."""

    def __init__(self, message: str, kind: str):
        super().__init__(message)
        self.kind = kind
