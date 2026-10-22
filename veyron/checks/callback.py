"""Operator-controlled callback listener for SSRF validation.

The listener binds to loopback only.  It exists so that SSRF validation has a
concrete, observable signal (an inbound request carrying a unique token)
instead of a guess based on timing or response text.  It is not used to probe
cloud metadata or third-party infrastructure.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .base import CallbackVerifier


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        token = parse_qs(urlsplit(self.path).query).get("vyn_token", [""])[0]
        if token:
            self.server.hits.append(token)  # type: ignore[attr-defined]
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: object) -> None:  # pragma: no cover - silence
        pass


class CallbackListener(CallbackVerifier):
    """A loopback HTTP listener used as an authorised SSRF callback target."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, token: str | None = None):
        self._token = token or secrets.token_hex(8)
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.hits = []  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._started = False

    def start(self) -> "CallbackListener":
        if not self._started:
            self._thread.start()
            self._started = True
        return self

    @property
    def token(self) -> str:
        return self._token

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/callback"

    def url_for(self, token: str) -> str:
        return f"{self.url}?vyn_token={token}"

    def hits(self) -> list[str]:
        return list(self._server.hits)  # type: ignore[attr-defined]

    def stop(self) -> None:
        if self._started:
            self._server.shutdown()
            self._server.server_close()
            self._started = False

    def __enter__(self) -> "CallbackListener":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()
