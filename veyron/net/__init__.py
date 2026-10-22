"""Shared network layer for VEYRON.

Every HTTP-based VEYRON module (dynamic assessment, advisory lookup, AI
gateway) uses :class:`~veyron.net.client.HttpClient` so that scope
enforcement, proxy routing, budgets, timeouts, cancellation and redaction
cannot be bypassed by an individual module.
"""

from .client import (
    ClientStats,
    HttpClient,
    HttpResponse,
    redact_headers,
    redact_url,
)
from .proxy import ProxyConfig, ProxyConfigError, SUPPORTED_PROXY_SCHEMES
from .scope import DEFAULT_BLOCKED_CIDRS, Scope, ScopeDecision
from .socks5 import Socks5Error, socks5_connect

__all__ = [
    "ClientStats",
    "DEFAULT_BLOCKED_CIDRS",
    "HttpClient",
    "HttpResponse",
    "ProxyConfig",
    "ProxyConfigError",
    "SUPPORTED_PROXY_SCHEMES",
    "Scope",
    "ScopeDecision",
    "Socks5Error",
    "redact_headers",
    "redact_url",
    "socks5_connect",
]
