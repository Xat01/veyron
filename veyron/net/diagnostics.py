"""Proxy diagnostics.

The diagnostic reports *observed* behaviour only:

* which proxy is configured (credentials masked),
* whether the proxy endpoint accepts TCP connections,
* whether the shared network client is configured to route through it,
* whether a direct connection could still be used as a fallback,
* known limitations of the selected routing mode.

It deliberately does not claim that a diagnostic proves anonymity, and it
does not claim to have verified anything it did not observe.
"""

from __future__ import annotations

import socket
from typing import Any

from .client import HttpClient, redact_url
from .proxy import ProxyConfig

LIMITATIONS = [
    "A proxy changes the network path, not the identity of the operator.",
    "DNS resolution happens locally in VEYRON; the resolved address is validated and pinned before connecting.",
    "A proxy can still observe traffic for non-TLS destinations; use HTTPS targets for confidentiality.",
    "No claim of anonymity is made or implied by these diagnostics.",
]


def proxy_status(
    proxy: ProxyConfig,
    *,
    timeout: float = 5.0,
    proxy_bypass_loopback: bool = True,
) -> dict[str, Any]:
    """Report the configured proxy and its observed reachability."""
    status: dict[str, Any] = {
        "configured_proxy": proxy.masked(),
        "proxy_configured": proxy.configured,
        "reachable": False,
        "reachability_error": None,
        "routing": "direct",
        "direct_fallback_possible": True,
        "tor_mode": proxy.tor,
        "loopback_bypasses_proxy": proxy_bypass_loopback,
        "limitations": list(LIMITATIONS),
    }

    if not proxy.configured:
        status["routing"] = "direct (no proxy configured)"
        status["reachability_error"] = "no proxy configured"
        return status

    status["routing"] = f"proxy ({proxy.endpoint()})"
    status["direct_fallback_possible"] = False
    if proxy_bypass_loopback:
        status["limitations"] = list(LIMITATIONS) + [
            "Loopback destinations bypass the proxy; they are contacted directly.",
        ]

    try:
        with socket.create_connection((proxy.host, proxy.port), timeout=timeout):
            status["reachable"] = True
    except OSError as exc:
        status["reachability_error"] = f"cannot connect to {proxy.endpoint()}: {exc}"

    if proxy.tor:
        status["tor_note"] = (
            "Tor mode is enabled. VEYRON verifies the SOCKS endpoint is reachable and that "
            "requests are sent through it. Tor does not guarantee anonymity, and this check "
            "does not test for DNS, IPv6, or WebRTC-style leaks."
        )
    return status


def probe_proxy_route(
    proxy: ProxyConfig,
    url: str,
    *,
    timeout: float = 15.0,
    verify_tls: bool = True,
    proxy_bypass_loopback: bool = True,
) -> dict[str, Any]:
    """Send one request through the proxy to confirm the route is used.

    The request is made by the shared client, so the observed outcome is the
    outcome of the same code path used by every scanner. ``via_proxy`` is
    reported from the client's own accounting, not guessed.
    """
    client = HttpClient(
        proxy=proxy,
        timeout=timeout,
        verify_tls=verify_tls,
        max_requests=1,
        proxy_bypass_loopback=proxy_bypass_loopback,
    )
    response = client.get(url, allow_redirects=False)
    return {
        "url": redact_url(url),
        "ok": response.ok,
        "status": response.status,
        "error": response.error,
        "error_kind": response.error_kind,
        "via_proxy": response.via_proxy,
        "elapsed_ms": response.elapsed_ms,
        "stats": client.stats.to_dict(),
        "direct_fallback_possible": False if proxy.configured else True,
    }
