"""Proxy configuration and diagnostics.

The proxy subsystem exists for legitimate privacy and research routing
(HTTP/HTTPS CONNECT proxies, SOCKS5 proxies, a locally operated Tor SOCKS
endpoint). It is a routing layer, not an authorisation mechanism: a proxy
never widens assessment scope and never makes unauthorised testing
permissible.

Credentials are treated as secrets: they are never logged, never printed,
and are masked in every display surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlsplit

SUPPORTED_PROXY_SCHEMES = ("http", "https", "socks5", "socks5h")
DEFAULT_PORTS = {"http": 8080, "https": 8443, "socks5": 1080, "socks5h": 1080}


class ProxyConfigError(ValueError):
    """Invalid proxy configuration supplied by the operator."""


@dataclass
class ProxyConfig:
    """Resolved proxy settings for the shared network layer."""

    enabled: bool = False
    scheme: str = "http"
    host: str = ""
    port: int = 0
    username: str = ""
    password: str = ""
    timeout_seconds: int = 15
    tor: bool = False
    label: str = ""

    # -- construction ---------------------------------------------------------

    @classmethod
    def from_url(cls, url: str, *, tor: bool = False, timeout_seconds: int = 15) -> "ProxyConfig":
        """Parse ``scheme://[user:pass@]host:port`` into a ProxyConfig."""
        if not url or not url.strip():
            raise ProxyConfigError("proxy URL must not be empty")
        parts = urlsplit(url.strip())
        scheme = (parts.scheme or "").lower()
        if scheme not in SUPPORTED_PROXY_SCHEMES:
            raise ProxyConfigError(
                f"unsupported proxy scheme '{scheme}' (supported: {', '.join(SUPPORTED_PROXY_SCHEMES)})"
            )
        if not parts.hostname:
            raise ProxyConfigError("proxy URL must include a host")
        try:
            port = parts.port or DEFAULT_PORTS[scheme]
        except ValueError as exc:  # invalid port literal
            raise ProxyConfigError(f"proxy URL has an invalid port: {exc}") from exc
        if not (1 <= port <= 65535):
            raise ProxyConfigError("proxy port must be between 1 and 65535")
        username = unquote(parts.username) if parts.username else ""
        password = unquote(parts.password) if parts.password else ""
        return cls(
            enabled=True,
            scheme=scheme,
            host=parts.hostname.lower(),
            port=port,
            username=username,
            password=password,
            timeout_seconds=timeout_seconds,
            tor=tor,
        )

    # -- state ----------------------------------------------------------------

    @property
    def configured(self) -> bool:
        """True when the proxy is enabled and fully specified."""
        return bool(self.enabled and self.host and self.port > 0)

    @property
    def is_socks(self) -> bool:
        return self.scheme in ("socks5", "socks5h")

    @property
    def has_credentials(self) -> bool:
        return bool(self.username)

    def endpoint(self) -> str:
        """Credential-free endpoint, safe to display and log."""
        return f"{self.scheme}://{self.host}:{self.port}"

    def url(self) -> str:
        """Full proxy URL *including* credentials — internal use only."""
        if self.username:
            return f"{self.scheme}://{self.username}:{self.password}@{self.host}:{self.port}"
        return self.endpoint()

    def masked(self) -> dict[str, Any]:
        """Display-safe representation."""
        return {
            "enabled": self.enabled,
            "configured": self.configured,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "username": "***" if self.username else "",
            "password": "***" if self.password else "",
            "has_credentials": self.has_credentials,
            "tor": self.tor,
            "label": self.label,
            "timeout_seconds": self.timeout_seconds,
            "endpoint": self.endpoint() if self.host else "",
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialisable form used for config files (contains credentials)."""
        return {
            "enabled": self.enabled,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "timeout_seconds": self.timeout_seconds,
            "tor": self.tor,
            "label": self.label,
        }
