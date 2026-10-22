"""Assessment scope: host/port/path authorisation and destination-address
validation.

Scope is a technical control, not a disclaimer. Every outbound request made
by VEYRON passes through :class:`Scope` before a socket is opened, and every
redirect hop is re-checked against the same scope.

Two distinct mechanisms are implemented:

1. **Host/port/path authorisation** — the operator states which hosts (and
   optionally ports and paths) may be contacted. A request outside that set is
   refused.

2. **Destination-address validation** — the hostname is resolved *before* the
   connection is made and every resolved address is checked. This is the
   defence against DNS rebinding and against a hostname that resolves into a
   link-local / cloud-metadata address. VEYRON additionally connects to the
   validated address rather than re-resolving the name, so a second
   resolution by the resolver cannot substitute a different address.

Limitation (documented, not hidden): address validation reduces but does not
mathematically eliminate rebinding risk on hosts that are explicitly
allow-listed, because the operator has already authorised that name.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit

# Special-purpose ranges that are refused by default. Cloud metadata
# (169.254.169.254) lives in 169.254.0.0/16 and is the classic SSRF target.
DEFAULT_BLOCKED_CIDRS: tuple[str, ...] = (
    "0.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)

# Private / loopback ranges — flagged, not blocked, because assessing local
# development services is a first-class use case.
PRIVATE_CIDRS: tuple[str, ...] = (
    "10.0.0.0/8",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)


@dataclass(frozen=True)
class ScopeDecision:
    """Outcome of a scope check."""

    allowed: bool
    reason: str = ""

    def __bool__(self) -> bool:  # pragma: no cover - trivial
        return self.allowed


ALLOW = ScopeDecision(True, "in scope")


def _host_matches(pattern: str, host: str) -> bool:
    """Match a host against a scope pattern.

    Supported forms:
      - ``example.com``      exact host
      - ``*.example.com``    any subdomain of ``example.com``
      - ``.example.com``     treated as ``*.example.com``
    """
    pattern = pattern.strip().lower().rstrip(".")
    host = host.lower().rstrip(".")
    if not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith("." + suffix)
    if pattern.startswith("."):
        suffix = pattern[1:]
        return host.endswith("." + suffix)
    return pattern == host


def _split_host_port(entry: str) -> tuple[str, int | None]:
    """Split ``host`` / ``host:port`` (IPv6 literals must be bracketed)."""
    entry = entry.strip().lower()
    if not entry:
        return "", None
    if entry.startswith("["):
        host, _, rest = entry.partition("]")
        host = host[1:]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return host, None
        return host, None
    if entry.count(":") == 1:
        host, _, port = entry.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, None
    return entry, None


@dataclass
class Scope:
    """Authorisation rules applied to every outbound request."""

    allowed_hosts: list[str] = field(default_factory=list)
    excluded_hosts: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allowed_paths: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    allow_private_addresses: bool = True
    allowed_cidrs: list[str] = field(default_factory=list)
    blocked_cidrs: list[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_CIDRS))
    resolve_dns: bool = True
    require_authorization: bool = False

    # -- construction ---------------------------------------------------------

    @classmethod
    def from_allowlist(
        cls,
        entries: Iterable[str],
        *,
        allow_any_port: bool = False,
        **kwargs: object,
    ) -> "Scope":
        """Build a scope from a host allowlist.

        ``allow_any_port=False`` (default) keeps the historical VEYRON rule:
        a bare host entry only covers the scheme's default port (80/443).
        """
        allowed_hosts: list[str] = []
        for entry in entries:
            raw = entry.strip().lower()
            if not raw:
                continue
            host, port = _split_host_port(raw)
            if not host:
                continue
            if port is not None:
                allowed_hosts.append(f"{host}:{port}")
            elif allow_any_port:
                allowed_hosts.append(host)
            else:
                # Historical VEYRON rule: a bare host covers only the scheme
                # default ports (80/443), never an arbitrary port.
                allowed_hosts.append(f"{host}:80")
                allowed_hosts.append(f"{host}:443")
        # NOTE: allowed_ports is deliberately left empty. Port restriction is
        # expressed per host entry above; populating the global list would
        # restrict unrelated hosts to the union of every entry's ports.
        return cls(allowed_hosts=allowed_hosts, **kwargs)  # type: ignore[arg-type]

    # -- checks ---------------------------------------------------------------

    def host_allowed(self, host: str, port: int) -> bool:
        """True when ``host:port`` matches an allow-list entry."""
        if not self.allowed_hosts:
            return False
        for pattern in self.excluded_hosts:
            p_host, _ = _split_host_port(pattern)
            if _host_matches(p_host, host):
                return False
        for pattern in self.allowed_hosts:
            p_host, p_port = _split_host_port(pattern)
            if not _host_matches(p_host, host):
                continue
            if p_port is None or p_port == port:
                return True
        return False

    def path_allowed(self, path: str) -> bool:
        # Normalise before prefix matching so ``/allowed/../admin`` and
        # encoded traversal cannot satisfy a permitted-path rule.  If the raw
        # path contains traversal or encoded separators we refuse it outright:
        # the server's normalisation may differ from ours.
        raw = path or "/"
        lowered = raw.lower()
        if ".." in lowered or "%2e" in lowered or "%2f" in lowered or "%5c" in lowered or "\\" in raw:
            return False
        normalised = "/" + "/".join(
            part for part in raw.split("/") if part not in {"", "."}
        )
        for excluded in self.excluded_paths:
            if normalised.startswith(excluded):
                return False
        if not self.allowed_paths:
            return True
        return any(normalised.startswith(prefix) for prefix in self.allowed_paths)

    def check_url(self, url: str) -> ScopeDecision:
        """Check a URL against scheme, host, port and path rules."""
        parts = urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in self.allowed_schemes:
            return ScopeDecision(False, f"scheme '{scheme}' is not permitted")
        host = (parts.hostname or "").lower()
        if not host:
            return ScopeDecision(False, "URL has no host")
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError:
            return ScopeDecision(False, "URL has an invalid port")
        if self.allowed_ports and port not in self.allowed_ports:
            return ScopeDecision(False, f"port {port} is not in the permitted port list")
        if not self.host_allowed(host, port):
            return ScopeDecision(False, f"host '{host}:{port}' is not in the authorised scope")
        if not self.path_allowed(parts.path or "/"):
            return ScopeDecision(False, f"path '{parts.path}' is not in the permitted path list")
        return ALLOW

    def check_redirect(self, current_url: str, target_url: str) -> ScopeDecision:
        """Validate a redirect hop.

        A redirect may never widen the scope: the target must independently
        satisfy every rule the original request had to satisfy.
        """
        decision = self.check_url(target_url)
        if not decision.allowed:
            return decision
        current = urlsplit(current_url)
        target = urlsplit(target_url)
        if (current.hostname or "").lower() != (target.hostname or "").lower():
            return ScopeDecision(False, "cross-host redirect to a host outside the authorised scope")
        return ALLOW

    # -- address validation ---------------------------------------------------

    def resolve(self, host: str, port: int) -> list[str]:
        """Resolve a hostname to a list of literal addresses."""
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses: list[str] = []
        for info in infos:
            sockaddr = info[4]
            addr = sockaddr[0]
            if addr not in addresses:
                addresses.append(addr)
        return addresses

    def check_addresses(self, addresses: Iterable[str]) -> ScopeDecision:
        """Validate resolved destination addresses.

        ``allowed_cidrs`` overrides the block list — an operator who
        explicitly allows a range (for example a private lab network) keeps
        working, while cloud-metadata and unspecified addresses stay blocked.
        """
        allowed_networks = []
        for cidr in self.allowed_cidrs:
            try:
                allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        blocked_networks = []
        for cidr in self.blocked_cidrs:
            try:
                blocked_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue

        for raw in addresses:
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                return ScopeDecision(False, f"resolved address '{raw}' is not a valid IP")
            if any(addr in net for net in allowed_networks):
                continue
            if any(addr in net for net in blocked_networks):
                return ScopeDecision(False, f"resolved address {addr} is in a blocked range")
            if not self.allow_private_addresses and any(
                addr in ipaddress.ip_network(cidr, strict=False) for cidr in PRIVATE_CIDRS
            ):
                return ScopeDecision(False, f"resolved address {addr} is a private/loopback address")
        return ALLOW

    def is_private_address(self, address: str) -> bool:
        """True when the address is private/loopback (diagnostic helper)."""
        try:
            addr = ipaddress.ip_address(address)
        except ValueError:
            return False
        for cidr in PRIVATE_CIDRS:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if addr in net:
                return True
        return False
