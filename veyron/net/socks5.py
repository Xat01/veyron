"""Minimal SOCKS5 client (RFC 1928 / RFC 1929) — standard library only.

VEYRON needs SOCKS5 support for Tor and for generic SOCKS proxies. The
standard library ships no SOCKS client, and adding a third-party dependency
would break VEYRON's "stdlib only" promise, so a minimal CONNECT-only client
is implemented here.

Deliberate limitations (documented rather than hidden):

* Only the CONNECT command is supported — no UDP ASSOCIATE, no BIND.
* The destination is always supplied by the caller as an already-resolved
  and scope-validated IP literal, so DNS resolution never happens on the
  proxy side. This removes proxy-side DNS rebinding and proxy-side DNS
  leakage for VEYRON's own traffic.
* TLS is layered on top by the caller; this module is transport-agnostic.
"""

from __future__ import annotations

import ipaddress
import socket
import struct

SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_UNACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REPLY_MESSAGES = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


class Socks5Error(Exception):
    """SOCKS5 negotiation or tunnel failure."""

    def __init__(self, message: str, reply_code: int | None = None):
        super().__init__(message)
        self.reply_code = reply_code


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly ``count`` bytes or raise."""
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise Socks5Error("proxy closed the connection during negotiation")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _encode_address(host: str) -> tuple[int, bytes]:
    """Encode a destination host as a SOCKS5 address tuple."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raw = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode("utf-8")
        if len(raw) > 255:
            raise Socks5Error("destination hostname is too long") from None
        return ATYP_DOMAIN, bytes([len(raw)]) + raw
    if ip.version == 4:
        return ATYP_IPV4, ip.packed
    return ATYP_IPV6, ip.packed


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    *,
    timeout: float = 15.0,
    username: str | None = None,
    password: str | None = None,
) -> socket.socket:
    """Open a SOCKS5 tunnel to ``dest_host:dest_port``.

    Returns a connected socket with the handshake completed. The caller owns
    the socket and must close it (or hand it to an HTTP connection object).
    """
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except OSError as exc:
        raise Socks5Error(f"cannot reach SOCKS proxy {proxy_host}:{proxy_port}: {exc}") from exc

    try:
        sock.settimeout(timeout)
        _greet(sock, username, password)
        _request_connect(sock, dest_host, dest_port)
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise

    sock.settimeout(timeout)
    return sock


def _greet(sock: socket.socket, username: str | None, password: str | None) -> None:
    methods = [AUTH_NONE]
    if username:
        methods.append(AUTH_USERPASS)
    sock.sendall(bytes([SOCKS_VERSION, len(methods), *methods]))

    resp = _recv_exact(sock, 2)
    if resp[0] != SOCKS_VERSION:
        raise Socks5Error(f"unexpected SOCKS version 0x{resp[0]:02x} from proxy")
    method = resp[1]
    if method == AUTH_UNACCEPTABLE:
        raise Socks5Error("proxy rejected all offered authentication methods")
    if method == AUTH_USERPASS:
        if not username:
            raise Socks5Error("proxy requires username/password authentication but no credentials are configured")
        user = username.encode("utf-8")
        secret = (password or "").encode("utf-8")
        sock.sendall(bytes([0x01, len(user)]) + user + bytes([len(secret)]) + secret)
        auth = _recv_exact(sock, 2)
        if auth[0] != 0x01 or auth[1] != 0x00:
            raise Socks5Error("SOCKS5 proxy authentication failed")
    elif method != AUTH_NONE:
        raise Socks5Error(f"proxy selected unsupported authentication method 0x{method:02x}")


def _request_connect(sock: socket.socket, dest_host: str, dest_port: int) -> None:
    atyp, addr = _encode_address(dest_host)
    sock.sendall(bytes([SOCKS_VERSION, CMD_CONNECT, 0x00, atyp]) + addr + struct.pack("!H", dest_port))

    head = _recv_exact(sock, 4)
    if head[0] != SOCKS_VERSION:
        raise Socks5Error(f"unexpected SOCKS version 0x{head[0]:02x} in reply")
    reply = head[1]
    if reply != 0x00:
        message = REPLY_MESSAGES.get(reply, "unknown SOCKS5 failure")
        raise Socks5Error(f"SOCKS5 CONNECT failed: {message} (code {reply})", reply_code=reply)

    bound_atyp = head[3]
    if bound_atyp == ATYP_IPV4:
        _recv_exact(sock, 4 + 2)
    elif bound_atyp == ATYP_IPV6:
        _recv_exact(sock, 16 + 2)
    elif bound_atyp == ATYP_DOMAIN:
        length = _recv_exact(sock, 1)[0]
        _recv_exact(sock, length + 2)
    else:
        raise Socks5Error(f"proxy returned unsupported bound address type 0x{bound_atyp:02x}")
