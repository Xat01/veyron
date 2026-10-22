"""Authorization model and assessment profiles.

Scope is a technical control, not a promise in a README.  This module turns an
operator's explicit statement of authorisation into the :class:`Scope` that
the shared HTTP client enforces, and refuses to promote a profile beyond what
that statement supports.

Profiles
--------
PASSIVE
    Ordinary, low-impact requests only (default). No vulnerability-specific
    payloads are sent.

SAFE_ACTIVE
    Bounded, non-destructive checks against explicitly authorised targets.
    Requires a scope and a separate execution confirmation.

CONTROLLED_VALIDATION
    Safe validation of selected findings (differential probes, markers, test
    identities) against authorised test environments.  Requires evidence
    requirements to be declared for the vulnerability class.

LAB_EXPLOIT
    Reproduces findings only in an isolated/lab environment.  The caller must
    assert ``lab_environment``; VEYRON never treats a public host as a lab.

Nothing here infers authorisation from a hostname being reachable.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .net.proxy import ProxyConfig
from .net.scope import Scope

PROFILE_PASSIVE = "PASSIVE"
PROFILE_SAFE_ACTIVE = "SAFE_ACTIVE"
PROFILE_CONTROLLED_VALIDATION = "CONTROLLED_VALIDATION"
PROFILE_LAB_EXPLOIT = "LAB_EXPLOIT"

PROFILES = (
    PROFILE_PASSIVE,
    PROFILE_SAFE_ACTIVE,
    PROFILE_CONTROLLED_VALIDATION,
    PROFILE_LAB_EXPLOIT,
)

# Existing DAST names remain accepted so old configs and the CLI keep working.
PROFILE_ALIASES = {
    "passive": PROFILE_PASSIVE,
    "safe-active": PROFILE_SAFE_ACTIVE,
    "safe_active": PROFILE_SAFE_ACTIVE,
    "controlled-validation": PROFILE_CONTROLLED_VALIDATION,
    "controlled_validation": PROFILE_CONTROLLED_VALIDATION,
    "lab-exploit": PROFILE_LAB_EXPLOIT,
    "lab_exploit": PROFILE_LAB_EXPLOIT,
}

EVIDENCE_RETENTION = ("none", "metadata", "redacted", "full")


def normalize_profile(value: str | None) -> str:
    """Return a canonical profile name or raise ``ValueError``."""
    if not value:
        return PROFILE_PASSIVE
    raw = value.strip()
    canonical = PROFILE_ALIASES.get(raw.lower(), raw.upper())
    if canonical not in PROFILES:
        raise ValueError(
            f"unknown assessment profile {value!r}; choose one of {', '.join(PROFILES)}"
        )
    return canonical


@dataclass
class Identity:
    """An explicitly supplied test identity.

    ``headers`` may contain an Authorization or Cookie value.  They are never
    written to reports or logs; only the identity label and privilege level
    are retained.
    """

    name: str
    headers: dict[str, str] = field(default_factory=dict)
    privilege: str = "low"  # "none" | "low" | "high"

    def sanitized(self) -> dict[str, str]:
        return {"name": self.name, "privilege": self.privilege}


@dataclass
class AssessmentSpec:
    """Operator-declared authorisation and safety budget for one assessment."""

    profile: str = PROFILE_PASSIVE
    authorized_hosts: list[str] = field(default_factory=list)
    permitted_schemes: tuple[str, ...] = ("http", "https")
    permitted_ports: list[int] = field(default_factory=list)
    permitted_paths: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    max_requests: int = 100
    max_rate_per_second: float = 1.0
    connection_timeout_seconds: float = 10.0
    deadline_seconds: int = 600
    max_concurrency: int = 1
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    evidence_retention: str = "redacted"
    stop_file: str | None = None
    lab_environment: bool = False
    identities: list[Identity] = field(default_factory=list)
    callback_url: str | None = None
    # Explicit expected-access rules, e.g.
    # {"url": "https://app.test/admin", "allowed_privileges": ["high"]}.
    access_control_rules: list[dict[str, object]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.profile = normalize_profile(self.profile)
        self.permitted_schemes = tuple(s.lower() for s in self.permitted_schemes)

    # -- validation -----------------------------------------------------------

    def issues(self) -> list[str]:
        """Reasons this specification cannot authorise an active assessment."""
        problems: list[str] = []
        if not self.authorized_hosts:
            problems.append("no authorised hosts were declared")
        for host in self.authorized_hosts:
            if host.strip() in {"*", "*.*"} or host.strip().startswith("*"):
                problems.append(f"wildcard authorisation is not accepted: {host!r}")
            if any(ch in host for ch in "/?#@"):
                problems.append(f"authorised host must be host[:port], got {host!r}")
        if not self.permitted_schemes:
            problems.append("no permitted scheme")
        bad_schemes = set(self.permitted_schemes) - {"http", "https"}
        if bad_schemes:
            problems.append(f"unsupported scheme(s): {', '.join(sorted(bad_schemes))}")
        if any(p < 1 or p > 65535 for p in self.permitted_ports):
            problems.append("permitted port outside 1..65535")
        if self.max_requests < 1:
            problems.append("max_requests must be >= 1")
        if not 0 <= self.max_rate_per_second <= 1000:
            problems.append("max_rate_per_second must be between 0 and 1000")
        if self.connection_timeout_seconds <= 0:
            problems.append("connection timeout must be positive")
        if self.deadline_seconds < 1:
            problems.append("deadline must be >= 1 second")
        if self.max_concurrency < 1 or self.max_concurrency > 8:
            problems.append("max_concurrency must be between 1 and 8")
        if self.evidence_retention not in EVIDENCE_RETENTION:
            problems.append(f"unknown evidence retention mode {self.evidence_retention!r}")
        if self.profile == PROFILE_LAB_EXPLOIT and not self.lab_environment:
            problems.append(
                "LAB_EXPLOIT requires an explicitly declared isolated lab_environment"
            )
        if self.profile in {PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT}:
            if not self.authorized_hosts:
                problems.append("validation profile requires an authorised target")
        if self.callback_url:
            parts = urlsplit(self.callback_url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                problems.append("callback_url must be an http(s) URL")
            else:
                try:
                    addr = ipaddress.ip_address(parts.hostname)
                except ValueError:
                    addr = None
                # Callback infrastructure must be operator-controlled.  We
                # cannot prove ownership, but we can refuse obvious
                # cloud-metadata / link-local destinations.
                if addr and (addr.is_link_local or addr.is_multicast or addr.is_unspecified):
                    problems.append("callback_url must not target link-local infrastructure")
        if self.proxy.enabled and not self.proxy.configured:
            problems.append("proxy is enabled but has no valid host")
        for rule in self.access_control_rules:
            if not isinstance(rule, dict):
                problems.append("access_control_rules entries must be objects")
                continue
            url = str(rule.get("url", ""))
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                problems.append(f"access-control rule URL is not http(s): {url!r}")
            allowed = rule.get("allowed_privileges", [])
            if not isinstance(allowed, list) or not allowed:
                problems.append(f"access-control rule needs allowed_privileges: {url!r}")
        return problems

    def scope(self) -> Scope:
        """Build the enforced scope.  Raises ``ValueError`` if unauthorised."""
        problems = self.issues()
        if problems:
            raise ValueError("invalid assessment authorisation: " + "; ".join(problems))
        hosts: list[str] = []
        for entry in self.authorized_hosts:
            host, port = _split_host_port(entry)
            if port is not None:
                hosts.append(f"{host}:{port}")
            elif self.permitted_ports:
                hosts.extend(f"{host}:{port}" for port in self.permitted_ports)
            else:
                hosts.append(host)
        return Scope(
            allowed_hosts=hosts,
            excluded_hosts=list(self.exclusions),
            allowed_ports=list(self.permitted_ports),
            allowed_schemes=tuple(self.permitted_schemes),
            allowed_paths=list(self.permitted_paths),
            resolve_dns=True,
        )

    # -- capability gates -----------------------------------------------------

    def can_send_payloads(self) -> bool:
        return self.profile in {
            PROFILE_SAFE_ACTIVE,
            PROFILE_CONTROLLED_VALIDATION,
            PROFILE_LAB_EXPLOIT,
        }

    def can_validate(self) -> bool:
        return self.profile in {PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT}

    def authorize(self, *, execute: bool, confirmation: str | bool) -> tuple[bool, list[str]]:
        """Authorise active testing only with explicit confirmation and scope."""
        reasons: list[str] = []
        if not execute:
            reasons.append("execution was not requested (planning mode)")
        if not confirmation:
            reasons.append("explicit authorisation confirmation is required")
        reasons.extend(self.issues())
        return (not reasons, reasons)

    def stop_requested(self) -> bool:
        return bool(self.stop_file) and Path(self.stop_file).exists()

    def summary(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "authorized_hosts": list(self.authorized_hosts),
            "permitted_schemes": list(self.permitted_schemes),
            "permitted_ports": list(self.permitted_ports),
            "permitted_paths": list(self.permitted_paths),
            "exclusions": list(self.exclusions),
            "max_requests": self.max_requests,
            "max_rate_per_second": self.max_rate_per_second,
            "connection_timeout_seconds": self.connection_timeout_seconds,
            "deadline_seconds": self.deadline_seconds,
            "max_concurrency": self.max_concurrency,
            "proxy_configured": self.proxy.configured,
            "proxy_label": self.proxy.label or self.proxy.scheme,
            "evidence_retention": self.evidence_retention,
            "stop_file": self.stop_file,
            "lab_environment": self.lab_environment,
            "identities": [i.sanitized() for i in self.identities],
            "callback_configured": bool(self.callback_url),
            "access_control_rules": len(self.access_control_rules),
        }


def _split_host_port(entry: str) -> tuple[str, int | None]:
    entry = entry.strip().lower()
    if entry.startswith("["):
        host, _, rest = entry.partition("]")
        host = host[1:]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if entry.count(":") == 1:
        host, _, port = entry.partition(":")
        if port.isdigit():
            return host, int(port)
    return entry, None
