"""Command-injection checks (non-destructive markers only).

We never run a destructive command, never spawn a reverse shell, and never
write to the target.  The check supplies a benign marker and a shell-meta
variant, then looks for two pieces of evidence:

* a *computed* marker echoed back (the marker was evaluated by a shell), or
* a distinct error differential (a shell error absent from the baseline).

Output evaluation is the strongest signal: an inert string that becomes a
computed value only when a shell evaluates it.  An error differential is
corroboration.  Neither is proof of remote code execution on its own; the
finding therefore stays ``DETECTED``/``CORROBORATED`` until the validation
engine can promote it under ``CONTROLLED_VALIDATION`` with reproduction.
"""

from __future__ import annotations

import secrets

from ..net.client import redact_url
from ..validation import ValidationEvidence
from .base import CheckContext, CheckFinding, finalize
from .xss import mutate_query, query_parameters

# Non-destructive: the marker is an arithmetic expression the shell folds to a
# fixed number.  Nothing is executed beyond the evaluation of a constant.
_MARKER_A = "vyncmdi{token}"
_NUM_A = "6389"  # 4241+2148, folded by a POSIX shell


def _is_error(status: int | None) -> bool:
    return status is not None and 500 <= status < 600


def check_command_injection(ctx: CheckContext, urls: list[str]) -> list[CheckFinding]:
    if not ctx.allowed():
        return []
    findings: list[CheckFinding] = []
    for url in urls:
        params = query_parameters(url)
        if not params:
            continue
        for name in params:
            token = secrets.token_hex(5)
            marker = _MARKER_A.format(token=token)
            # $((4241+2148)) folds to 6389 in sh/bash; stays literal otherwise.
            payload = f";echo {marker} $((4241+2148));"
            baseline = ctx.get(mutate_query(url, name, "vyncmdi_baseline"))
            first = ctx.get(mutate_query(url, name, payload))
            if first.status is None:
                continue

            body = first.text(limit=400_000)
            # Evidence 1: the shell folded the arithmetic next to our marker.
            evaluated = marker in body and _NUM_A in body
            # Evidence 2: a distinct error differential versus the baseline.
            differential = (
                baseline.status is not None
                and baseline.status != first.status
                and _is_error(first.status)
            )
            if not (evaluated or differential):
                continue

            # Independent second reproduction with a fresh token/expression.
            token2 = secrets.token_hex(5)
            marker2 = _MARKER_A.format(token=token2)
            payload2 = f";echo {marker2} $((1700+31));"
            second = ctx.get(mutate_query(url, name, payload2))
            second_body = second.text(limit=400_000) if second.status is not None else ""
            second_evaluated = marker2 in second_body and "1731" in second_body
            reproductions = 1 + int(
                second_evaluated
                or (baseline.status is not None and second.status is not None
                    and baseline.status != second.status and _is_error(second.status))
            )

            observed = (
                f"command output: shell folded an arithmetic expression next to marker "
                f"{marker!r} (returned {_NUM_A})"
                if evaluated
                else f"different response: status changed to {first.status} "
                     f"for a shell-meta value"
            )
            evidence = ValidationEvidence(
                endpoint=url,
                method="GET",
                request=f"GET {redact_url(url)} [{name}=<non-destructive shell marker>]",
                response=body[:500],
                status_code=first.status,
                reproducible=reproductions >= 2,
                reproductions=reproductions,
                preconditions="Target passes the parameter to a shell or command interpreter.",
                expected=(
                    "The value is treated as an opaque string: the arithmetic expression is "
                    "never evaluated and no shell error appears."
                ),
                observed=observed,
                limitations=(
                    "A folded expression or error differential is necessary evidence, not "
                    "proof of remote code execution; no destructive command was run and no "
                    "data was read or written."
                ),
                validation_method="response-differential",
                environment="Remote HTTP target (authorised scope)",
                independent_sources=["command-output", "error-differential"],
            )
            findings.append(finalize(ctx, CheckFinding(
                title=f"Potential command injection in parameter {name!r}",
                category="command-injection",
                severity="critical",
                confidence="medium",
                description=(
                    f"The {name!r} parameter appears to reach a command interpreter: a "
                    "non-destructive shell marker was evaluated or produced a distinct error."
                ),
                endpoint=redact_url(url),
                evidence=observed,
                remediation=(
                    "Never build shell commands from user input. Use argument arrays or a "
                    "parameterised API, and allowlist the accepted values."
                ),
                source="dast.command_injection",
            ), evidence, severity="critical"))
    return findings
