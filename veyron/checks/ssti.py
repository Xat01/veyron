"""Server-side template injection (SSTI) arithmetic differential.

Only inert arithmetic expressions are evaluated (``7*7``).  No template
objects, file reads, shell commands, or sandbox escapes are attempted.  The
check is confined to CONTROLLED_VALIDATION/LAB_EXPLOIT because template
evaluation is a vulnerability-specific payload.
"""

from __future__ import annotations

import secrets

from ..assessment import PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT
from ..net.client import redact_url
from ..validation import CLASS_INJECTION, ValidationEvidence
from .base import CheckContext, CheckFinding, finalize
from .xss import mutate_query, query_parameters

PAYLOADS = ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>")


def check_ssti(ctx: CheckContext, urls: list[str]) -> list[CheckFinding]:
    if ctx.profile not in {PROFILE_CONTROLLED_VALIDATION, PROFILE_LAB_EXPLOIT}:
        return []
    findings: list[CheckFinding] = []
    for url in urls:
        params = query_parameters(url)
        if not params:
            continue
        for name in params:
            for payload in PAYLOADS:
                token = secrets.token_hex(4)
                marker = f"49vyn{token}"
                probe_value = payload + marker
                probe_url = mutate_query(url, name, probe_value)
                response = ctx.get(probe_url)
                body = response.text(limit=400_000)
                if marker not in body:
                    continue
                repeat = ctx.get(probe_url)
                repeated = marker in repeat.text(limit=400_000)
                observed = (
                    "Template expression "
                    f"{payload!r} was evaluated server-side: the response contained "
                    f"the arithmetic result marker {marker!r} (49)."
                )
                evidence = ValidationEvidence(
                    endpoint=probe_url,
                    method="GET",
                    request=f"GET {redact_url(probe_url)}",
                    response=body[:400],
                    response_headers=dict(response.headers),
                    status_code=response.status,
                    reproducible=repeated,
                    reproductions=2 if repeated else 1,
                    preconditions=(
                        "User input is interpolated into a server-side template "
                        "before rendering."
                    ),
                    expected="Template syntax is treated as literal data.",
                    observed=observed,
                    limitations=(
                        "Arithmetic evaluation proves template interpretation, not "
                        "sandbox escape or code execution. No files, commands or "
                        "internal objects were accessed."
                    ),
                    validation_method="response-differential",
                    environment=(
                        "Isolated/lab" if ctx.profile == PROFILE_LAB_EXPLOIT
                        else "Authorised test environment"
                    ),
                    independent_sources=["arithmetic-differential"],
                )
                findings.append(finalize(ctx, CheckFinding(
                    title=f"Server-side template injection indicator in {name!r}",
                    category="ssti",
                    severity="high",
                    confidence="high",
                    description=(
                        "A template expression supplied in a query parameter was "
                        "evaluated by the server and its arithmetic result rendered. "
                        "This indicates server-side template injection."
                    ),
                    endpoint=redact_url(probe_url),
                    evidence=observed,
                    remediation=(
                        "Render user data as template data, never as template source. "
                        "Use logic-less templates or a sandbox, and reject template "
                        "delimiters in user input as defence in depth."
                    ),
                    source="dast.ssti",
                ), evidence, severity="high"))
                break
    return findings
