"""Path-traversal checks (harmless marker only).

We never attempt to read a real file and we never exfiltrate content.  The
check inserts a harmless traversal marker into parameters and looks for two
pieces of evidence that a path is being resolved unsafely:

* the marker being reflected back as part of a resolved path, or
* a *distinct* error differential (the response to the traversal marker differs
  from the response to the baseline value).

That is necessary evidence for a traversal weakness, not proof of file access.
The finding therefore stays ``DETECTED``/``INCONCLUSIVE`` until the validation
engine can promote it under ``CONTROLLED_VALIDATION`` with independent
reproduction.
"""

from __future__ import annotations

import secrets

from ..net.client import redact_url
from ..validation import ValidationEvidence
from .base import CheckContext, CheckFinding, finalize
from .xss import mutate_query, query_parameters

# Traversal-shaped but harmless payloads.  ``veyron_probe_<token>`` is not a
# real file: if a server resolves it, that is the signal we are looking for.
_TRAVERSAL = "../../../../etc/veyron_probe_{token}"
_WINDOWS_TRAVERSAL = "..\\..\\..\\..\\windows\\veyron_probe_{token}"


def _is_error(status: int | None) -> bool:
    return status is not None and 500 <= status < 600


def check_path_traversal(ctx: CheckContext, urls: list[str]) -> list[CheckFinding]:
    if not ctx.allowed():
        return []
    findings: list[CheckFinding] = []
    for url in urls:
        params = query_parameters(url)
        if not params:
            continue
        for name in params:
            token = secrets.token_hex(6)
            probe = _TRAVERSAL.format(token=token)
            baseline = ctx.get(mutate_query(url, name, "veyron_baseline"))
            first = ctx.get(mutate_query(url, name, probe))
            if first.status is None:
                continue

            marker = f"veyron_probe_{token}"
            body = first.text(limit=400_000)
            # Evidence 1: the traversal marker reflects *as a resolved path* —
            # the "../" segments were normalised away around the marker.  A
            # plain echo that still contains the literal ".." is not evidence.
            marker_index = body.find(marker)
            resolved = marker_index >= 0 and ".." not in body[max(0, marker_index - 40):marker_index]
            # Evidence 2: a distinct error differential versus the baseline.
            differential = (
                baseline.status is not None
                and baseline.status != first.status
                and _is_error(first.status)
            )
            if not (resolved or differential):
                continue

            # Independent second reproduction before we claim reproduction.
            token2 = secrets.token_hex(6)
            probe2 = _WINDOWS_TRAVERSAL.format(token=token2)
            second = ctx.get(mutate_query(url, name, probe2))
            second_body = second.text(limit=400_000) if second.status is not None else ""
            marker2 = f"veyron_probe_{token2}"
            marker2_index = second_body.find(marker2)
            second_resolved = marker2_index >= 0 and ".." not in second_body[
                max(0, marker2_index - 40):marker2_index
            ]
            second_reproduced = second_resolved or (
                baseline.status is not None and second.status is not None
                and baseline.status != second.status and _is_error(second.status)
            )
            reproductions = 1 + int(second_reproduced)

            observed = (
                f"resolved path: traversal marker {marker!r} returned with the "
                "'../' segments normalised away"
                if resolved
                else f"different response: status changed to {first.status} "
                     f"for a traversal-shaped value"
            )
            evidence = ValidationEvidence(
                endpoint=url,
                method="GET",
                request=f"GET {redact_url(url)} [{name}=<traversal marker>]",
                response=body[:500],
                status_code=first.status,
                reproducible=reproductions >= 2,
                reproductions=reproductions,
                preconditions="Target accepts query parameters and performs a path lookup.",
                expected=(
                    "The value is treated as an opaque string: no path resolution and no "
                    "differential error."
                ),
                observed=observed,
                limitations=(
                    "A reflected marker or error differential is necessary evidence, not "
                    "proof of file disclosure; no file content was retrieved and no "
                    "sensitive path was targeted."
                ),
                validation_method="response-differential",
                environment="Remote HTTP target (authorised scope)",
                independent_sources=["traversal-marker", "error-differential"],
            )
            findings.append(finalize(ctx, CheckFinding(
                title=f"Potential path traversal in parameter {name!r}",
                category="path-traversal",
                severity="high",
                confidence="medium",
                description=(
                    f"The {name!r} parameter appears to resolve a path-like value: the "
                    "response reflected the traversal marker or returned a distinct error."
                ),
                endpoint=redact_url(url),
                evidence=observed,
                remediation=(
                    "Canonicalise user-supplied paths and reject any value that escapes the "
                    "intended base directory; prefer lookups by opaque identifier."
                ),
                source="dast.path_traversal",
            ), evidence, severity="high"))
    return findings
