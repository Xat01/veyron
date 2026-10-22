# Feature report: modular, profile-gated web checks

## A. Summary

Added `veyron/checks/`, a package of vulnerability-class checks that are
independently testable, honest about what they observed, and gated by the
assessment profile. Each check either produces a finding backed by concrete
evidence or produces nothing. A finding is never written from a hunch: it is
written because a marker was observed, a differential appeared, or a call-back
arrived.

## B. Original problem

The safe-active website profile could crawl and analyse read-only HTML, but it
had no vocabulary for class-specific validation — XSS, injection, SSRF, broken
access control. Adding them ad-hoc inside `dast.py` would have produced an
unmaintainable monolith and encouraged "detect and shout" behaviour, which is
exactly what the evidence-driven requirement forbids.

## C. Design

### A shared context, a shared finding shape

`CheckContext` carries the shared `HttpClient`, the `AssessmentSpec`, an
assessment-level `consume()`/`stop()` budget hook, and an optional
`CallbackVerifier`. `ctx.get()` refuses to send a request when the budget is
exhausted or the emergency stop file is present — so no check can outrun the
budget, and none needs its own accounting. `CheckFinding` is the one shape the
DAST report and the `Finding` model both speak.

### Checks are gated, not just bounded

* `xss`, `sqli`, `ssti`, `access_control` run only when the profile permits
  sending payloads (`SAFE_ACTIVE` and above).
* `ssrf` runs only under `CONTROLLED_VALIDATION` or `LAB_EXPLOIT`, and only when
  a callback verifier is present.
* Every payload inserted into a parameter is generated locally from a random
  token; nothing is fetched from a wordlist server.

### Honest findings

Each check records *expected* vs *observed* behaviour and a validation method.
None of them set `VALIDATED` themselves for an actively-probed class — they emit
`CheckFinding`s whose evidence is then judged by the validation engine (report
006). A reflected marker alone is `DETECTED`, not `VALIDATED`.

### SSRF uses only operator-controlled callbacks

The SSRF check inserts only the operator's callback URL — never cloud-metadata
addresses, internal ranges, or third-party services — into parameters, and
confirms with two independent tokens. A finding exists only when the target
actually called back. VEYRON runs its own **loopback-only** listener
(`CallbackListener`) when no operator callback is configured, so SSRF validation
has a concrete signal without any external dependency.

The package exports:

```
xss.Check (reflected-marker), sqli (error-differential),
ssti (arithmetic-evaluation), path_traversal (resolved-path / error-differential),
ssrf (callback-observation), access_control (control-identity-comparison)
```

## D. Changed files

* `veyron/checks/base.py` (new) — `CheckContext`, `CheckFinding`,
  `CallbackVerifier` protocol, `finalize()`, stable `VYN-<hash>` finding ids.
* `veyron/checks/xss.py`, `sqli.py`, `ssti.py`, `path_traversal.py`, `ssrf.py`,
  `access_control.py` (new) — one class each.
* `veyron/checks/callback.py` (new) — loopback `CallbackListener`.
* `veyron/checks/__init__.py` (new) — `run_checks(ctx, urls)`.
* `veyron/dast.py` — profile-gated invocation, one shared client per run, and
  the callback lifecycle (start listener, run checks, stop listener in a
  `finally`).
* `tests/test_webchecks.py` (new) — per-check behaviour against a local
  loopback server.

## E. Verification

`tests/test_webchecks.py` runs each check against a locally-started loopback
server only. It asserts that: a reflected marker produces a finding while the
same request without reflection does not; the SQLi check requires an observable
error differential; the SSTI check requires the arithmetic result to appear;
SSRF produces a finding only after a genuine call-back with the token; a
resolved-path response yields a traversal finding while an opaque echo does not;
and access-control produces a finding only with a real identity comparison. No
test contacts a third-party host.

## F. Limitations and follow-up

* Command injection, deserialisation, file-handling and auth/session checks
  are recognised by the validation engine's class map but do not yet have
  dedicated collectors; they will be added as separate check modules.
* The checks share `dast.py`'s crawl output as their URL set; deeper crawling
  for parameter discovery is future work.
