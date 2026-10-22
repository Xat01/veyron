# Feature report: evidence-driven validation engine

## A. Summary

Added `veyron/validation.py`, the component that decides whether a *detected*
weakness is a *confirmed* one. Detection and confirmation are now deliberately
separate: a scanner signature, a reflected marker, or an AI opinion is never
enough on its own. Each vulnerability class declares the evidence it requires,
and `evaluate()` applies those requirements deterministically, returning an
outcome that explains *why* confirmation was or was not possible.

## B. Original problem

The initial design had a single `validation_status` string that mixed three
different ideas: (1) it exists, (2) it is reproducible, (3) it is exploitable.
Nothing forced a finding to earn `VALIDATED` with concrete evidence, and there
was no vocabulary for "we tried but were not permitted to confirm this" or "the
evidence is incomplete".

The requirement was that confirmation must be **evidence-driven and
falsifiable** — the same inputs must always produce the same verdict, and every
non-confirmation must state what was missing.

## C. Design

### Findings carry evidence, not opinions

`ValidationEvidence` is a dataclass of *observed facts*: endpoint, method,
status code, sanitised request/response excerpts, whether a differential was
observed, how many independent reproductions were obtained, precondition notes,
and — for specific classes — a control-identity comparison or an observed
call-back. It never contacts a target; the caller passes only what it actually
observed.

### Each class declares its requirement

A `Requirement` per class states the allowed validation methods and which
evidence is mandatory (observation, reproduction, control identity, callback),
plus whether the class can be validated under the passive profile:

* **Injection** (XSS/SQLi/SSTI/command/path/deser) — needs an observed
  differential or reflected marker, plus two independent reproductions.
* **Access control** — needs a low-privilege vs higher-privilege identity
  comparison, plus reproduction.
* **SSRF** — needs an observed call-back to operator-controlled infrastructure,
  plus reproduction.
* **File handling** — needs a harmless-file canary or differential, plus
  reproduction.
* **Auth/session** and **configuration** — may validate under `PASSIVE` from a
  direct observation (e.g. a missing `Secure` flag).
* **Dependency** — can **never** be promoted to `VALIDATED` by version alone.
  Advisory correlation is `ANALYSED` at most: runtime reachability of the
  vulnerable path is a separate question that a version match does not answer.

### Deterministic verdicts

`evaluate()` returns a `ValidationOutcome`:

* `VALIDATION_NOT_PERMITTED` — active validation was not authorised.
* `BLOCKED_BY_SCOPE` — the endpoint is outside the declared scope.
* `INCONCLUSIVE` — evidence is incomplete; `missing` lists exactly what is
  needed.
* `ANALYSED` — correlated but not exploitable (dependency advisories).
* `VALIDATED` — requirement met with concrete, reproducible evidence.

### Evidence is sanitised before it is stored

`sanitize_excerpt()` redacts `Authorization`/`Cookie` headers, bearer tokens and
`key=value` secrets from excerpts unconditionally — even when the scanner did
not classify them as secrets. `ValidationEvidence.sanitized(retention)` honours
the operator's retention mode (`none`/`metadata`/`redacted`/`full`) and never
emits credentials.

## D. Changed files

* `veyron/validation.py` (new) — `ValidationEvidence`, `evaluate()`,
  `apply_outcome()`, `correlate_confidence()`, `Requirement`/`REQUIREMENTS`,
  `sanitize_excerpt()`.
* `veyron/constants.py` — added `BLOCKED_BY_SCOPE`,
  `VALIDATION_NOT_PERMITTED`, `REQUIRES_MANUAL_REVIEW` states.
* `veyron/finding.py` — legal `FINDING_STATES` transitions, `validation_evidence`
  field, professional report fields, and `correlate_confidence()` to lower
  confidence when evidence is weak.
* `tests/test_validation.py` (new) — per-class requirement enforcement, passive
  gating, dependency never-promotes, excerpt redaction, retention modes.

## E. Verification

`tests/test_validation.py` asserts, among others: an injection finding with a
differential and two reproductions validates; the same finding with one
reproduction is `INCONCLUSIVE` and the `missing` list names the second
reproduction; an access-control finding without a control identity is
`INCONCLUSIVE`; an SSRF finding without an observed call-back is `INCONCLUSIVE`;
a dependency advisory is `ANALYSED` even with a perfect version match; and
credentials never survive `sanitize_excerpt()`.

## F. Limitations and follow-up

* The engine classifies by a normalised class key; a caller that passes a
  genuinely unknown category gets a conservative requirement rather than a
  silent pass.
* Automatic *collection* of evidence is the checks' job (report 006); the engine
  only judges what it is given. Keeping these separate is what makes the engine
  testable without a target.
