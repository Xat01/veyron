# Feature report: assessment profiles and the authorisation model

## A. Summary

Added an explicit assessment model (`veyron/assessment.py`) that turns "what am
I allowed to do to this target" from an implicit combination of CLI flags into
a single, inspectable object. The model defines four profiles, the evidence each
profile may collect, and the budget/identity/proxy/callback constraints that
bound a run. `AssessmentSpec` is now the single source of authorisation for the
website-assessment path; DAST derives an enforcement `Scope` from it, so
authorisation and scope can never drift apart.

## B. Original problem

Before this change, "authorised" meant "the host was in the allowlist and the
operator passed `--authorize`". That conflated two different questions:

* **Scope** — which hosts, ports, schemes and paths may be contacted.
* **Capability** — what *kind* of activity is permitted (reading a page,
  sending a probe, comparing two identities, exploiting a lab).

There was no way to say "read-only corroboration is fine but do not attempt to
exploit", and no place that recorded *why* a given action was allowed. The
requirement was to separate these concerns and make authorisation auditable.

## C. Design

### Four profiles

| Profile | Intent | May send payloads | May validate |
| --- | --- | --- | --- |
| `PASSIVE` | Read the target page and published resources only. | no | passive classes only |
| `SAFE_ACTIVE` | Same-origin crawl + read-only HTML/form analysis; bounded corroboration. | yes | no |
| `CONTROLLED_VALIDATION` | Differential/marker validation of specific classes. | yes | yes |
| `LAB_EXPLOIT` | Disposable lab only; strongest validation. | yes | yes |

Legacy strings (`passive`, `safe-active`) are accepted as aliases so existing
configuration and scripts keep working.

### One object, validated up front

`AssessmentSpec.validate()` returns a list of human-readable problems rather
than raising. A spec with problems is refused — VEYRON does not silently
downgrade to a weaker profile. Notable rules:

* `LAB_EXPLOIT` requires an explicitly declared `lab_environment`; there is no
  flag that "assumes" a lab.
* `CONTROLLED_VALIDATION` and `LAB_EXPLOIT` require at least one authorised
  host.
* `callback_url`, when present, must be http(s) and must not target link-local
  infrastructure (the same range used by cloud metadata endpoints).

### Scope derived mechanically

`AssessmentSpec.to_scope()` builds the `Scope` used by the shared HTTP client
directly from the spec's `authorized_hosts`, `permitted_ports`,
`permitted_schemes`, `permitted_paths` and `exclusions`. Because the scope is
derived, it is impossible to configure an authorisation and then enforce a
different one.

### Capability gates

`can_send_payloads()` and `can_validate()` are the only things the modular
checks consult for "am I allowed to do this". They are derived from the profile,
not from scattered booleans.

## D. Changed files

* `veyron/assessment.py` (new) — profiles, `AssessmentSpec`, `Identity`,
  `validate()`, `to_scope()`, `authorize()`, `summary()`.
* `veyron/dast.py` — builds the spec from `DASTConfig`, refuses on
  `spec_problems`, derives the request `Scope` from the spec, and records the
  sanitised spec in `DASTResult.authorization`.
* `veyron/config.py` — DAST extended fields (`permitted_paths`, `exclusions`,
  `evidence_retention`, `stop_file`, `lab_environment`, `callback_url`,
  `access_control_rules`, `identities`) with JSON and `VEYRON_*` env support.
* `veyron/cli.py` — `--profile`, `--permit-path`, `--exclude-host`,
  `--max-requests`, `--rate-limit`, `--stop-file`, `--lab-environment`,
  `--evidence-retention`.
* `tests/test_assessment.py` (new) — profile rules, alias handling, scope
  derivation, link-local callback rejection, capability gates.

## E. Verification

`tests/test_assessment.py` covers: alias normalisation, refusal of
`LAB_EXPLOIT` without a lab declaration, refusal of validation profiles without
an authorised host, scope derivation for host/port/path permutations,
link-local callback rejection, and the capability gates. All hermetic — no
network access.

## F. Limitations and follow-up

* The spec is currently constructed from `DASTConfig`; the source-scanning path
  reports `PASSIVE`. A future change can let `scan` carry an explicit spec too.
* Identity secrets are stored in the spec but only ever surfaced via
  `Identity.sanitized()` (name + privilege); the secret is never serialised.
* Passwords/cookies for identities are read from config; a future change should
  support OS-keyring lookup so they need not live in the config file.
