# Feature report: command-injection and prompt-injection checks

## A. Summary

Two new modular checks extend the web-check suite to classes the validation
engine already understood but had no collector for:

* **Command injection** — a non-destructive marker probe that looks for a
  shell-evaluated constant or a distinct error differential.
* **Prompt injection** — a benign canary probe against an explicitly nominated
  LLM-enabled endpoint, checking whether the model follows instructions
  embedded in untrusted text.

Both follow the established rule: a finding is written only when a concrete,
observable signal was returned, and neither check claims `VALIDATED` on its own.

## B. Original problem

The class map recognised `command-injection` and (newly) prompt injection, but
no check produced evidence for them, so those classes could never appear in a
report. Prompt injection in particular needs a different discipline from the
HTTP-parameter checks: the target surface is an LLM endpoint and the probe must
be benign.

## C. Design

### Command injection: non-destructive, output-evaluated

The check sends `;echo vyncmdi<token> $((4241+2148));`. A shell folds the
constant to `6389`; an opaque system leaves it literal. Evidence is:

1. **command output** — the marker *and* the folded number both appear, proving
   a shell evaluated the value; or
2. **error differential** — a 5xx that the baseline did not return.

An independent second reproduction with a fresh token is required before the
engine can validate. Nothing destructive is executed; the only thing "run" is
the evaluation of a numeric constant. The finding carries severity `critical`
only once validated; until then it is `DETECTED`/`CORROBORATED`.

### Prompt injection: only nominated endpoints, benign canary

Prompt injection is meaningless against arbitrary URLs, so the target surface
must be **explicitly nominated** (CLI `--llm-endpoint`, or
`dast.prompt_injection_endpoints` in config). This prevents VEYRON from
blindly POSTing prompts to every form it finds.

The probe embeds a benign instruction — "reply with exactly this token" —
inside a clearly-delimited untrusted block, and asks for a normal summary. If
the response contains the canary, the model followed instructions that arrived
as data. Evidence is the observed instruction-following, plus an independent
second reproduction with a fresh canary. VEYRON never asks the model to leak a
system prompt wholesale, produce harmful content, or call a tool.

### New validation class

`CLASS_PROMPT_INJECTION` (`"prompt-injection"`) has its own requirement:
validation method `prompt-instruction-following` (or `response-differential`),
with mandatory observation and reproduction. It was added to the engine's
`marker_required` set and to `OBSERVABLE_MARKERS` ("instruction followed",
"command output"), so a narrative-only claim becomes `REQUIRES_MANUAL_REVIEW`
rather than a confirmed finding.

## D. Changed files

* `veyron/checks/command_injection.py` (new).
* `veyron/checks/prompt_injection.py` (new).
* `veyron/checks/base.py` — budget-aware `CheckContext.post_json`.
* `veyron/checks/__init__.py` — register both checks; `run_checks` accepts
  `prompt_injection_endpoints`.
* `veyron/validation.py` — `CLASS_PROMPT_INJECTION`, its requirement, class
  aliases, new validation method, and the two observable markers.
* `veyron/config.py` — `dast.prompt_injection_endpoints` (+ `_apply` key).
* `veyron/dast.py` — pass nominated endpoints through to `run_checks`.
* `veyron/cli.py` — `dast --llm-endpoint` (repeatable).
* `tests/test_webchecks.py`, `tests/test_validation.py` — new cases.

## E. Verification

* A local fixture that folds a constant yields a command-injection finding and
  validates; an opaque fixture yields nothing.
* A local `/chat` fixture that echoes the injected canary yields a
  prompt-injection finding and validates; a `/chat-safe` fixture that treats the
  text as data yields nothing; no endpoint yields nothing when not nominated.
* Engine tests: prompt injection validates with observed instruction-following
  and two reproductions; a narrative-only claim is `REQUIRES_MANUAL_REVIEW`; a
  single reproduction is `INCONCLUSIVE`.

All tests use local loopback servers only.

## F. Limitations and follow-up

* Prompt injection requires the operator to nominate the endpoint; automatic
  discovery of LLM surfaces is not attempted (and should not be).
* The canary probe detects direct instruction-following; subtler indirect or
  tool-chaining injections need bespoke, higher-profile probes.
* Deserialisation and file-handling checks remain future work.
