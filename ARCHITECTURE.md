# VEYRON Architecture

Vulnerability Evaluation, Research, and Yield-Oriented Offensive Analysis
Engine.

## Decisions and trade-offs

| Decision | Rationale |
|---|---|
| Modular monolith | One repository, clear module boundaries (`cli`, `orchestrator`, `adapters`, `config`, `finding`, `ai`, `dashboard`, `dast`, `report`). No microservices — no demonstrated need, and a dev-laptop-friendly runtime matters more than distribution. |
| No database | Assessment metadata lives in local JSONL history + per-assessment JSON report dirs (`~/.veyron`). Simplest durable storage; zero infrastructure cost. |
| Argument arrays only | Every scanner invocation goes through `veyron.subproc.run_command`, which forbids `shell=True`. Prevents command injection via target paths or config. |
| AI optional | Deterministic scanners (Semgrep, Bandit, Gitleaks, OSV) work without any AI. AI failures are recorded but never block an assessment. |
| OpenAI-compatible local gateway | OmniRoute at `http://localhost:3103/v1` routes requests to verified free models only; never to paid models. Configuration stored locally, key masked in output. |
| Local dashboard, loopback only | Web UI binds `127.0.0.1` by default; non-loopback binding requires explicit opt-in env var. CSRF + CSP + frame-ancestors DENY. |
| Secret handling | Detected secrets are redacted in evidence, reports, and AI payloads. Never transmitted, never validated externally. |
| Controlled DAST | Allowlist-first, budget-bound, redirect-safe, dry-run default, explicit authorisation required. Safe checks only (headers, cookies, banners). |

## Module map

`veyron/cli.py` — CLI entrypoint (`veyron scan|doctors|scanners|history|config|ai|dashboard|dast`)
`veyron/config.py` — configuration (file + `VEYRON_*` env overrides, validation)
`veyron/constants.py` — shared constants, severity/confidence/state vocabularies
`veyron/discovery.py` — repository discovery (inventory, manifests, exclusions)
`veyron/finding.py` — normalised Finding model, dedup/correlation, risk scoring
`veyron/orchestrator.py` — assessment pipeline: discovery → scans → dedupe → reports
`veyron/registry.py` — scanner adapter availability report
`veyron/ai.py` — OmniRoute/OpenAI-compatible chat adapter with redaction + retries
`veyron/dast.py` — controlled dynamic testing with audit log
`veyron/dashboard.py` — local web dashboard (loopback only)
`veyron/adapters/base.py` — ScannerAdapter contract (10 adapter requirements)
`veyron/adapters/semgrep.py` — Semgrep CE SAST adapter
`veyron/adapters/bandit.py` — Bandit Python SAST adapter
`veyron/adapters/gitleaks.py` — Gitleaks secret-detection adapter (redacting)
`veyron/adapters/osv.py` — OSV.dev SCA adapter (live or offline cache)
`veyron/subproc.py` — safe subprocess execution
`veyron/redact.py` — secret redaction (evidence/reports/AI payloads)
`veyron/report/core.py` — Markdown / JSON / SARIF report rendering

## Finding validation states

`DETECTED → ANALYSED → CORROBORATED → VALIDATED` (requires concrete evidence
language, never scanner+AI agreement alone). `DETECTED → FALSE_POSITIVE`,
`INCONCLUSIVE → DETECTED/CORROBORATED/VALIDATED/FALSE_POSITIVE`, and
`VALIDATED → INCONCLUSIVE` transitions permitted. Every transition records
actor, reason, and timestamp.

## SARIF

SARIF 2.1.0 emitted best-effort with `partialFingerprints` keyed by VEYRON
finding id; failed scanners recorded in invocation properties so a CI
consumer can distinguish "no findings" from "scan failed".

## Zero-cost constraints

No paid infrastructure. Network use limited to: OSV.dev advisory queries
(optional, cacheable), and OmniRoute-hosted free model requests (optional).
Neither is required for scanning.
