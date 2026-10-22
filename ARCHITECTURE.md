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
| Controlled DAST | Allowlist-first, budget-bound, redirect-safe, dry-run default, explicit authorisation required. Safe checks only (headers, cookies, banners). The opt-in `safe-active` profile adds a bounded same-origin crawl plus passive HTML/form/mixed-content analysis; still `GET`/`OPTIONS` only, no form submission, no payloads. Higher profiles (`controlled-validation`, `lab-exploit`) permit modular class-specific checks whose findings must satisfy the validation engine's evidence requirements before being marked `VALIDATED`. |
| One shared network layer | Every outbound HTTP request goes through `veyron.net.client.HttpClient`: scope check → DNS resolve → destination-address validation → connect → bounded response. Individual modules cannot bypass it. Enforced by a repository-wide test. |
| Two kinds of destination | A *website assessment target* (DAST) is bound by the operator's allowlist (`Scope`). A *configured integration endpoint* (AI gateway, OSV advisory API) is authorised by its configuration, not by a host allowlist — applying a website allowlist to it would reject a perfectly valid provider. Both get proxy routing, fail-closed proxy behaviour, budgets, timeouts and TLS verification. |
| `http.client`, not `urllib.request` | VEYRON must connect to a *validated IP* while still presenting the original hostname for SNI and `Host`. The high-level urllib API cannot express that, and address pinning is the DNS-rebinding defence. |
| Stdlib-only SOCKS5 | Tor and generic SOCKS proxies need a SOCKS client; the standard library has none and a third-party dependency would break the zero-dependency promise. A minimal CONNECT-only client (RFC 1928/1929) is implemented in `veyron/net/socks5.py`. |
| Fail-closed proxy | When a proxy is configured and unreachable, the request fails with `proxy_error`. There is no direct-retry path in the code, so "no unintended direct fallback" is a structural property, not a policy flag. |
| Loopback bypasses the proxy | A remote proxy cannot meaningfully reach a loopback destination, and the local AI gateway must stay reachable. `network.proxy_bypass_loopback` makes this explicit and configurable. |
| DNS resolved locally | The proxy is given an already-validated IP literal. This avoids proxy-side DNS rebinding and DNS leakage, at the cost of requiring local resolution. |

## Module map

`veyron/cli.py` — CLI entrypoint (`veyron scan|doctors|scanners|history|config|ai|proxy|dashboard|dast`)
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
`veyron/report/core.py` — Markdown / JSON / SARIF / HTML report rendering, per-finding reports, disclosure draft
`veyron/assessment.py` — assessment profiles and the `AssessmentSpec` authorisation model
`veyron/validation.py` — evidence-driven validation engine (per-class requirements, deterministic verdicts)
`veyron/checks/` — modular, profile-gated web checks (xss, sqli, ssti, path_traversal, ssrf, access_control) + loopback callback listener
`veyron/net/client.py` — shared HTTP client (scope, proxy routing, budgets, TLS)
`veyron/net/scope.py` — scope model: host/port/path authorisation, address validation
`veyron/net/proxy.py` — proxy configuration (HTTP/HTTPS/SOCKS5), credential masking
`veyron/net/socks5.py` — minimal SOCKS5 CONNECT client (RFC 1928/1929)
`veyron/net/diagnostics.py` — proxy status and route probing

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
