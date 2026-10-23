# Changelog

## 0.1.0 (unreleased) — initial functional release

- Modular monolith: CLI, discovery, scanner adapters, AI adapter, DAST,
  dashboard, reporting (Markdown/JSON/SARIF).
- SAST: Semgrep Community Edition adapter (argument arrays, version capture,
  failure vs clean distinction).
- SAST: Bandit Python security scanner adapter.
- Secret detection: Gitleaks adapter with secret redaction in evidence and
  reports.
- SCA: OSV.dev advisory lookup (live or offline cache), advisory-match only,
  never claimed exploitable.
- Finding model: stable IDs, provenance, dedup/correlation, validation states
  (DETECTED → VALIDATED requires evidence), transparent risk scoring (not
  CVSS).
- AI: OmniRoute/OpenAI-compatible adapter, bounded retries, outbound secret
  redaction, untrusted model output treated as text only.
- Controlled DAST: allowlist, budget, deadline, rate limit, redirect safety,
  dry-run default, audit log.
- Website assessment (`dast --profile safe-active`): bounded same-origin
  crawl (default 10 pages), passive HTML link/form/mixed-content analysis,
  `security.txt` and `OPTIONS` probes, new DETECTED-only findings. No
  exploitation, fuzzing, or form submission.
- Direct CLI scanning: `veyron dast <url> -y` scopes the typed URL for the
  run and executes without editing config; output is a human-readable
  summary by default (`--json` for machine output).
- Local dashboard on 127.0.0.1: CSRF, CSP, path containment. Added read-only
  finding drill-down and report export, confined to files VEYRON itself recorded
  in local history.
- Assessment profiles and authorisation model (`veyron/assessment.py`): four
  profiles (PASSIVE, SAFE_ACTIVE, CONTROLLED_VALIDATION, LAB_EXPLOIT) with a
  single validated `AssessmentSpec` as the source of authorisation; the request
  scope is derived mechanically from it; invalid specs are refused, never
  silently downgraded.
- Evidence-driven validation engine (`veyron/validation.py`): per-class evidence
  requirements, deterministic verdicts
  (`VALIDATION_NOT_PERMITTED`/`BLOCKED_BY_SCOPE`/`INCONCLUSIVE`/`ANALYSED`/
  `VALIDATED`), dependency advisories never promote past `ANALYSED`, and
  unconditional credential redaction of evidence excerpts (honouring
  `evidence_retention`).
- Modular, profile-gated web checks (`veyron/checks/`): reflected-marker XSS,
  SQL-injection error differential, SSTI arithmetic, path traversal
  (resolved-path / error differential), non-destructive command injection
  (shell-evaluated constant / error differential), SSRF via an
  operator-controlled **loopback** callback, operator-declared broken access
  control, and benign prompt injection against explicitly nominated LLM
  endpoints. Each reports only what it observed; none claims `VALIDATED` on
  its own.
- Professional reporting: per-finding reports and an editable
  responsible-disclosure draft (never sent by VEYRON); every finding carries
  validation evidence, expected vs observed behaviour, impact, preconditions,
  safe reproduction, remediation and verification guidance. HTML report is
  self-contained with a strict CSP.
- `veyron scan --profile quick|standard|deep` presets; AI is never enabled
  implicitly.
- Global `offline` switch (no external AI or vulnerability-intelligence
  calls) with `VEYRON_OFFLINE` and per-integration overrides; AI endpoint
  policy (`allow_remote`/`allowed_hosts`) enforced independently of website
  scope; configurable OSV endpoint (`osv_base_url`).
- 310 unit tests (127 pre-existing + network-layer, migration, assessment,
  validation, web-check, reporting, dashboard and CLI tests); integration tests
  run when real scanners are installed.- Shared network layer (`veyron/net/`): one HTTP client for every outbound
  request — scope enforcement, DNS resolution + destination-address
  validation (cloud-metadata blocked by default), redirect validation,
  request budgets, timeouts, cancellation, TLS verification on by default.
- All remaining outbound HTTP paths migrated onto the shared network layer:
  DAST (`veyron/dast.py`), the AI adapter (`veyron/ai.py`) and the OSV.dev
  adapter (`veyron/adapters/osv.py`) no longer use `urllib.request`. The
  shared layer is now the only sanctioned outbound HTTP path in the
  codebase, so scope, proxy routing, fail-closed proxy behaviour, budgets,
  timeouts and TLS verification apply uniformly. A repository-wide test
  enforces this structurally.
- AI adapter: the gateway is treated as an explicitly configured integration
  endpoint, not a website assessment target — the website allowlist is not
  applied to it, while proxy routing and TLS verification still are.
- Fixed: `AIAdapter.healthcheck()` passed an unsupported `system_override=`
  keyword, so every enabled healthcheck raised `TypeError`.
- Fixed: DAST recorded whole `Set-Cookie` header values in its check output
  and findings, leaking session cookie values into reports. Only the cookie
  name and its security-relevant attributes (`HttpOnly`, `Secure`,
  `SameSite`) are now recorded. Tokens in a `Location` header are masked too.
- Proxy subsystem: HTTP/HTTPS CONNECT and SOCKS5 routing, optional local Tor
  SOCKS endpoint, fail-closed behaviour (a proxy failure never silently falls
  back to a direct connection), credential masking, `veyron proxy status` and
  `veyron proxy probe` diagnostics.
- Original SVG logo suite and brand specification.
- PolyForm Noncommercial licence (author: Xat01); GitHub Actions workflow for CI (`tests.yml`).

## Planned next

- README screenshots from real scans (once dashboard has findings screenshots).
- Dynamic testing validated against a local vulnerable staging app.
- More language-specific SAST adapters (Go, JavaScript).
