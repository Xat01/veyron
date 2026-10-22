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
- Local dashboard on 127.0.0.1: CSRF, CSP, path containment.
- Shared network layer (`veyron/net/`): one HTTP client for every outbound
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
- 221 unit tests (127 pre-existing + 55 network-layer tests + 39 migration
  and AI-adapter tests); integration tests run when real scanners are
  installed.
- Original SVG logo suite and brand specification.
- PolyForm Noncommercial licence (author: Xat01); GitHub Actions workflow for CI (`tests.yml`).

## Planned next

- README screenshots from real scans (once dashboard has findings screenshots).
- Dynamic testing validated against a local vulnerable staging app.
- More language-specific SAST adapters (Go, JavaScript).
