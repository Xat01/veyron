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
- Local dashboard on 127.0.0.1: CSRF, CSP, path containment.
- Shared network layer (`veyron/net/`): one HTTP client for every outbound
  request — scope enforcement, DNS resolution + destination-address
  validation (cloud-metadata blocked by default), redirect validation,
  request budgets, timeouts, cancellation, TLS verification on by default.
- Proxy subsystem: HTTP/HTTPS CONNECT and SOCKS5 routing, optional local Tor
  SOCKS endpoint, fail-closed behaviour (a proxy failure never silently falls
  back to a direct connection), credential masking, `veyron proxy status` and
  `veyron proxy probe` diagnostics.
- 182 unit tests (127 pre-existing + 55 network-layer tests); integration
  tests run when real scanners are installed.
- Original SVG logo suite and brand specification.
- PolyForm Noncommercial licence (author: Xat01); GitHub Actions workflow for CI (`tests.yml`).

## Planned next

- README screenshots from real scans (once dashboard has findings screenshots).
- Dynamic testing validated against a local vulnerable staging app.
- More language-specific SAST adapters (Go, JavaScript).
