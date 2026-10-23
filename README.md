# VEYRON

**Vulnerability Evaluation, Research, and Yield-Oriented Offensive Analysis
Engine** — an AI-assisted application security assessment platform that runs
locally, costs zero to operate, and distinguishes *detected* weaknesses from
*validated* findings.

<img src="assets/logo/veyron-logo.svg" alt="VEYRON logo" width="200">

## What VEYRON is

A command-line (and optional local web) security assessment tool for local
repositories. It combines deterministic free scanners with optional AI
assistance, normalises every finding into one evidence-preserving schema,
and writes human-readable and machine-readable reports.

## Key capabilities

- **Repository discovery** — inventories files, languages, dependency
  manifests; honours exclusions and file-size limits; reports skipped/
  unsupported files honestly.
- **Static analysis** — Semgrep Community Edition (multi-language) and Bandit
  (Python) adapters with safe subprocess execution, version capture, and
  failure-vs-clean reporting.
- **Dependency analysis** — OSV.dev advisory lookups (live or cached),
  distinguishing advisory match from demonstrated exploitability.
- **Secret detection** — Gitleaks integration with automatic secret redaction
  in evidence and reports; secrets are never transmitted anywhere.
- **AI-assisted analysis** — optional OmniRoute integration using verified
  free models only; AI output is advisory, never executable, never permitted
  to bypass safety checks.
- **Controlled dynamic testing** — allowlist-first, budget-bound, redirect-safe
  checks with explicit authorisation; dry-run by default. An opt-in
  `safe-active` profile adds a bounded same-origin crawl and passive
  HTML/form analysis — no exploitation, fuzzing, or form submission.
  Profile-gated modular web checks (XSS, SQL-injection error differential,
  SSTI arithmetic, path traversal, non-destructive command injection, SSRF via
  operator/loopback callback, operator-declared broken access control, and
  benign prompt injection against nominated LLM endpoints) validate only what
  they actually observed, and say so.
- **Four assessment profiles** — `PASSIVE`, `SAFE_ACTIVE`,
  `CONTROLLED_VALIDATION`, and `LAB_EXPLOIT`. Each declares what evidence it
  may collect; higher profiles require explicit authorisation (`LAB_EXPLOIT`
  additionally requires a declared isolated lab environment).
- **Scan presets** — `veyron scan --profile quick|standard|deep` trades
  scanner coverage for speed (`deep` is the only preset that may use AI).
- **Professional reporting** — consolidated markdown/JSON/SARIF/HTML reports,
  per-finding reports, and an editable responsible-disclosure draft. Every
  finding carries validation evidence, expected vs observed behaviour,
  impact, prerequisites, safe reproduction, remediation and verification
  guidance.
- **Finding lifecycle** — DETECTED → ANALYSED → CORROBORATED → VALIDATED
  (evidence required); FALSE_POSITIVE and INCONCLUSIVE states retained.
- **Reports** — Markdown, JSON, SARIF; executive summary, scope, failures,
  exclusions, remediation guidance, known limitations; all secrets redacted.
- **Shared network layer** — one HTTP client for every outbound request:
  proxy routing (HTTP/HTTPS CONNECT, SOCKS5, optional Tor), scope
  enforcement, destination-address validation, redirect validation, request
  budgets, timeouts, cancellation and TLS verification. A proxy failure
  never silently falls back to a direct connection.

## Technology stack

- Python 3.10+ (tested on 3.14), stdlib-only networking (`http.client` +
  a minimal SOCKS5 client)
- Scanners: Semgrep CE, Bandit, Gitleaks, OSV.dev API
- AI gateway: OmniRoute (local, OpenAI-compatible) at `http://localhost:3103/v1`
- Dashboard: stdlib `http.server` bound to 127.0.0.1, no frontend framework

## Installation

```powershell
# From source
git clone https://github.com/<you>/veyron
cd veyron
py -m pip install -e .
```

Zero-cost constraints: no paid infrastructure, no paid model tier, AI
optional.

## Quick start

```powershell
veyron doctors               # check scanners + AI health
veyron scan ./my-repo                 # assess a local repo (standard preset)
veyron scan ./my-repo --profile quick  # fast secrets + dependency scan
veyron scan ./my-repo --profile deep   # all scanners + AI enrichment
veyron proxy status          # proxy configuration and reachability
veyron dashboard             # local web UI at http://127.0.0.1:8732
```

Website assessments (authorised targets only):

```powershell
# Dry run first: shows the plan, sends nothing.
veyron dast http://127.0.0.1:8080/

# Execute passive/safe-active checks against an allowlisted target.
veyron dast http://127.0.0.1:8080/ --execute --authorize --profile safe-active

# Controlled validation, restricted to a path prefix, with reports on disk.
veyron dast http://127.0.0.1:8080/ --profile controlled-validation `
  --execute --authorize --permit-path /app --report-dir .\reports\dast

# Probe an authorised LLM endpoint for prompt injection (explicitly nominated).
veyron dast http://127.0.0.1:8080/ --profile controlled-validation `
  --execute --authorize --llm-endpoint http://127.0.0.1:8080/chat
```

## Proxy and network routing

VEYRON routes all HTTP traffic through one shared client
(`veyron/net/`). Configure a proxy in `~/.veyron/config.json`:

```json
{
  "proxy": { "url": "socks5://127.0.0.1:9050", "tor": true },
  "network": { "timeout_seconds": 15, "verify_tls": true, "max_requests": 500 }
}
```

or with environment variables:

```powershell
$env:VEYRON_PROXY_URL = "http://user:pass@127.0.0.1:8080"   # HTTP/HTTPS proxy
$env:VEYRON_TOR_SOCKS_PROXY = "socks5://127.0.0.1:9050"     # local Tor SOCKS
```

Diagnostics report what was actually observed:

```powershell
veyron proxy status          # configured proxy, reachability, fallback policy
veyron proxy probe https://example.com/   # one request through the proxy
```

* A configured proxy is **fail-closed**: if the proxy is unreachable the
  request fails with `proxy_error` — VEYRON never retries it directly.
* Loopback destinations bypass the proxy by default; set
  `network.proxy_bypass_loopback` to `false` to force the proxy path.
* Tor is optional and operated by you. VEYRON verifies the SOCKS endpoint
  is reachable and that requests use it, but **no anonymity guarantee is
  claimed or implied**.
* VEYRON resolves hostnames locally, validates the resolved address against
  the scope, and connects to the validated address — this blocks
  cloud-metadata targets and reduces DNS-rebinding risk.
* Proxy credentials are never logged, printed, or written to reports.

## Example

Reports are produced for the included `fixtures/vulnerable_app` fixture:

```powershell
veyron scan fixtures/vulnerable_app --offline-sca
```

Outputs under `~/.veyron/reports/<assessment-id>/` as `.json`, `.md`, `.sarif`.
See `docs/` for a sample report walkthrough (to be generated from real runs).

## AI configuration (optional)

Copy `.env.example` to `~/.veyron/config.json`, or set `VEYRON_*` variables:

```json
{
  "ai": { "enabled": true, "base_url": "http://localhost:3103/v1", "model": "free-reliable" },
  "scanners": { "enabled": ["semgrep", "bandit", "gitleaks", "osv"] }
}
```

`free-reliable` is verified against the local OmniRoute gateway. AI is
never required for scanning.

## Zero-cost limitations

- AI model routes are free-only today; routing can change without notice.
- OSV.dev advisory queries need network; offline cache may be stale.
- No unlimited free quota is claimed anywhere.

## Security & authorisation

- DAST requires explicit `--authorize` + `--execute` against allowlisted
  targets only; localhost by default.
- Validation never runs without authorisation: profiles that require
  `--authorize`/`--execute` are refused rather than silently downgraded, and
  a global `stop_file` aborts a run immediately when it appears.
- VEYRON never contacts a third party on your behalf: no security-contact
  lookup, no ticket creation, no outbound disclosure. It only produces an
  editable draft you review and send yourself.
- The `safe-active` website profile crawls only same-origin links and issues
  only `GET`/`OPTIONS`; it never submits forms or injects payloads.
- `veyron dast <url> -y` scopes the exact URL typed for that run and executes
  it. The persistent allowlist is unchanged; without `-y`/`--authorize` a
  non-allowlisted target is still refused.
- Every outbound request passes the shared network layer: scope check →
  DNS resolution → destination-address validation → connect.
- Cloud-metadata and link-local ranges are blocked by default.
- Secrets redacted by default; never committed to fixtures or docs.
- Proxy credentials are masked in every output surface.
- Dashboard binds loopback only.

## Testing

```powershell
py -m pytest -q
```

Integration tests run only when the real scanners are installed. Network
tests use locally-started servers and local proxy/SOCKS5 test doubles — no
test contacts a third-party host.

## Known limitations

- Semgrep `auto` ruleset requires metrics enabled; VEYRON pins `p/default`
  (free Semgrep registry ruleset).
- Secret redaction is pattern-based; manual review still required.
- The SOCKS5 client supports CONNECT only (no UDP ASSOCIATE/BIND).
- Tor integration is optional, unverified for anonymity, and requires you
  to install and operate Tor yourself.
- Dashboard is single-user local; no multi-user auth.

## Roadmap

See `ARCHITECTURE.md` and the milestone list in the project specification
(M1 core → M7 release).

## Licence

PolyForm Noncommercial 1.0.0 — free for personal, research, educational, and
charitable use; commercial use and redistribution as a distinct product require
written permission. See `LICENSE` for the full terms.
