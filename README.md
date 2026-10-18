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
  checks with explicit authorisation; dry-run by default.
- **Finding lifecycle** — DETECTED → ANALYSED → CORROBORATED → VALIDATED
  (evidence required); FALSE_POSITIVE and INCONCLUSIVE states retained.
- **Reports** — Markdown, JSON, SARIF; executive summary, scope, failures,
  exclusions, remediation guidance, known limitations; all secrets redacted.

## Technology stack

- Python 3.10+ (tested on 3.14), stdlib-only networking (urllib)
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
veyron scan ./my-repo        # assess a local repo
veyron dashboard             # local web UI at http://127.0.0.1:8732
```

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
- Secrets redacted by default; never committed to fixtures or docs.
- Dashboard binds loopback only.

## Testing

```powershell
py -m pytest -q
```

Integration tests run only when the real scanners are installed.

## Known limitations

- Semgrep `auto` ruleset requires metrics enabled; VEYRON pins `p/default`
  (free Semgrep registry ruleset).
- Secret redaction is pattern-based; manual review still required.
- Dashboard is single-user local; no multi-user auth.

## Roadmap

See `ARCHITECTURE.md` and the milestone list in the project specification
(M1 core → M7 release).

## Licence

PolyForm Noncommercial 1.0.0 — free for personal, research, educational, and
charitable use; commercial use and redistribution as a distinct product require
written permission. See `LICENSE` for the full terms.
