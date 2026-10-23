# VEYRON feature reports

This directory holds detailed engineering reports for meaningful features, fixes, architectural changes, and security improvements.

Reports are written as the work lands (per the master prompt §21). Each report documents the problem, design, changed files, tests, limitations, and follow-up work so the change remains reviewable and auditable.

## Index

| Report | Date | Summary |
| --- | --- | --- |
| [001-shared-network-layer.md](001-shared-network-layer.md) | 2026-10-22 | Shared HTTP/SOCKS5 client, proxy diagnostics, scope validation, fail-closed proxy behaviour. |
| [002-network-layer-migration.md](002-network-layer-migration.md) | 2026-10-22 | Migration of DAST, AI and OSV onto the shared network layer; session-cookie leak, dropped auth header and healthcheck bug fixes. |
| [003-website-assessment.md](003-website-assessment.md) | 2026-10-22 | Phase 4 website assessment: opt-in safe-active profile with bounded same-origin crawl, passive HTML/form analysis and read-only probes. |
| [004-direct-cli-dast.md](004-direct-cli-dast.md) | 2026-10-22 | Direct nmap-style invocation: `dast <url> -y` scopes the typed URL for the run; human summary by default, `--json` optional. |
| [005-assessment-profiles-authorization.md](005-assessment-profiles-authorization.md) | 2026-10-22 | Four assessment profiles and a single `AssessmentSpec` authorisation model; scope derived mechanically; fail-closed on invalid specs. |
| [006-validation-engine.md](006-validation-engine.md) | 2026-10-22 | Evidence-driven validation: per-class evidence requirements, deterministic verdicts, dependency advisories never promote, unconditional credential redaction. |
| [007-modular-web-checks.md](007-modular-web-checks.md) | 2026-10-22 | Profile-gated modular checks (XSS, SQLi, SSTI, SSRF via loopback callback, access control) that only report what they observed. |
| [008-reporting-dashboard-presets.md](008-reporting-dashboard-presets.md) | 2026-10-22 | Professional reports (per-finding + disclosure draft), dashboard finding drill-down/export, and `scan --profile quick|standard|deep` presets. |
| [009-command-and-prompt-injection.md](009-command-and-prompt-injection.md) | 2026-10-23 | Non-destructive command-injection check and a benign prompt-injection check against explicitly nominated LLM endpoints; new prompt-injection validation class. |
| [010-automatic-exploit-validation.md](010-automatic-exploit-validation.md) | 2026-10-23 | Automatic exploit-validation engine: explicit lifecycle, module registry, AUTO_SAFE/APPROVAL_REQUIRED/LAB_ONLY policy, separated verification, structured evidence, automatic reports and a no-host-fallback lab backend. |
