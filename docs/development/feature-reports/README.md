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
