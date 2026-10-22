# VEYRON feature reports

This directory holds detailed engineering reports for meaningful features, fixes, architectural changes, and security improvements.

Reports are written as the work lands (per the master prompt §21). Each report documents the problem, design, changed files, tests, limitations, and follow-up work so the change remains reviewable and auditable.

## Index

| Report | Date | Summary |
| --- | --- | --- |
| [001-shared-network-layer.md](001-shared-network-layer.md) | 2026-10-22 | Shared HTTP/SOCKS5 client, proxy diagnostics, scope validation, fail-closed proxy behaviour. |
| [002-network-layer-migration.md](002-network-layer-migration.md) | 2026-10-22 | Migration of DAST, AI and OSV onto the shared network layer; session-cookie leak, dropped auth header and healthcheck bug fixes. |
