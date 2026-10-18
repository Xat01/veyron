# Security policy for VEYRON

VEYRON is a security assessment tool. Its own security is treated as part of
its contract.

## Supported versions

| Version | Status |
|---|---|
| 0.1.0 (current) | Security fixes accepted |

Report security concerns via GitHub issue tags or email the repository
maintainer. Do not disclose suspected vulnerabilities publicly until the
maintainer has had 90 days to respond.

## Threat model and boundaries

- **In scope:** local CLI and local web dashboard (127.0.0.1 by default),
  assessment of repositories you own or are authorised to assess.
- **Out of scope:** scanning arbitrary public websites, validating discovered
  credentials, automatic exploitation, model-driven command execution.

## Reported risks of VEYRON itself (documented)

1. **OmniRoute route uncertainty.** `free-reliable` is verified to route to a
   free model today, but the gateway may change routing without notice. AI
   remains optional and failures degrade gracefully.
2. **OSV advisory freshness.** Offline cached advisories can be stale; reports
   mark cache-freshness explicitly.
3. **Secret redaction is pattern-based.** Not every secret shape is caught;
   humans must still review findings labelled "potential secret".
4. **Dashboard path containment.** Only files under `~/.veyron/reports` are
   served; history entries pointing elsewhere are refused.
5. **CLI console encoding.** Windows cp1252 terminals cannot render ✓/✗/⚠;
   ASCII markers are used on stdout.

## Secure defaults

- Dashboard binds to `127.0.0.1` only.
- CSRF double-submit + same-origin check on state-changing endpoints.
- CSP: default-src 'none', frame-ancestors 'none', X-Frame-Options DENY.
- Config file `~/.veyron/config.json` written mode 0600; API keys never
  printed or logged.
- No shell=True anywhere; scanner commands are argument arrays.

## Scanners bundled / invoked

Semgrep CE (LGPL-3.0), Bandit (LGPL-3.0), Gitleaks (MIT), OSV.dev API (no
key required). Verify each licence before production redistribution.
