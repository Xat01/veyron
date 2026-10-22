# Feature report: migrating the remaining HTTP paths onto the shared network layer (Phase 3 completion)

## A. Summary

Migrated the last three independent outbound HTTP paths in VEYRON — DAST
(`veyron/dast.py`), the AI adapter (`veyron/ai.py`) and the OSV.dev
dependency adapter (`veyron/adapters/osv.py`) — onto the shared
`veyron.net.client.HttpClient` introduced in report 001.

Before this change, `veyron/net/client.py` was the sanctioned transport for
only some modules; three modules still opened sockets with `urllib.request`
and therefore bypassed scope enforcement, proxy routing, fail-closed proxy
behaviour, request budgets, redirect validation, timeouts, cancellation and
TLS verification. After this change, `veyron/net/client.py` is the **only**
place in the codebase that performs outbound HTTP, and a repository-wide test
enforces that structurally.

Three latent defects were found and fixed along the way: an always-raising
`TypeError` in `AIAdapter.healthcheck()`, a dropped provider
`Authorization` header, and a session-cookie value leak in DAST check output.

## B. Original problem

Report 001 introduced the shared network layer and listed the remaining
migration as follow-up work:

> `veyron/ai.py` and `veyron/adapters/osv.py` still use `urllib` directly.

The concrete consequences of that state:

| Module | Transport | What it bypassed |
| --- | --- | --- |
| `veyron/dast.py` | `urllib.request` + a private `_NoRedirect` handler | Operator proxy configuration (a DAST scan went direct even with a proxy set), `HttpClient` request budgets, per-request deadlines/cancellation, `HttpClient`'s redirect scope validation, address-pinning (the DNS-rebinding defence) |
| `veyron/ai.py` | `urllib.request.urlopen` | Operator proxy configuration, `HttpClient` budgets, address validation |
| `veyron/adapters/osv.py` | `urllib.request.urlopen` | Operator proxy configuration, `HttpClient` budgets, address validation |

The most serious of these is the proxy bypass. VEYRON's proxy subsystem is
documented as fail-closed — "a proxy failure never silently falls back to a
direct connection" — but that guarantee only held for the modules already on
`HttpClient`. With a proxy configured, a DAST scan or an OSV advisory lookup
would connect directly, silently disclosing the operator's source IP to the
target or to Google. The guarantee was documented but not true.

## C. Design decision

Route all three modules through `HttpClient`, and let the shared layer own
scope, proxy, budgets, timeouts and TLS. Module-specific behaviour (DAST's
audit log and check model, the AI adapter's payload redaction and response
parsing, OSV's caching) stays in the module; only transport moves.

The interesting design question was **what "scope" means** for a destination
that is not a website assessment target. Three options were considered:

1. **Apply the website allowlist to everything.** Rejected: the AI gateway
   and the OSV API are *configured integration endpoints*, authorised by the
   operator's configuration rather than by a host allowlist. Applying a
   website allowlist to them would reject a perfectly valid provider, and the
   AI gateway is usually `127.0.0.1` — which no website allowlist would
   contain.
2. **Give every module its own bespoke scope.** Rejected: reintroduces
   per-module policy, which is exactly the failure mode being eliminated.
3. **Distinguish the two kinds of destination explicitly.** Chosen: a
   *website assessment target* (DAST) is bound by the operator's allowlist
   via `Scope`; a *configured integration endpoint* (AI gateway, OSV) passes
   `scope=None` — authorised by configuration — while still receiving proxy
   routing, fail-closed proxy behaviour, budgets, timeouts and TLS
   verification.

Option 3 is now documented in `ARCHITECTURE.md` as "Two kinds of destination".

A second decision: **DAST keeps its own allowlist check in addition to the
client's scope check.** The client already refuses out-of-scope requests, but
DAST's audit log is a product requirement — a scope escape must be visible in
the audit trail. The DAST-level check is therefore retained as a
belt-and-braces control that also produces the `BLOCKED_OUT_OF_SCOPE` audit
record. This is defence in depth, not duplicated policy: both checks are
derived from the same `cfg.allowlist`, and `Scope.from_allowlist` implements
exactly the same port rule as `host_in_allowlist` (a bare host covers only
the scheme default ports 80/443; a `host:port` entry covers exactly that
port).

## D. Files changed

| File | Change |
| --- | --- |
| `veyron/dast.py` | `_safe_request` now issues its request via `HttpClient`; `_NoRedirect` (the `urllib` redirect blocker) removed; `_scope_for_allowlist()` added to translate the DAST allowlist into a `Scope`; `_cookie_summary()` and `_redact_location()` added to keep session values out of reports; the transport error kind is surfaced in the check's `error` field |
| `veyron/ai.py` | `_post()` now uses `HttpClient.post_json`; `_build_client()` added to construct a client carrying the operator's proxy/TLS policy; `_auth_headers()` added so the provider Bearer token is still sent; `_status_to_failure_kind()` added; `healthcheck()`'s `system_override=` bug fixed |
| `veyron/adapters/osv.py` | `_query_osv_batch()` uses `HttpClient.post_json`; `_enrich()` uses `HttpClient.get`; the adapter owns a long-lived `HttpClient` configured with the operator's proxy; offline mode and the local cache are unchanged |
| `veyron/config.py` | `DASTConfig` gained `timeout_seconds` (15) and `max_redirects` (5); both are loadable from the config file and validated |
| `tests/test_ai.py` | Rewritten to fake `HttpClient.post_json` instead of `urllib.request.urlopen`; added transport-contract tests |
| `tests/test_config.py` | Added tests for loading and validating the new DAST transport settings |
| `tests/test_net_migration.py` | **New** — 27 tests for the migrated paths (see section G) |
| `ARCHITECTURE.md` | Added the "Two kinds of destination" decision row; noted the structural test |
| `CHANGELOG.md` | Recorded the migration, the three bug fixes, and the new test count |

## E. Implementation details

### DAST

`_safe_request` keeps its original signature and return shape
(`status, headers, body, error`) so the rest of the module is unchanged. The
transport became:

```python
scope = _scope_for_allowlist(cfg)
proxy_cfg = _live_cfg.proxy if _live_cfg.proxy.configured else None
client = HttpClient(
    scope=scope, proxy=proxy_cfg, timeout=cfg.timeout_seconds,
    verify_tls=True, max_requests=cfg.max_requests,
    rate_limit_per_second=cfg.rate_limit_per_second,
    max_redirects=cfg.max_redirects, user_agent=USER_AGENT,
)
response = client.get(url, allow_redirects=False)
```

`allow_redirects=False` preserves the original semantics exactly: DAST never
auto-follows a redirect; it surfaces the `Location` header and validates the
target against the allowlist itself, so the `REDIRECT_BLOCKED` audit record
and the `redirect_blocked_as_out_of_scope` check field are unchanged.

Audit record actions are unchanged (`REQUEST` → `RESPONSE`/`ERROR`, plus
`BLOCKED_OUT_OF_SCOPE`, `SKIPPED_BUDGET`, `REDIRECT_BLOCKED`).

### AI

`chat()` is unchanged; only `_post()` was rewritten, so the retry loop, the
bounded backoff and the `retries` accounting all keep their original
behaviour. The request body is still built and redacted exactly as before
(`redact_text()` over both the system and user messages).

Failure classification is preserved by mapping explicitly:

| Condition | `failure_kind` | Retried? |
| --- | --- | --- |
| `401` / `403` | `auth` | No |
| `429` | `rate_limit` | Yes |
| other non-2xx | `http_error` | Yes |
| transport failure | `unreachable` | Yes |
| unparseable / unexpected body | `bad_response` | No |
| AI disabled | `disabled` | No |

`HttpClient` reports transport problems via `error_kind` using finer-grained
kinds internally (`proxy_error`, `dns_error`, `timeout`, …). The original
urllib implementation reported all of them as `unreachable`, and the retry
policy depends on that — `RETRYABLE = {"unreachable", "rate_limit",
"http_error"}`. The adapter therefore collapses transport failures back onto
`unreachable` and keeps the precise kind in the error message
(`"proxy_error: connection failed: …"`), so the documented failure-kind set
and the retry behaviour are unchanged while diagnosis stays possible.

The AI client is built with `scope=None` (see section C) and with
`max_requests = max_retries + 1` so a bounded retry sequence is never blocked
by a stale request counter.

### OSV

The adapter owns a single `HttpClient` for its lifetime, configured with the
operator's proxy and a bounded request budget. The two transport calls map
directly onto the shared client: `post_json` for the batch advisory query and
`get` for per-advisory enrichment. Offline mode is unchanged: the adapter
never constructs a request when `offline` is set, and falls back to the
on-disk cache with `data_freshness` marked as cached.

## F. Security impact

**Positive:**

* The fail-closed proxy guarantee now covers the whole application. With a
  proxy configured, DAST, AI and OSV traffic can no longer reach the network
  directly.
* DAST requests are now subject to `HttpClient`'s address validation, so
  the DNS-rebinding defence (pin the validated IP, keep the original
  hostname for SNI) applies to DAST as well.
* Out-of-scope destinations are refused before a socket is opened, and
  cross-host redirects are refused on every hop.

**Fixed defects:**

* **Dropped provider authentication header (AI).** The urllib implementation
  sent `Authorization: Bearer <api_key>`. The first version of the migration
  did not, which would have made *every* provider call fail with 401 while
  the unit tests still passed. `_auth_headers()` restores it, and
  `test_ai_sends_provider_authorization_header` is a regression guard that
  fails if the header is ever dropped again.
* **Session cookie leak (DAST).** The old cookie comprehension put the
  entire `Set-Cookie` header — including the cookie value — into the
  `flags` field of every cookie record, and `_interpret` then copied that
  into the finding `detail` and `evidence` fields. A DAST report therefore
  contained live session tokens. `_cookie_summary()` now records only the
  cookie name and its security-relevant attributes (`HttpOnly`, `Secure`,
  `SameSite`), which is exactly what the flag analysis needs. The detection
  logic in `_interpret` is unchanged.
* **`Location` header query leak (DAST).** `redirect_location` is now passed
  through `_redact_location()`, which masks sensitive query parameters
  (`token`, `session`, `key`, …) using the shared `SENSITIVE_KEYS` list.
* **`AIAdapter.healthcheck()` always raised.** It passed
  `system_override="…"`, but `chat()`'s keyword is `system`. Every enabled
  healthcheck — including the `veyron doctors` and `veyron ai` CLI paths —
  raised `TypeError`. Now corrected to `system=`.

**Not changed:** the AI payload redaction, the DAST dry-run default, the
OSV advisory cache semantics, and the DAST allowlist semantics are all
unchanged.

## G. Tests

The suite is **221 passing** (was 182).

### New: `tests/test_net_migration.py` (27 tests)

A local application server, a local proxy double and a free-port helper —
no test contacts a third-party host. The proxy double records the
connections it receives and then drops them, which lets a test assert both
that the request *reached the proxy layer* and that the target was *never
contacted directly*. A test that only asserted "the call failed" could not
tell a proxy failure from a direct-connection failure.

| Test | What it proves |
| --- | --- |
| `test_dast_uses_shared_http_client` | DAST issues its requests through `HttpClient`; the module no longer imports `urllib` |
| `test_dast_rejects_out_of_scope_destination` | An out-of-scope target is never contacted |
| `test_dast_per_host_port_restriction_enforced` | Allowlisting `host:8080` does not permit `host:9999` |
| `test_dast_redirect_cannot_escape_scope` | A cross-host redirect is flagged and the target is never contacted |
| `test_dast_request_budget_respected` | The request budget caps outbound requests |
| `test_dast_timeout_is_enforced` | A slow handler is cut off at the configured timeout |
| `test_dast_tls_verification_enabled_by_default` | `verify_tls` is never disabled silently |
| `test_dast_cookie_values_never_reach_the_report` | A session value never appears in the check output; name and flags are still analysed |
| `test_dast_redirect_location_query_secrets_are_masked` | Tokens in a `Location` header are masked |
| `test_dast_proxy_failure_does_not_fall_back_to_direct` | The proxy saw the request, the target was never contacted directly |
| `test_ai_has_no_independent_http_path` | The AI module carries no `urllib` transport of its own |
| `test_ai_sends_provider_authorization_header` | The provider Bearer token is sent |
| `test_ai_omits_authorization_header_when_no_key` | No key means no header, not an empty one |
| `test_ai_key_never_reaches_the_client_log` | The API key never reaches the client's log output |
| `test_ai_uses_configured_provider_endpoint` | The endpoint comes from configuration and is used verbatim |
| `test_ai_does_not_apply_website_allowlist` | The AI gateway is not bound by a website allowlist |
| `test_ai_healthcheck_succeeds` / `test_ai_healthcheck_failure_is_reported` | The healthcheck no longer raises |
| `test_ai_proxy_failure_does_not_fall_back_to_direct` | A dead proxy yields `unreachable` with zero direct connections |
| `test_osv_uses_shared_http_client` | OSV routes through `HttpClient`; no `urllib` in the module |
| `test_osv_respects_configured_endpoint` | OSV queries `api.osv.dev`, not an arbitrary host |
| `test_osv_proxy_failure_does_not_fall_back_to_direct` | A dead proxy fails the scan rather than querying OSV directly |
| `test_osv_offline_mode_makes_no_external_requests` | Offline mode issues **zero** requests (both `get` and `post_json` are trapped) |
| `test_osv_offline_with_no_cache_is_rejected` | Offline without a cache is a configuration error |
| `test_no_module_uses_urllib_request_for_http` | **Repo-wide audit:** no module outside `veyron/net/` references `urllib.request`, `urllib.error`, `http.client`, `requests`, `httpx` or `aiohttp` |
| `test_no_module_opens_raw_sockets_outside_net_layer` | **Repo-wide audit:** only the network layer opens raw sockets |

The two repo-wide audit tests are the structural guarantee: they fail the
build if a future module reintroduces an independent HTTP path, rather than
relying on review to catch it.

### Changed: `tests/test_ai.py` (15 → 25 tests)

The previous tests monkeypatched `ai_mod.urllib.request.urlopen`. With the
migration that hook no longer exists, so the tests were rewritten to patch
`HttpClient.post_json` — the seam the adapter now actually uses. The
assertions are unchanged in substance (unreachable, rate limit, auth, schema
errors, empty completion, secret redaction); they were re-pointed at the new
transport.

Ten tests were added: the configured provider endpoint, the "no website
allowlist on the AI gateway" rule, the healthcheck success and failure
paths, the authorization-header contract (sent / omitted / never logged),
the "no independent HTTP path" structural assertion, and a non-JSON body
case. Every test that existed before still exists — the prompt-injection
resistance test and `test_parse_json_never_raises` were restored verbatim
after an intermediate draft dropped them.

The redaction test's input was also left as the original
(`api_key='FAKE_OUTBOUND_KEY_9876543210'`), which the redactor recognises;
an intermediate draft used a differently-shaped secret that the redactor
does not match, which tested the redactor rather than the adapter.

### Changed: `tests/test_config.py` (9 → 11 tests)

Added `test_dast_transport_fields_are_loadable` and
`test_dast_transport_fields_are_validated` for the two new `DASTConfig`
fields.

### Unchanged

`tests/test_net.py` (55 tests), `tests/test_dast.py`, `tests/test_cli.py`,
`tests/test_adapters.py`, `tests/test_reports.py`, `tests/test_orchestrator.py`
and the rest all pass unmodified. A per-file comparison against `HEAD`
confirms no test was dropped from any file.

## H. Limitations

* **The AI gateway and the OSV API are not scope-checked.** They are trusted
  by configuration. A compromised or mistyped `base_url` in the config file
  will be connected to. This is deliberate — applying a website allowlist to
  a configured provider would be wrong — but it means the config file is
  trusted input. `HttpClient` still applies destination-address validation
  (cloud-metadata ranges stay blocked), budgets, timeouts and TLS
  verification to these calls.
* **The proxy is read from the global config on each adapter construction.**
  `AIAdapter._build_client()` and `OSVAdapter.__init__` both call
  `Config.load()`. A proxy change made after an adapter is constructed will
  not be picked up by that adapter. For the AI adapter the client is
  constructed per call, so this is a non-issue; for OSV the client is
  long-lived.
* **Loopback destinations bypass the proxy** by default
  (`proxy_bypass_loopback`). This is pre-existing and correct for the local
  AI gateway, but it means a local target is never routed through a remote
  proxy. The proxy tests deliberately disable that exemption so the proxy
  path is genuinely exercised.
* **DAST's `Budget` and `HttpClient`'s request budget are now two counters**
  for the same requests. DAST's budget additionally enforces the wall-clock
  deadline, which `HttpClient` does not have. The two are set to the same
  limit, so the tighter of the two wins — but they are not unified.
* **`HttpClient` has no per-request deadline**, only a per-request timeout
  and a client-wide deadline. DAST's `max_minutes` is enforced by the DAST
  budget, not by the client.
* **The AI provider's own request body is unchanged**, so a provider that
  requires additional headers beyond `Authorization` would still not receive
  them. This was the case before the migration too.

## I. Regression considerations

* **DAST audit records** keep their original action strings and ordering, so
  existing log parsers and the `veyron/dast` JSON output shape are stable.
* **DAST check dicts** keep their original keys. The `cookies` list changed
  *content* (name + security attributes instead of the raw header) and
  `redirect_location` is now masked — see the security impact above.
  Consumers reading `cookie["flags"]` for `HttpOnly` / `Secure` are
  unaffected; consumers that expected the raw cookie value were reading a
  credential that should never have been there.
* **The AI adapter's public surface** (`AIAdapter`, `AIResult`,
  `parse_json_reply`) is unchanged. `AIResult` gained no new fields; the
  `failure_kind` value set is exactly the same as before.
* **`parse_json_reply()` was preserved byte-for-byte** from the original,
  including the bounded `{...}` scan for JSON embedded in prose.
* **`AIAdapter.chat()` was preserved byte-for-byte** from the original —
  only `_post()` changed — so the retry loop, backoff and redaction
  behaviour are untouched.
* **`OSVAdapter._to_finding()` and the manifest parsers were preserved
  byte-for-byte** from the original. An intermediate draft of this work
  rewrote `_to_finding()` to derive a severity from the CVSS score, which
  the original deliberately refuses to do ("we do not fabricate CVSS
  numbers"); the original was restored. The same draft dropped the
  `require ( ... )` block branch of `_parse_go_mod`; it was restored too.
  An AST-level comparison of every function against `HEAD` was used to
  verify that only the intended transport functions changed.
* **OSV's cache file format is unchanged**, so an existing cache still loads.
* **`DASTConfig` gained two fields** with defaults, so existing config files
  and existing `DASTConfig(...)` constructor calls are unaffected.

## J. Manual verification

```console
$ py -3 -m pytest -q
221 passed in 51.70s

$ py -3 -m http.server 8099 --bind 127.0.0.1 &
$ VEYRON_DAST_ALLOWLIST=127.0.0.1:8099 \
    py -3 -m veyron.cli dast "http://127.0.0.1:8099/" --execute --authorize
{
  "ok": true,
  "mode": "execute",
  "target": "http://127.0.0.1:8099/",
  "authorized_ok": true,
  "plan": [],
  "checks": [
    {
      "url": "http://127.0.0.1:8099/",
      "status": 200,
      "security_headers_present": [],
      "security_headers_missing": [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy"
      ],
      "cookies": [],
      "server": "SimpleHTTP/0.6 Python/3.14.0",
      "error": null,
      "redirect_location": ""
    },
    ...
  ],
  "findings": [
    {
      "title": "Missing HTTP security headers",
      "detail": "strict-transport-security, content-security-policy, ...",
      "severity": "low",
      "confidence": "high",
      "validation_status": "DETECTED",
      "evidence": "GET http://127.0.0.1:8099/ -> 200; absent: [...]",
      ...
    }
  ],
  "ok": true
}

$ git grep -n "urllib.request|http.client" -- 'veyron/*.py' 'veyron/**/*.py'
veyron/net/client.py:18:The client is deliberately built on :mod:`http.client` rather than
veyron/net/client.py:19::mod:`urllib.request` because VEYRON needs to connect to a *validated IP
veyron/net/client.py:28:import http.client
veyron/net/client.py:154:class _PinnedHTTPConnection(http.client.HTTPConnection):
...
```

Only `veyron/net/client.py` matches. A live DAST execution against a local
server returned the same check and finding structure as before the migration.

## K. Owner review

* The scope decision in section C (website targets are allowlist-bound;
  configured integration endpoints are not) is the one design choice here
  that a reviewer should push back on if they disagree — it is the reason
  the AI gateway and the OSV API are not scope-checked.
* The cookie-leak fix changes what DAST records. If any downstream consumer
  relied on the raw `Set-Cookie` value, it will break — deliberately.
* `DASTConfig.timeout_seconds` and `DASTConfig.max_redirects` are new public
  fields; the intended home for them may be the existing `NetworkConfig`
  instead, which was not changed to avoid a wider blast radius.
* The AI transport failure kinds are collapsed onto `unreachable` to
  preserve the documented contract. A reviewer who prefers the finer-grained
  kinds to survive into `AIResult.failure_kind` should say so — that would
  also require widening `RETRYABLE`.

## L. Follow-up work

* Unify DAST's `Budget` with `HttpClient`'s request budget and deadline so
  there is one counter rather than two.
* Consider a `Config`-level notion of "trusted integration endpoints" that
  are checked against an allowlist of *providers* rather than a website
  allowlist, so a mistyped `base_url` is refused.
* Give `HttpClient` a per-request deadline, and have DAST's `max_minutes`
  drive it rather than the DAST-side budget.
* Move `DASTConfig.timeout_seconds` / `max_redirects` into `NetworkConfig`
  if the owner prefers a single source of timeout truth.
* Add a test that exercises a *live* DAST scan through the local proxy
  double end-to-end (asserting the proxy saw the request and the target saw
  nothing). The current proxy tests assert the failure path.
* Re-run the AST-level function comparison against `HEAD` as a permanent
  CI check, so an accidental rewrite of a preserved function — such as the
  `_to_finding` regression caught during this work — cannot land again.
