# Feature report: VEYRON shared network layer (Phase 3)

## A. Summary

Added `veyron/net/` — a shared HTTP and SOCKS5 transport layer with proxy
routing, scope enforcement, destination-address validation, redirect
validation, request budgets, cancellation, TLS verification, and credential
redaction. Every HTTP-based VEYRON module routes outbound traffic through
:class:`HttpClient`, so scope controls cannot be bypassed by any individual
scanner.

## B. Original problem

DAST was built around :mod:`urllib` with private helpers to disable
redirects. Scope, budget, timeouts, redirect validation, proxy routing, and
TLS verification were encoded ad hoc in each module that needed them. That
meant a scanner could accidentally bypass scope rules, go direct when an
operator asked for a proxy, skip address validation, follow unsigned
redirects, or leak credentials.

## C. Design decision

A single standard-library-only implementation using :mod:`http.client`
(with SNI/Host pinned to validated IPs for the DNS-rebinding defence), plus a
small SOCKS5 client (standard library has no SOCKS support) and a scope
decision object. Fail-closed proxy behaviour: a proxy failure returns
without a direct fallback and is recorded as `proxy_error`.

Alternatives considered:

* Expose proxy config to config only and run every scanner through one
  pre-built opener — rejected because adapters need different connection
  semantics and each needed a different opener. The shared client is simpler.
* Add the `requests` library as a dependency — rejected: breaks VEYRON's
  "stdlib-only" guarantee, adds a transitive dependency that can change
  versions without notice, and adds another failure mode on import.

## D. Files changed

* `veyron/config.py` — added `NetworkConfig` and `proxy` to `Config`; added
  `network.*`, `proxy.*` overrides; appended validation rules; save now
  writes `network` and `proxy`.
* `veyron/cli.py` — new `proxy status` / `proxy probe` commands.
* `veyron/net/__init__.py` — exports.
* `veyron/net/client.py` — `HttpClient`, `HttpResponse`, `ClientStats`,
  `redact_headers`, `redact_url`.
* `veyron/net/scope.py` — `Scope`, `ScopeDecision`.
* `veyron/net/proxy.py` — `ProxyConfig`.
* `veyron/net/socks5.py` — minimal SOCKS5 CONNECT client.
* `veyron/net/diagnostics.py` — `proxy_status`, `probe_proxy_route`.
* `veyron/net/__init__.py` — exports.
* New files: `veyron/net/{__init__,client,scope,proxy,socks5,diagnostics}.py`,
  `tests/test_net.py`.

## E. Implementation details

* `Scope` is built from `allowed_hosts` (host:port or bare host), `excluded_hosts`,
  `allowed_ports`, `allowed_schemes`, `allowed_paths`, optional `allowed_cidrs`
  and default `blocked_cidrs` (cloud-metadata 169.254.0.0/16, 0.0.0.0/8,
  multicast, IPv4/IPv6 unspecified). Address validation happens *before* dialing
  and pins the resolved literal address into the socket connection, so a second
  resolver can't substitute a different IP.
* `HttpClient` resolves the host with the same DNS resolver used for normal
  outbound checks, validates addresses against scope rules, then pins the IP
  into `HTTPConnection.connect` (`_PinnedHTTPConnection`) while keeping the
  original hostname for SNI. Redirects are validated by `Scope.check_redirect`
  on every hop.
* Proxies (HTTP CONNECT and SOCKS5, optionally Tor) route all external
  traffic. Loopback targets bypass the proxy unless `proxy_bypass_loopback`
  is off — so a local AI gateway can be reached directly. A proxy failure is
  always a final error; no direct retry path is built in, because per spec a
  proxy failure must not silently retry direct.
* `verify_tls` defaults True and is never disabled silently; it can be turned
  off explicitly via CLI flag only.
* Credentials are masked everywhere: `redact_url`, `redact_headers`,
  `ProxyConfig.masked()`, `proxy_status` output.

## F. Security impact

This is the phase that makes scope enforcement enforceable across *every*
HTTP module instead of only DAST. Previously a scanner could run an
unauthorised check; now no non-local check can reach its target through the
shared client without being scope-validated at the TCP layer. Proxy failures
are no longer silent because they return an explicit error and set
`stats.proxy_failures`. TLS verification is unconditional by default. Proxy
credentials are never logged.

## G. Tests

Added `tests/test_net.py` with 55 tests covering scope, proxy config, SOCKS5,
client behaviour, and diagnostics — all against locally-started servers, no
third-party hosts. Test run: `py -3 -m pytest tests/test_net.py` → 55 passed.

Command smoke tests (`proxy status --json`, `proxy probe ...`) are also in
the file under the CLI section and pass with no proxy configured.

### New test categories
* scope: host matching, wildcard subdomain, port/scheme/path rules,
  excluded hosts, excluded paths, cross-host redirect rejection, cloud
  metadata blocklist, CIDR override, private address refusal.
* proxy config: scheme parsing, credentials, unsupported scheme rejection,
  masking, endpoint display.
* redaction: URL + header masking.
* client: successful get, out-of-scope block before connect, out-of-scope
  redirect block, same-host redirect follow, redirect-disabled by default,
  request budget, cancellation, timeout, large body truncation, request
  accounting, invalid scheme, loopback proxy bypass.
* fail-closed: dead HTTP proxy routes through proxy only, dead SOCKS5 routes
  through proxy only, SOCKS5 auth forwarding, SOCKS5 connection refused,
  socks5 helper raises on unreachable proxy.
* diagnostics: status without proxy, status with dead proxy (reachable=False,
  direct_fallback_possible=False), credential leak check, probe fail closed,
  probe confirming route.
* configuration wiring: file load, invalid proxy problem recorded, env var
  overrides, tor env var, display masking, save+reload, validate flags
  incomplete proxy.

Skipped: none.

## H. Limitations

* SOCKS5 supports CONNECT only; UDP ASSOCIATE and BIND are unsupported.
* Address validation reduces but does not mathematically eliminate rebinding
  risk on explicitly allow-listed hosts — documented in diagnostics.
* Loopback destinations bypass the proxy by default (`network.proxy_bypass_loopback`),
  because routing a local service or the local AI gateway through a remote
  proxy would break the request. Set it to `false` to force the proxy path.
* HTTPS through an HTTP proxy uses `CONNECT`; HTTPS through SOCKS5 tunnels
  the raw socket and layers TLS on top. Neither path has been exercised
  against a live TLS endpoint in CI — only plain HTTP and the SOCKS5
  handshake are covered by automated tests.
* No proxy rotation, no retry-within-request, and no per-request proxy
  switching: one proxy is configured per client.
* `veyron dast` still uses its own urllib-based request path; it has not
  yet been migrated onto the shared client, so the two paths implement
  scope rules separately (see Follow-up).
* `veyron/ai.py` and `veyron/adapters/osv.py` also still use `urllib`
  directly and do not yet route through the shared client.

## I. Regression considerations

* Existing behaviour is unchanged: the new `network` and `proxy` config
  sections default to "no proxy, TLS verification on". Existing config
  files without these keys load unchanged.
* `veyron config` now prints `network` and `proxy` sections; the proxy
  section is masked. Consumers of that JSON output see two new keys.
* `veyron scan` output is unchanged.
* The new CLI subcommand `proxy` does not collide with any existing command.
* `Scope.from_allowlist` no longer populates the global `allowed_ports`
  list; port restriction is expressed per host entry instead. This is a
  deliberate fix — populating the global list would have restricted every
  host in the scope to the union of all entry ports.

## J. Manual verification

1. `veyron doctors` — should still list scanners and AI.
2. `veyron scan fixtures/vulnerable_app` — existing workflow still works.
3. Set `VEYRON_PROXY_URL=http://user:pass@10.0.0.5:8080` and run a probe:
   `veyron proxy probe <url>`. Verify response is `via_proxy: true` and that
   no direct fallback occurred.
4. Set `VEYRON_TOR_SOCKS_PROXY=socks5://127.0.0.1:9050` and run
   `veyron proxy status`. Without a running Tor daemon, `reachable: false`.
5. Configure a host allowlist (`dast.allowlist`) and try a non-allowlisted
   URL: request is refused before the socket is opened.

## K. Owner review

* Network routing defaults changed from "no proxy" to "proxy aware but no
  configured proxy". If this changes operator expectations, adjust
  `PROXY_BYPASS_LOOPBACK` and loopback exemptions.
* Proxy credentials are saved in the same `~/.veyron/config.json` as other
  settings (permissions 0600). Review whether credentials should be moved
  into a dedicated key file.

## L. Follow-up work

* `veyron/adapters/osv.py` and `veyron/ai.py` already use `urllib.request`
  directly — those modules should route through the shared client or accept
  an injected `HttpClient` where the network call matters. Phase 4 (site
  assessment) will benefit most.
* Rotation and retry policies for the shared client remain operator-driven
  today; a production gateway may want adaptive backoff.
* Browser-based DAST toolkits (e.g., OWAT) would naturally integrate with
  the shared layer when implemented.
