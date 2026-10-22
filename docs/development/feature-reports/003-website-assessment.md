# Feature report: website assessment profile (Phase 4)

## A. Summary

Extended the controlled DAST module (`veyron/dast.py`) with a second,
operator-selectable assessment profile:

* `passive` (default) — the previous behaviour: inspect the single target
  page plus `robots.txt` and `sitemap.xml`.
* `safe-active` — adds a bounded, same-origin crawl and passive HTML analysis
  (links, forms, mixed content, diagnostic leakage), a `security.txt` probe,
  and an `OPTIONS` method inventory.

Both profiles remain allowlist-first, budget-bound, redirect-safe, and
non-destructive. `safe-active` still performs only `GET` and `OPTIONS`
requests. It never submits a form, never fuzzes a parameter, never exploits a
finding, and never leaves the assessed origin while crawling.

## B. Original problem

Before this change, VEYRON's website assessment was a fixed three-request
snapshot of one URL (`/`, `/robots.txt`, `/sitemap.xml`). It could not answer
basic assessment questions that an operator reasonably expects from a
"website assessment":

* Which other pages are reachable from the entry point?
* Does the site mix HTTP subresources into an HTTPS page?
* Are there password forms served over plaintext HTTP?
* Do forms post to a different origin?
* Does an error page leak stack traces or SQL errors?
* Is there a disclosure policy (`security.txt`)?
* Which HTTP methods does the entry point advertise?

The fixed snapshot also made the `dast` command's "website assessment"
positioning in the project README stronger than the implementation.

## C. Design decision

### Profiles, not a new command

The change adds `profile: "passive" | "safe-active"` to `DASTConfig` and a
`--profile` CLI flag rather than creating a second scanner. Reasons:

* Scope, budget, audit, allowlist, redirect validation and the shared
  `HttpClient` are already correct in `dast.py`; a parallel module would
  duplicate and eventually diverge from those controls.
* Operators already authorise DAST explicitly (`--execute --authorize`); the
  profile is a capability selector, not an authorisation bypass.
* `passive` stays the default, so existing behaviour and tests are unchanged.

### Crawl boundaries

The crawler is deliberately conservative:

* Only links whose `(scheme, host, port)` matches the **entry URL's** origin
  are enqueued. Links to other origins are recorded by hostname as
  `external_resources`, never fetched.
* Every dequeued link is re-checked with `host_in_allowlist` and with the
  shared client's `Scope`; a link that somehow escapes is recorded as
  `BLOCKED_OUT_OF_SCOPE` and skipped.
* `max_pages` (default `10`) counts actual page fetches, not auxiliary probes
  such as `robots.txt` or `OPTIONS`.
* The existing request budget and wall-clock deadline still apply to every
  request, including crawl requests.
* Fragments are stripped and URLs are deduplicated canonically.

### Passive HTML analysis

HTML is parsed with the standard-library `html.parser.HTMLParser`. Nothing is
executed and no subresource is fetched. The parser records:

* same-origin links for the crawler;
* subresource URLs (`script`, `img`, `iframe`, `link`, ...) for mixed-content
  detection;
* form descriptors: action, method, field count, password field presence,
  cross-origin action;
* the page title.

Query-string values in recorded form actions pass through
`redact_url` so tokens (`token`, `key`, `session`, ...) never reach a report.

### Read-only active probes

`safe-active` adds two requests beyond the snapshot:

* `GET /.well-known/security.txt` — standard disclosure-policy location;
* `OPTIONS /` — records the `Allow` header.

Neither changes server state.

## D. Files changed

| File | Change |
| --- | --- |
| `veyron/config.py` | `DASTConfig.profile`, `DASTConfig.max_pages`; file/env overrides (`VEYRON_DAST_PROFILE`, `VEYRON_DAST_MAX_PAGES`); validation. |
| `veyron/dast.py` | Profile-aware plan; same-origin crawler; `_PageParser`; `_analyse_page`; new findings; `_safe_request(method=...)`; `profile` in `DASTResult`. |
| `veyron/cli.py` | `dast --profile {passive,safe-active}`; pass-through to `run_dast`. |
| `tests/test_website.py` | New: local-server integration tests and passive-analysis unit tests. |
| `tests/test_config.py` | Profile/max-pages loading, validation, and env-override tests. |
| `README.md`, `ARCHITECTURE.md`, `CHANGELOG.md`, `.env.example` | Documentation of the profile and its limits. |

## E. Implementation details

### Plan generation

`_build_plan()` now emits:

* fixed probes (`/`, `/robots.txt`, `/sitemap.xml`);
* in `safe-active`, `/.well-known/security.txt` and `OPTIONS /`;
* in `safe-active`, a synthetic crawl step (`"crawl": true`) whose URL is
  illustrative. The executor skips synthetic steps; the plan output tells the
  operator that discovered same-origin pages will be visited, up to
  `max_pages`.

### Execution

`_run_safe_checks()` performs fixed probes in order, collecting same-origin
links from every HTML `GET`. It then drains the queue while the page counter
is below `max_pages` and the budget is not exhausted. Each request goes
through `_safe_request()`, which already:

1. re-checks the allowlist;
2. consumes the budget;
3. builds a `Scope` from the allowlist;
4. loads operator proxy configuration;
5. sends the request through `HttpClient`.

A new `method` keyword lets the same path issue `OPTIONS`. Responses are
turned into check records by `_make_check()`, which analyses only `GET`
responses and only when the body looks like HTML.

### Findings

New `DETECTED`-only findings (never `VALIDATED`):

| Title | Severity | Basis |
| --- | --- | --- |
| HTTPS page loads plaintext HTTP resources | medium | `http://` subresources on an `https://` page |
| Password form submitted over plaintext HTTP | high | password field on an HTTP page with a non-HTTPS action |
| Form posts to a different origin | medium | form action origin differs from entry origin |
| Diagnostic information disclosed in response body | low | stack-trace/SQL/debug signatures in the body |

The existing missing-header and cookie-flag findings are unchanged and now
apply to every crawled page as well as the root.

## F. Security impact

* **No new egress.** All requests still go through `HttpClient`; the crawler
  cannot enqueue a non-root origin, and every URL is allowlist-checked twice.
* **No state change.** Only `GET` and `OPTIONS` are issued. Forms are parsed,
  never submitted. No payloads are injected.
* **Bounded work.** `max_pages`, `max_requests`, `max_minutes`, and
  `rate_limit_per_second` bound the assessment. A crawl cap produces a
  `CRAWL_CAP` audit record.
* **Credential hygiene.** Form actions are passed through `redact_url`;
  cookie values are still never recorded (only names and flags).
* **Honest findings.** All new findings are `DETECTED` with `medium`/`low`
  confidence where the evidence is circumstantial. Nothing is marked
  `VALIDATED`.

## G. Tests

`tests/test_website.py` (10 tests, all passing):

* passive profile sends only the three fixed probes and does not crawl;
* safe-active crawls `/about`, `/deep`, `/login`, `/error` from `/` but never
  requests `outside.example`;
* safe-active issues `OPTIONS` and records the `Allow` header;
* safe-active probes `/.well-known/security.txt`;
* password-form-over-HTTP and diagnostic-disclosure findings are produced;
* `max_pages=2` limits fetched pages and emits `CRAWL_CAP`;
* plan mode lists the `OPTIONS` step and the crawl step, all non-destructive;
* mixed content is detected on HTTPS pages but not HTTP pages;
* cross-origin form actions are flagged;
* non-HTML bodies are not parsed;
* sensitive query values are redacted in recorded form actions;
* links carrying URL-embedded credentials are never followed.

`tests/test_config.py` (+3 tests): profile/max-pages load from file, validate,
and override from environment.

Full suite at the time of writing: **234 passed**.

Static checks:

* `bandit -q -r veyron` — no findings in `dast.py`, `config.py`, or `cli.py`
  (remaining findings are pre-existing in `ai.py`, `dashboard.py`,
  `net/client.py`, `subproc.py`).
* `semgrep --config p/default veyron/dast.py veyron/config.py veyron/cli.py`
  — no findings.

## H. Limitations

* The integration tests use HTTP only. Mixed content and cross-origin form
  handling are covered by unit tests against `_analyse_page`, not by a live
  TLS server.
* The crawler is same-origin and unauthenticated. It does not log in, manage
  sessions, or follow JavaScript-rendered navigation.
* `robots.txt` and `sitemap.xml` are fetched but their contents are not yet
  parsed into a path inventory; only presence/status is recorded.
* `security.txt` presence is recorded as a check, not as a finding. A missing
  policy is not treated as a vulnerability.
* No active checks are performed (no parameter reflection, no authentication
  testing, no TLS configuration grading).

## I. Regression considerations

* `profile` defaults to `passive`, so existing `run_dast()` callers and the
  previous three-request behaviour are unchanged.
* `run_dast()` gained an optional keyword; positional call sites are
  unaffected.
* `DASTResult` gained `profile` with a default, so construction from existing
  code remains valid.
* `_safe_request()` gained a keyword-only `method`; existing calls still mean
  `GET`.

## J. Manual verification

```text
py -3 -m pytest -q
# 234 passed

py -3 -m veyron dast http://127.0.0.1:8080/ --profile safe-active
# plan includes:
#   GET /, /robots.txt, /sitemap.xml, /.well-known/security.txt
#   OPTIONS /
#   crawl discovered same-origin pages (max 10)
```

## K. Owner review

* `safe-active` is strictly opt-in. Confirm the default `max_pages=10` is
  appropriate for your assessment targets.
* The crawler treats the entry URL's origin as the crawl boundary even when
  the allowlist contains additional hosts. This is intentional (a target
  cannot expand its own scope) but means multi-host allowlists are only fully
  assessed if each host is supplied explicitly.
* Findings are deliberately conservative and `DETECTED`-only; no automatic
  promotion should be added without a reproducible evidence workflow.

## L. Follow-up work

* Parse `robots.txt` disallow entries and `sitemap.xml` URLs into a reviewed
  path inventory (still read-only).
* Add a TLS inspection check (certificate issuer, expiry, protocol) using the
  already-validated connection.
* Add an authenticated-profile design (explicit credential injection, never
  persisted) if operators need post-login coverage.
* Consider a `safe-active` report section that groups findings by page.
