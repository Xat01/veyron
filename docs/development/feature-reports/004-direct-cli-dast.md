# Feature report: direct CLI website assessment (nmap-style invocation)

## A. Summary

Reduced the friction of running a website assessment from "put the target in
a JSON config, then invoke the tool" to a single command:

```text
veyron dast https://target.example/ -y
```

`-y` / `--yes` is shorthand for "scope the URL I typed, I am authorised, run
it". The persistent allowlist is not modified. Without `-y` or
`--authorize`, a non-allowlisted target is still refused before any socket is
opened.

Default output is now a short human-readable summary instead of a large JSON
document. `--json` preserves the previous machine-readable output.

## B. Original problem

The DAST safety model required every target to be present in
`dast.allowlist` (default: `127.0.0.1:8080`, `localhost:8080`). That is the
right default for unattended or CI use, but it made an interactive assessment
awkward:

1. edit `~/.veyron/config.json` (or export `VEYRON_DAST_ALLOWLIST`),
2. run `veyron dast <url> --execute --authorize`,
3. read a wall of JSON.

The owner asked for an nmap-style workflow: type the target, get a result.

## C. Design decision

### Scope from the command line, consent from a flag

When `--authorize` or `-y` is present and the target is not already
allowlisted, the CLI adds the target's explicit `host:port` to an in-memory
copy of the allowlist **for that process only**.

* The persistent config is untouched.
* `run_dast()` and the shared `HttpClient` still require an allowlist and a
  `Scope`; the library contract is unchanged.
* The safety gate is still explicit consent (`-y` / `--authorize`). A bare
  `veyron dast <url>` remains a no-traffic plan and is refused if the target
  is outside the allowlist.

`-y` additionally implies `--execute`, so the common interactive path is one
flag. `--execute --authorize` remains supported for scripts.

### Human output by default

The CLI prints target, profile, mode, request budget, findings by severity
and any blocked/denied audit events. `--json` keeps the full `DASTResult`
serialisation for piping and automation.

## D. Files changed

| File | Change |
| --- | --- |
| `veyron/dast.py` | `allowlist_entry_for_url()` helper. |
| `veyron/cli.py` | `-y/--yes`; auto-scope when authorised; `_print_dast_result()` summary; `--json` selects the previous output. |
| `tests/test_cli.py` | Auto-scope, one-flag run, refusal-without-consent, and summary-output tests; JSON tests pass `--json`. |
| `README.md`, `CHANGELOG.md` | Document the direct CLI path. |

## E. Tests

* `test_dast_authorize_scopes_cli_target_for_this_run` — `--authorize` on
  `localhost:3001` yields `authorized_ok: true`, plan mode, no requests,
  exit 0.
* `test_dast_yes_runs_without_allowlist_config` — `-y` yields execute mode,
  records attempts, exit 0, with no config file.
* `test_dast_non_allowlisted_without_consent_still_rejected` — bare command
  keeps `authorized_ok: false`, no checks, exit 3.
* `test_dast_summary_output_is_human_readable` — default output contains
  target/profile/plan, not JSON.
* Existing JSON tests now pass `--json` and are unchanged in substance.

`py -3 -m pytest -q` — 237 passed (see the run that landed with this
change).

## F. Security impact

* No implicit scope expansion: the target is only added when the operator
  supplies an explicit authorisation flag for that exact invocation.
* The target entry is the explicit `host:port`, so a bare `--authorize` does
  not widen scope to other ports or hosts.
* The crawler still requires same-origin links, and every request still goes
  through `HttpClient` with allowlist/`Scope` checks.
* No credentials are read from or written to config by this path.

## G. Limitations

* `-y` is an assertion by the operator. It is not proof of authorisation;
  the operator remains responsible for permission to test the target.
* A CDN or multi-host site still requires each host to be supplied
  separately if it should be assessed; the crawler is same-origin by design.
* The summary output is intentionally terse; detailed per-page observations
  remain in `--json` output.

## H. Follow-up work

* Optional `--scope host:port` flag for multi-host assessments without
  editing config.
* Optional `--output PATH` to write the JSON result directly.
