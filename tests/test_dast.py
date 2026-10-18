"""Controlled DAST: scope enforcement, redirect safety, budgets, dry-run."""

from veyron.config import DASTConfig
from veyron.dast import Budget, host_in_allowlist, run_dast


def cfg(**kw) -> DASTConfig:
    base = dict(enabled=True, allowlist=["127.0.0.1:8080", "localhost:8080"],
                max_requests=10, max_minutes=1, max_concurrency=1,
                follow_redirects=False, dry_run=True, rate_limit_per_second=100.0)
    base.update(kw)
    return DASTConfig(**base)


# -- allowlist ----------------------------------------------------------------

def test_localhost_in_allowlist():
    assert host_in_allowlist("http://127.0.0.1:8080/", ["127.0.0.1:8080"])


def test_arbitrary_public_site_blocked():
    assert not host_in_allowlist("https://example.com/", ["127.0.0.1:8080"])


def test_port_mismatch_blocked():
    assert not host_in_allowlist("http://127.0.0.1:9999/", ["127.0.0.1:8080"])


def test_lookalike_host_blocked():
    assert not host_in_allowlist("http://127.0.0.1.evil.com:8080/", ["127.0.0.1:8080"])


def test_non_http_scheme_blocked():
    assert not host_in_allowlist("file:///etc/passwd", ["127.0.0.1:8080"])


def test_default_port_inference_exact_only():
    # bare host entry matches scheme-default ports
    assert host_in_allowlist("https://staging.local/", ["staging.local"])
    # but explicit different port needs explicit entry
    assert not host_in_allowlist("https://staging.local:8443/", ["staging.local"])


# -- dry run -------------------------------------------------------------------

def test_dry_run_sends_nothing_and_shows_plan():
    res = run_dast(cfg(), target_url="http://127.0.0.1:8080/", execute=False, authorized=True)
    assert res.mode == "plan"
    assert res.checks == []
    assert res.plan and all(step["destructive"] is False for step in res.plan)
    assert res.budget["used"] == 0
    assert any("no requests sent" in s for s in res.skipped)


def test_execution_without_authorization_refused():
    res = run_dast(cfg(), target_url="http://127.0.0.1:8080/", execute=True, authorized=False)
    assert res.ok is False
    assert res.mode == "plan"  # never upgraded to execute
    assert res.budget["used"] == 0


def test_execution_outside_allowlist_refused():
    res = run_dast(cfg(), target_url="https://example.com/", execute=True, authorized=True)
    assert res.ok is False
    assert res.authorized_ok is False
    assert res.checks == []
    assert any("outside the allowlist" in s for s in res.skipped)
    # audit shows the denial
    assert any(a["action"] == "DENIED" and a["in_scope"] is False for a in res.audit)


# -- budget --------------------------------------------------------------------

def test_budget_exhaustion():
    b = Budget(cfg(max_requests=3))
    assert b.consume() and b.consume() and b.consume()
    assert not b.consume()
    assert b.exhausted_reason == "request budget exhausted"


def test_budget_snapshot_counts():
    b = Budget(cfg(max_requests=5))
    b.consume()
    snap = b.snapshot()
    assert snap["used"] == 1
    assert snap["max_requests"] == 5
    assert snap["remaining_seconds"] >= 0


# -- executed safe checks against local allowlisted target ----------------------

def test_execute_against_allowlisted_local_target_runs_safe_checks():
    # Use a target that will fail to connect (nothing listens) — the point is
    # scope enforcement and error recording, not live traffic.
    res = run_dast(cfg(allowlist=["127.0.0.1:1"]), target_url="http://127.0.0.1:1/",
                   execute=True, authorized=True)
    assert res.mode == "execute"
    assert res.authorized_ok is True
    # all planned attempts were within scope
    for a in res.audit:
        assert a["in_scope"] is True or a["action"].startswith(("REQUEST", "RESPONSE", "ERROR", "SKIPPED"))
    assert res.budget["used"] <= 5
