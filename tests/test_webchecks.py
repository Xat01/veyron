"""Modular web checks against local test servers only.

No third-party host is contacted.  The SSRF fixture uses VEYRON's own loopback
callback listener, which is exactly the controlled infrastructure the check is
supposed to use.
"""

from __future__ import annotations

import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from veyron.assessment import (
    AssessmentSpec,
    Identity,
    PROFILE_CONTROLLED_VALIDATION,
    PROFILE_SAFE_ACTIVE,
)
from veyron.checks import CheckContext, run_checks
from veyron.checks.callback import CallbackListener
from veyron.checks.xss import mutate_query
from veyron.net.client import HttpClient


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib hook
        parsed = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        value = query.get("q", "")
        if parsed.path == "/echo":
            body = f"<html><body>Results: {value}</body></html>".encode()
            status = 200
        elif parsed.path == "/safe":
            import html

            body = f"<html><body>Results: {html.escape(value)}</body></html>".encode()
            status = 200
        elif parsed.path == "/sqlerr":
            if "'" in value or '"' in value:
                body = b"<html>You have an error in your SQL syntax near ...</html>"
            else:
                body = b"<html>ok</html>"
            status = 200
        elif parsed.path == "/ssti":
            body = f"<html><body>{value.replace('{{7*7}}', '49').replace('${7*7}', '49')}</body></html>".encode()
            status = 200
        elif parsed.path == "/admin":
            # Deliberately ignores the identity: the bug under test.
            body = b"<html><body>synthetic record: invoice 42</body></html>"
            status = 200
        elif parsed.path == "/traverse":
            # Deliberately resolves a path-like value: the bug under test.
            # A resolver collapses the "../" segments, so the marker appears
            # as part of a path with no leading traversal left.
            if ".." in value:
                resolved = value.split("veyron_probe_")[-1]
                body = f"<html><body>resolved path: /etc/veyron_probe_{resolved}</body></html>".encode()
            else:
                body = b"<html><body>resolved path: /srv/app/index</body></html>"
            status = 200
        elif parsed.path == "/traverse-safe":
            import html

            body = f"<html><body>opaque value: {html.escape(value)}</body></html>".encode()
            status = 200
        elif parsed.path == "/fetch":
            # Deliberately fetches user-supplied URLs: the bug under test.
            target = query.get("url", value)
            try:
                urllib.request.urlopen(target, timeout=2).read()
            except Exception:  # noqa: BLE001 - best effort for the fixture
                pass
            body = b"<html>fetched</html>"
            status = 200
        else:
            body = b"not found"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture()
def site():
    import veyron.config as config_mod
    from veyron.config import Config

    # Avoid the developer's real config/proxy environment leaking into tests.
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(Config, "load", classmethod(lambda cls: Config()))
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        monkeypatch.undo()


def spec(profile: str, host: str, **kw) -> AssessmentSpec:
    port = int(host.rsplit(":", 1)[1])
    return AssessmentSpec(
        profile=profile,
        authorized_hosts=[host.split("//")[1]],
        permitted_ports=[port],
        max_requests=40,
        max_rate_per_second=100.0,
        **kw,
    )


def context(spec_obj: AssessmentSpec, callback=None) -> CheckContext:
    client = HttpClient(scope=spec_obj.scope(), timeout=3, max_requests=40)
    return CheckContext(client=client, spec=spec_obj, callback=callback)


def test_query_mutation_preserves_other_parameters():
    assert mutate_query("http://x/a?one=1&q=old&two=2", "q", "new") == (
        "http://x/a?one=1&q=new&two=2"
    )


def test_xss_marker_corroborated_in_safe_active(site):
    s = spec(PROFILE_SAFE_ACTIVE, site)
    findings, errors = run_checks(context(s), [site + "/echo?q=hello"])
    assert not errors
    xss = [f for f in findings if f["category"] == "xss"]
    assert xss, findings
    assert xss[0]["validation_status"] == "CORROBORATED"
    assert xss[0]["validation_evidence"]["engine"]["status"] == "CORROBORATED"


def test_xss_validated_in_controlled_validation(site):
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    findings, errors = run_checks(context(s), [site + "/echo?q=hello"])
    assert not errors
    xss = [f for f in findings if f["category"] == "xss"]
    assert xss, findings
    assert xss[0]["validation_status"] == "VALIDATED"


def test_encoded_reflection_is_not_a_finding(site):
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    findings, _ = run_checks(context(s), [site + "/safe?q=hello"])
    assert [f for f in findings if f["category"] == "xss"] == []


def test_sqli_error_differential(site):
    s = spec(PROFILE_SAFE_ACTIVE, site)
    findings, _ = run_checks(context(s), [site + "/sqlerr?q=abc"])
    sqli = [f for f in findings if f["category"] == "sql-injection"]
    assert sqli, findings
    assert sqli[0]["validation_status"] == "CORROBORATED"
    assert "syntax error" in sqli[0]["validation_evidence"]["observed"].lower()


def test_ssti_requires_controlled_validation(site):
    s = spec(PROFILE_SAFE_ACTIVE, site)
    findings, _ = run_checks(context(s), [site + "/ssti?q=x"])
    assert [f for f in findings if f["category"] == "ssti"] == []

    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    findings, _ = run_checks(context(s), [site + "/ssti?q=x"])
    ssti = [f for f in findings if f["category"] == "ssti"]
    assert ssti, findings
    assert ssti[0]["validation_status"] == "VALIDATED"


def test_access_control_requires_explicit_rule_and_identities(site):
    host = site.split("//")[1]
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    s.identities = [
        Identity(name="low", headers={"Authorization": "Bearer low"}, privilege="low"),
        Identity(name="high", headers={"Authorization": "Bearer high"}, privilege="high"),
    ]
    s.access_control_rules = [
        {"url": site + "/admin", "allowed_privileges": ["high"]}
    ]
    findings, _ = run_checks(context(s), [])
    acl = [f for f in findings if f["category"] == "broken-access-control"]
    assert acl, findings
    assert acl[0]["validation_status"] == "VALIDATED"
    # Credentials must never appear in the reportable evidence.
    blob = str(acl[0])
    assert "Bearer low" not in blob and "Bearer high" not in blob


def test_access_control_without_rule_sends_no_requests(site):
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    s.identities = [
        Identity(name="low", privilege="low"), Identity(name="high", privilege="high")
    ]
    findings, _ = run_checks(context(s), [])
    assert findings == []


def test_ssrf_only_reports_observed_callback(site):
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    with CallbackListener() as listener:
        ctx = context(s, callback=listener)
        findings, _ = run_checks(ctx, [site + "/fetch?url=placeholder"])
        ssrf = [f for f in findings if f["category"] == "ssrf"]
        assert ssrf, findings
        assert ssrf[0]["validation_status"] == "VALIDATED"
        assert "callback" in ssrf[0]["evidence"].lower()


def test_ssrf_does_not_run_without_callback(site):
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    findings, _ = run_checks(context(s), [site + "/fetch?url=placeholder"])
    assert [f for f in findings if f["category"] == "ssrf"] == []


def test_passive_profile_sends_no_checks(site):
    from veyron.assessment import PROFILE_PASSIVE

    s = spec(PROFILE_PASSIVE, site)
    findings, errors = run_checks(context(s), [site + "/echo?q=hello"])
    assert findings == [] and errors == []


def test_budget_stops_requests(site):
    s = spec(PROFILE_SAFE_ACTIVE, site)
    client = HttpClient(scope=s.scope(), timeout=3, max_requests=40)
    allowed = {"count": 0}

    def consume() -> bool:
        allowed["count"] += 1
        return False

    ctx = CheckContext(client=client, spec=s, consume=consume)
    findings, _ = run_checks(ctx, [site + "/echo?q=hello"])
    assert findings == []

def test_path_traversal_reports_resolved_path(site):
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    findings, _ = run_checks(context(s), [site + "/traverse?q=file"])
    trav = [f for f in findings if f["category"] == "path-traversal"]
    assert trav, findings
    assert trav[0]["validation_status"] == "VALIDATED"
    assert "resolved path" in trav[0]["validation_evidence"]["observed"]


def test_opaque_path_parameter_is_not_a_finding(site):
    s = spec(PROFILE_CONTROLLED_VALIDATION, site)
    findings, _ = run_checks(context(s), [site + "/traverse-safe?q=file"])
    assert [f for f in findings if f["category"] == "path-traversal"] == []
