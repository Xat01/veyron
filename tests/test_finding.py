"""Finding model: normalisation, deduplication, states, risk handling."""

import json

from veyron.finding import (
    Finding,
    deduplicate,
    prioritise,
    stable_finding_id,
)


def make(**kw) -> Finding:
    base = dict(
        id=stable_finding_id("sast.semgrep", "rule.a", "a.py", 1, "t"),
        title="t",
        description="d",
        category="cat",
        severity="high",
        confidence="medium",
        validation_status="DETECTED",
        source="sast.semgrep",
        file_path="a.py",
        line=1,
        evidence="ev",
    )
    base.update(kw)
    return Finding(**base)


def test_stable_id_deterministic():
    a = stable_finding_id("s", "r", "f.py", 3, "Title")
    b = stable_finding_id("s", "r", "f.py", 3, "title")
    c = stable_finding_id("s", "r", "f.py", 4, "Title")
    assert a == b
    assert a != c
    assert a.startswith("VYN-")


def test_invalid_severity_normalised_to_unknown():
    f = make(severity="apocalyptic")
    assert f.severity == "unknown"


def test_invalid_state_normalised_to_detected():
    f = make(validation_status="MAYBE")
    assert f.validation_status == "DETECTED"


def test_validated_requires_substantive_reason():
    f = make()
    assert f.transition("VALIDATED", "scanner said so") is False  # too short / no evidence
    assert f.validation_status == "DETECTED"
    assert f.transition("VALIDATED", "reproduced locally with crafted payload; see evidence hash abc") is True
    assert f.validation_status == "VALIDATED"
    assert len(f.validation_history) == 1


def test_illegal_transition_blocked():
    f = make(validation_status="VALIDATED")
    assert f.transition("DETECTED", "step backwards should not apply") is False
    assert f.validation_status == "VALIDATED"


def test_false_positive_with_reason():
    f = make()
    assert f.transition("FALSE_POSITIVE", "confirmed test-only string, not reachable") is True
    assert f.validation_status == "FALSE_POSITIVE"


def test_roundtrip_dict():
    f = make(remediation="fix it")
    again = Finding.from_dict(json.loads(json.dumps(f.to_dict())))
    assert again.id == f.id
    assert again.remediation == "fix it"


def test_dedup_same_provenance_merges():
    f1 = make()
    f2 = make(id=stable_finding_id("sast.semgrep", "rule.a", "a.py", 1, "t"))
    merged, log = deduplicate([f1, f2])
    assert len(merged) == 1
    assert log and "Same detection source" in log[0]["reason"]


def test_dedup_keeps_distinct_rules_apart():
    f1 = make(rule_id="rule.a", title="A")
    f2 = make(rule_id="rule.b", title="A")  # same title, different rule
    merged, _ = deduplicate([f1, f2])
    assert len(merged) == 2  # titles alone must never merge findings


def test_dedup_cross_source_keeps_provenance():
    f1 = make(source="sast.semgrep")
    f2 = make(source="sast.bandit")  # different source -> different key
    merged, _ = deduplicate([f1, f2])
    assert len(merged) == 2


def test_priority_score_reasonable_and_documented():
    f = make(severity="critical", confidence="high", validation_status="VALIDATED")
    p = prioritise(f)
    assert 8.0 <= p["score"] <= 10.0
    assert p["assumptions"] == []
    assert "not a CVSS" in p["note"]


def test_priority_discounts_unvalidated_and_flags_assumptions():
    f = make(severity="critical", confidence="unknown", validation_status="DETECTED")
    p = prioritise(f)
    assert p["score"] < 9.0
    assert any("unknown" in a for a in p["assumptions"])


def test_false_positive_scores_zero():
    f = make(validation_status="FALSE_POSITIVE")
    assert prioritise(f)["score"] == 0.0


def test_unknown_severity_stays_unknown():
    f = make(severity="unknown", confidence="unknown")
    p = prioritise(f)
    assert any("Severity unknown" in a for a in p["assumptions"])
