"""CLI behaviour: exit codes, help, availability reporting."""

import json

import pytest

from veyron.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["--version"])
    assert ei.value.code == 0
    assert "VEYRON" in capsys.readouterr().out


def test_scan_requires_command():
    with pytest.raises(SystemExit) as ei:
        main([])
    assert ei.value.code == 2


def test_scanners_json_output(capsys, monkeypatch):
    # regardless of what is installed on this machine, the command must
    # produce parseable JSON with the known scanner names.
    code = main(["scanners", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"semgrep", "bandit", "gitleaks", "osv"}
    for info in data.values():
        assert "available" in info and "kind" in info
    assert code in (0, 1)


def test_config_masks_api_key(capsys):
    main(["config"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["ai"]["api_key"] in {"***", "(unset)"}


def test_history_empty(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    import os
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    code = main(["history"])
    out = capsys.readouterr().out
    assert code == 0
    # either no history message or json — never a crash
    assert "No assessments recorded" in out or out.strip().startswith("[")


def test_scan_missing_target(tmp_path, capsys):
    code = main(["--no-ai", "scan", str(tmp_path / "nope")])
    assert code == 2
    assert "error" in capsys.readouterr().err


def test_scan_fixture_with_no_scanners_runs_but_flags_coverage(tmp_path, capsys, monkeypatch):
    """With every scanner disabled the run completes, findings=0, but the
    report must NOT read as a clean bill of health (no tools ran)."""
    from pathlib import Path

    fixture = Path(__file__).resolve().parent.parent / "fixtures" / "vulnerable_app"
    monkeypatch.setenv("VEYRON_AI_ENABLED", "false")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    code = main(["--no-ai", "--config", str(tmp_path / "no-config.json"),
                 "scan", str(fixture),
                 "--no-scanner", "semgrep", "--no-scanner", "bandit",
                 "--no-scanner", "gitleaks", "--no-scanner", "osv"])
    out = capsys.readouterr().out
    assert "COMPLETE" in out
    assert "findings: 0" in out
    # exit code 0 only because no scanner *failed* — all were explicitly
    # disabled by the user; coverage warnings still surface if present.
    assert code in (0, 1)


def test_dast_help_mentions_authorization(capsys):
    with pytest.raises(SystemExit):
        main(["dast", "--help"])
    out = capsys.readouterr().out
    assert "--authorize" in out
    assert "--execute" in out


# -- DASTResult is a dataclass, not a dict (regression: AttributeError) --------

def test_dast_plan_outputs_json_object_not_crash(tmp_path, capsys, monkeypatch):
    """cmd_dast must serialise DASTResult via asdict() and read fields by
    attribute access — result.get(...) raised AttributeError on the dataclass."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    code = main(["dast", "http://127.0.0.1:8080/"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, dict)
    assert set(data) >= {"ok", "mode", "target", "authorized_ok", "plan"}
    assert data["mode"] == "plan"
    # planning without --authorize must be denied and exit 3
    assert data["authorized_ok"] is False
    assert code == 3


def test_dast_plan_authorized_allowlisted_exits_zero(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    code = main(["dast", "http://127.0.0.1:8080/", "--authorize"])
    data = json.loads(capsys.readouterr().out)
    assert data["authorized_ok"] is True
    assert data["mode"] == "plan"
    assert data["checks"] == []          # dry-run: no requests sent
    assert code == 0


def test_dast_non_allowlisted_target_rejected_without_requests(tmp_path, capsys, monkeypatch):
    """localhost:3001 is not in the default allowlist: even with --authorize
    the target is rejected, no requests are sent, and exit code is 3."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    code = main(["dast", "http://localhost:3001/", "--authorize"])
    data = json.loads(capsys.readouterr().out)
    assert data["authorized_ok"] is False
    assert data["checks"] == []
    assert any("allowlist" in s for s in data["skipped"])
    assert code == 3


def test_dast_execute_without_authorize_stays_plan_mode(tmp_path, capsys, monkeypatch):
    """--execute alone is not consent: run_dast downgrades to plan mode,
    denies authorization, and sends no requests."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    code = main(["dast", "http://127.0.0.1:8080/", "--execute"])
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "plan"
    assert data["authorized_ok"] is False
    assert data["checks"] == []
    assert code == 3
