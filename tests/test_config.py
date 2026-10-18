"""Configuration parsing, env overrides, validation, masking."""

import json

import pytest

from veyron.config import Config, AIConfig, _env_overrides


def test_defaults():
    cfg = Config()
    assert cfg.ai.enabled is True
    assert cfg.ai.base_url.startswith("http://")
    assert cfg.scanners.timeout_seconds > 0
    assert cfg.dast.max_requests > 0
    assert cfg.validate() == []


def test_load_missing_file_uses_defaults(tmp_path):
    cfg = Config.load(tmp_path / "nope.json")
    assert cfg.ai.model


def test_load_invalid_json_uses_defaults(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{not json", encoding="utf-8")
    cfg = Config.load(p)
    assert cfg.ai.enabled is True


def test_file_overrides(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "ai": {"enabled": False, "model": "unit-test-model"},
        "scanners": {"timeout_seconds": 123, "enabled": ["semgrep"]},
        "dast": {"max_requests": 7},
        "exclusions": ["tests/*"],
    }), encoding="utf-8")
    cfg = Config.load(p)
    assert cfg.ai.enabled is False
    assert cfg.ai.model == "unit-test-model"
    assert cfg.scanners.timeout_seconds == 123
    assert cfg.scanners.enabled == ["semgrep"]
    assert cfg.dast.max_requests == 7
    assert cfg.exclusions == ["tests/*"]


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("VEYRON_AI_ENABLED", "false")
    monkeypatch.setenv("VEYRON_AI_MODEL", "env-model")
    monkeypatch.setenv("VEYRON_SCANNER_TIMEOUT_SECONDS", "55")
    monkeypatch.setenv("VEYRON_DAST_ALLOWLIST", "127.0.0.1:9000, staging.local:80")
    monkeypatch.setenv("VEYRON_MAX_FILE_SIZE_BYTES", "1000")
    cfg = Config.load(None)
    assert cfg.ai.enabled is False
    assert cfg.ai.model == "env-model"
    assert cfg.scanners.timeout_seconds == 55
    assert cfg.scanners.max_file_size_bytes == 1000
    assert cfg.dast.allowlist == ["127.0.0.1:9000", "staging.local:80"]
    assert cfg.dast.enabled is True


def test_invalid_values_rejected():
    cfg = Config()
    cfg.ai.base_url = "ftp://bad"
    cfg.scanners.timeout_seconds = 0
    problems = cfg.validate()
    assert any("base_url" in p for p in problems)
    assert any("timeout_seconds" in p for p in problems)


def test_dast_allowlist_required_when_enabled():
    cfg = Config()
    cfg.dast.enabled = True
    cfg.dast.allowlist = []
    assert any("allowlist" in p for p in cfg.validate())


def test_api_key_masked_in_display():
    cfg = Config()
    cfg.ai.api_key = "super-secret-value-xyz"
    display = cfg.to_display()
    assert "super-secret-value-xyz" not in json.dumps(display)
    assert display["ai"]["api_key"] == "***"


def test_ai_masked_method():
    ai = AIConfig(api_key="leaked-key")
    assert "leaked-key" not in json.dumps(ai.masked())
