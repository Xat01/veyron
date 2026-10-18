"""Configuration loading: file + environment overrides.

Precedence: CLI flags > environment variables > config file > defaults.
Secrets (API keys) are accepted but never printed by the application.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_AI_MAX_RETRIES,
    DEFAULT_AI_TIMEOUT_SECONDS,
    DEFAULT_DASHBOARD_HOST,
    DEFAULT_DASHBOARD_PORT,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_SCANNER_TIMEOUT_SECONDS,
    ENV_PREFIX,
)


@dataclass
class AIConfig:
    enabled: bool = True
    base_url: str = "http://localhost:3103/v1"
    api_key: str = "local-omniroute"
    model: str = "free-reliable"
    timeout_seconds: int = DEFAULT_AI_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_AI_MAX_RETRIES

    def masked(self) -> dict[str, Any]:
        """Config safe for display/logging: key is masked, never shown."""
        d = asdict(self)
        d["api_key"] = "***" if self.api_key else "(unset)"
        return d


@dataclass
class ScannerConfig:
    timeout_seconds: int = DEFAULT_SCANNER_TIMEOUT_SECONDS
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    semgrep_path: str | None = None
    bandit_path: str | None = None
    gitleaks_path: str | None = None
    semgrep_config: str = "p/default"
    gitleaks_scan_history: bool = False
    osv_offline: bool = False
    enabled: list[str] = field(default_factory=lambda: ["semgrep", "bandit", "gitleaks", "osv"])


@dataclass
class DASTConfig:
    """Controlled dynamic testing — allowlist-first, budget-bound."""

    enabled: bool = False
    allowlist: list[str] = field(default_factory=lambda: ["127.0.0.1:8080", "localhost:8080"])
    max_requests: int = 200
    max_minutes: int = 30
    max_concurrency: int = 2
    follow_redirects: bool = False
    dry_run: bool = True
    rate_limit_per_second: float = 2.0


@dataclass
class Config:
    ai: AIConfig = field(default_factory=AIConfig)
    scanners: ScannerConfig = field(default_factory=ScannerConfig)
    dast: DASTConfig = field(default_factory=DASTConfig)
    exclusions: list[str] = field(default_factory=list)
    dashboard_host: str = DEFAULT_DASHBOARD_HOST
    dashboard_port: int = DEFAULT_DASHBOARD_PORT
    # Defaults resolved at instantiation (not import), so environment/config
    # redirection at runtime is honoured.
    reports_dir: Path | None = None
    history_path: Path | None = None

    def __post_init__(self) -> None:
        if self.reports_dir is None:
            self.reports_dir = Path.home() / ".veyron" / "reports"
        if self.history_path is None:
            self.history_path = Path.home() / ".veyron" / "data" / "history.jsonl"

    # -- constructors ---------------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        cfg = cls()
        config_path = Path(path) if path else Path.home() / ".veyron" / "config.json"
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                data = {}
            cfg._apply(data)
        cfg._apply(_env_overrides())
        return cfg

    def _apply(self, data: dict[str, Any]) -> None:
        if not isinstance(data, dict):
            return
        ai = data.get("ai")
        if isinstance(ai, dict):
            for k in ("enabled", "base_url", "api_key", "model", "timeout_seconds", "max_retries"):
                if k in ai:
                    setattr(self.ai, k, ai[k])
        sc = data.get("scanners")
        if isinstance(sc, dict):
            for k in ("timeout_seconds", "max_file_size_bytes", "semgrep_path", "bandit_path",
                      "gitleaks_path", "semgrep_config", "gitleaks_scan_history", "osv_offline", "enabled"):
                if k in sc:
                    setattr(self.scanners, k, sc[k])
        da = data.get("dast")
        if isinstance(da, dict):
            for k in ("enabled", "allowlist", "max_requests", "max_minutes",
                      "max_concurrency", "follow_redirects", "dry_run", "rate_limit_per_second"):
                if k in da:
                    setattr(self.dast, k, da[k])
        for key in ("exclusions", "dashboard_host", "dashboard_port"):
            if key in data:
                setattr(self, key, data[key])
        if "reports_dir" in data:
            self.reports_dir = Path(data["reports_dir"])
        if "history_path" in data:
            self.history_path = Path(data["history_path"])

    # -- persistence ----------------------------------------------------------

    def save(self, path: str | Path | None = None) -> Path:
        config_path = Path(path) if path else Path.home() / ".veyron" / "config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            # API key written to a local, permission-restricted file only.
            "ai": asdict(self.ai),
            "scanners": asdict(self.scanners),
            "dast": asdict(self.dast),
            "exclusions": self.exclusions,
            "dashboard_host": self.dashboard_host,
            "dashboard_port": self.dashboard_port,
            "reports_dir": str(self.reports_dir),
        }
        config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            os.chmod(config_path, 0o600)
        except OSError:
            pass  # Windows may not honour POSIX perms
        return config_path

    # -- validation -----------------------------------------------------------

    def validate(self) -> list[str]:
        problems: list[str] = []
        if self.ai.enabled:
            if not self.ai.base_url.startswith(("http://", "https://")):
                problems.append("ai.base_url must be an http(s) URL")
            if not self.ai.model:
                problems.append("ai.model must not be empty when AI is enabled")
            if not (1 <= self.ai.timeout_seconds <= 600):
                problems.append("ai.timeout_seconds must be between 1 and 600")
        if self.scanners.timeout_seconds <= 0:
            problems.append("scanners.timeout_seconds must be > 0")
        if self.scanners.max_file_size_bytes <= 0:
            problems.append("scanners.max_file_size_bytes must be > 0")
        if self.dast.enabled:
            if not self.dast.allowlist:
                problems.append("dast.allowlist must contain at least one host:port when DAST is enabled")
            if self.dast.max_requests <= 0:
                problems.append("dast.max_requests must be > 0")
            if self.dast.max_concurrency < 1:
                problems.append("dast.max_concurrency must be >= 1")
        return problems

    def to_display(self) -> dict[str, Any]:
        """Configuration for display: API key masked."""
        return {
            "ai": self.ai.masked(),
            "scanners": asdict(self.scanners),
            "dast": asdict(self.dast),
            "exclusions": self.exclusions,
            "dashboard_host": self.dashboard_host,
            "dashboard_port": self.dashboard_port,
            "reports_dir": str(self.reports_dir),
        }


def _env_overrides() -> dict[str, Any]:
    """Build a config dict from VEYRON_* environment variables."""

    def get(name: str, default: Any = None) -> Any:
        return os.environ.get(ENV_PREFIX + name, default)

    data: dict[str, Any] = {"ai": {}, "scanners": {}, "dast": {}}
    if (v := get("AI_ENABLED")) is not None:
        data["ai"]["enabled"] = v.strip().lower() in {"1", "true", "yes", "on"}
    for env_key, cfg_key, cast in [
        ("AI_BASE_URL", "base_url", str),
        ("AI_API_KEY", "api_key", str),
        ("AI_MODEL", "model", str),
        ("AI_TIMEOUT_SECONDS", "timeout_seconds", int),
        ("AI_MAX_RETRIES", "max_retries", int),
    ]:
        if (v := get(env_key)) is not None:
            try:
                data["ai"][cfg_key] = cast(v)
            except ValueError:
                pass
    if (v := get("SCANNER_TIMEOUT_SECONDS")) is not None:
        try:
            data["scanners"]["timeout_seconds"] = int(v)
        except ValueError:
            pass
    if (v := get("MAX_FILE_SIZE_BYTES")) is not None:
        try:
            data["scanners"]["max_file_size_bytes"] = int(v)
        except ValueError:
            pass
    for env_key, cfg_key in [("SEMGREP_PATH", "semgrep_path"), ("BANDIT_PATH", "bandit_path"),
                             ("GITLEAKS_PATH", "gitleaks_path")]:
        if (v := get(env_key)) is not None:
            data["scanners"][cfg_key] = v
    if (v := get("DAST_ALLOWLIST")) is not None:
        data["dast"]["allowlist"] = [x.strip() for x in v.split(",") if x.strip()]
        data["dast"]["enabled"] = True
    for env_key, cfg_key, cast in [
        ("DAST_MAX_REQUESTS", "max_requests", int),
        ("DAST_MAX_MINUTES", "max_minutes", int),
        ("DAST_MAX_CONCURRENCY", "max_concurrency", int),
    ]:
        if (v := get(env_key)) is not None:
            try:
                data["dast"][cfg_key] = cast(v)
            except ValueError:
                pass
    if (v := get("DAST_FOLLOW_REDIRECTS")) is not None:
        data["dast"]["follow_redirects"] = v.strip().lower() in {"1", "true", "yes"}
    return {k: v for k, v in data.items() if v}
