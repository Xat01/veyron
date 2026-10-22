"""Adapter registry — resolves scanner availability and versions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .adapters.bandit import BanditAdapter
from .adapters.base import ScannerAdapter
from .adapters.gitleaks import GitleaksAdapter
from .adapters.osv import OSVAdapter
from .adapters.semgrep import SemgrepAdapter
from .config import Config


def build_adapters(cfg: Config) -> dict[str, ScannerAdapter]:
    """Instantiate enabled scanner adapters from configuration."""
    sc = cfg.scanners
    all_adapters: dict[str, ScannerAdapter] = {
        "semgrep": SemgrepAdapter(executable=sc.semgrep_path, timeout=sc.timeout_seconds,
                                  config={"config": sc.semgrep_config}),
        "bandit": BanditAdapter(executable=sc.bandit_path, timeout=sc.timeout_seconds),
        "gitleaks": GitleaksAdapter(executable=sc.gitleaks_path, timeout=sc.timeout_seconds,
                                    config={"scan_history": sc.gitleaks_scan_history}),
        "osv": OSVAdapter(timeout=min(sc.timeout_seconds, 60),
                          config={"offline": sc.osv_offline or cfg.offline,
                                  "base_url": sc.osv_base_url}),
    }
    return {name: adapter for name, adapter in all_adapters.items() if name in sc.enabled}


def availability_report(cfg: Config) -> dict[str, dict[str, Any]]:
    """Report per-scanner availability, version, and reason when unavailable."""
    report: dict[str, dict[str, Any]] = {}
    for name, adapter in build_adapters(cfg).items():
        ok, reason = adapter.validate_config()
        report[name] = {
            "available": ok,
            "kind": adapter.kind,
            "version": adapter.version() if ok else None,
            "reason": None if ok else reason,
        }
    return report
