"""VEYRON command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__
from .ai import AIAdapter
from .config import Config
from .constants import APP_DISPLAY_NAME, APP_DESCRIPTION
from .finding import prioritise
from .net.diagnostics import probe_proxy_route, proxy_status
from .orchestrator import Orchestrator
from .registry import availability_report
from .redact import redact_text


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="veyron",
        description=f"{APP_DISPLAY_NAME} — {APP_DESCRIPTION}",
    )
    p.add_argument("--version", action="version", version=f"{APP_DISPLAY_NAME} {__version__}")
    p.add_argument("--config", metavar="PATH", default=None,
                   help="Path to a config JSON file (default: ~/.veyron/config.json)")
    p.add_argument("--no-ai", action="store_true", help="Disable AI assistance for this run")

    # Shared per-command flags (parent parser; must come AFTER the subcommand).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="Machine-readable output where supported")

    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run an assessment against a local repository", parents=[common])
    scan.add_argument("target", metavar="PATH", help="Path to the repository to assess")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="Glob pattern to exclude (repeatable)")
    scan.add_argument("--format", choices=["markdown", "json", "sarif", "all"], default="all")
    scan.add_argument("--offline-sca", action="store_true",
                      help="Do not query OSV API; use local cache only")
    scan.add_argument("--no-scanner", action="append", default=[], metavar="NAME",
                      help="Disable a scanner for this run (repeatable: semgrep, bandit, gitleaks, osv)")

    sub.add_parser("doctors", help="Check scanner availability, AI health, and configuration", parents=[common])
    sub.add_parser("scanners", help="List scanner availability and versions", parents=[common])
    sub.add_parser("history", help="Show local assessment history", parents=[common])
    sub.add_parser("config", help="Show effective configuration (secrets masked)", parents=[common])

    ai = sub.add_parser("ai", help="AI integration utilities")
    ai_sub = ai.add_subparsers(dest="ai_command", required=True)
    ai_sub.add_parser("status", help="Probe AI provider health (minimal request)", parents=[common])
    ai_sub.add_parser("models", help="Show configured AI model", parents=[common])

    dash = sub.add_parser("dashboard", help="Launch the local web dashboard", parents=[common])
    dash.add_argument("--host", default=None, help="Bind address (default 127.0.0.1)")
    dash.add_argument("--port", type=int, default=None, help="Port (default 8732)")

    proxy = sub.add_parser("proxy", help="Proxy configuration and diagnostics")
    proxy_sub = proxy.add_subparsers(dest="proxy_command", required=True)
    proxy_sub.add_parser("status", help="Show proxy configuration and reachability", parents=[common])
    proxy_probe = proxy_sub.add_parser("probe", help="Send a request through the configured proxy", parents=[common])
    proxy_probe.add_argument("url", help="URL to request via the shared client")
    proxy_probe.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification (explicit only)")

    dast = sub.add_parser("dast", help="Controlled dynamic testing (authorised targets only)", parents=[common])
    dast.add_argument("target_url", nargs="?", default=None,
                      help="Authorised target URL (must be allowlisted; localhost by default)")
    dast.add_argument("--plan", action="store_true", default=True,
                      help="Planning/dry-run mode: show the plan, send no requests (default)")
    dast.add_argument("--execute", action="store_true",
                      help="Actually execute safe checks against the authorised target")
    dast.add_argument("--authorize", action="store_true",
                      help="Confirm you are authorised to test the target")
    return p


def _print(msg: str) -> None:
    print(redact_text(msg))


def cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    formats = ("markdown", "json", "sarif") if args.format == "all" else (args.format,)
    if args.no_ai:
        cfg.ai.enabled = False
    if args.offline_sca:
        cfg.scanners.osv_offline = True
    if args.exclude:
        cfg.exclusions = list(cfg.exclusions) + list(args.exclude)
    if args.no_scanner:
        cfg.scanners.enabled = [s for s in cfg.scanners.enabled if s not in set(args.no_scanner)]

    target = Path(args.target)
    _print(f"{APP_DISPLAY_NAME} {__version__} — assessing {target}")

    orch = Orchestrator(cfg, progress=_print)
    try:
        outcome = orch.run(target, formats=formats)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    counts = outcome.context.get("severity_counts", {})
    status = "INTERRUPTED" if outcome.interrupted else "COMPLETE"
    _print("")
    _print(f"Assessment {outcome.assessment_id} {status} in {outcome.duration_seconds:.1f}s")
    _print(f"  findings: {len(outcome.findings)} "
           + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    failed = [t for t in outcome.scan_results if not t.get("ok")]
    if failed:
        _print("  scanner failures:")
        for t in failed:
            _print(f"    - {t['scanner']}: {t.get('failure_kind')} ({t.get('error')})")
    if outcome.context.get("coverage_warning"):
        _print(f"  coverage warning: {outcome.context['coverage_warning']}")
    for fmt, path in outcome.reports.items():
        _print(f"  {fmt}: {path}")

    # Non-zero exit when scan infrastructure failed, so CI can trust green.
    if failed:
        return 1
    return 0


def cmd_scanners(args: argparse.Namespace, cfg: Config) -> int:
    report = availability_report(cfg)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    for name, info in report.items():
        mark = "[+]" if info["available"] else "[-]"
        line = f"{mark} {name:<10} [{info['kind']}]"
        if info["available"]:
            line += f" version: {info['version'] or 'unknown'}"
        else:
            line += f" — {info['reason']}"
        print(line)
    return 0 if all(i["available"] for i in report.values()) else 1


def cmd_doctors(args: argparse.Namespace, cfg: Config) -> int:
    ok_all = True
    print(f"{APP_DISPLAY_NAME} {__version__} — environment check")
    print("")
    print("Scanners:")
    report = availability_report(cfg)
    for name, info in report.items():
        mark = "[+]" if info["available"] else "[-]"
        detail = info["version"] or info["reason"] or ""
        print(f"  {mark} {name:<10} {detail}")
        ok_all = ok_all and info["available"]

    print("")
    print("AI integration:")
    ai = AIAdapter(cfg.ai)
    if not cfg.ai.enabled:
        print("  - AI disabled by configuration (deterministic analysis still works)")
    else:
        res = ai.healthcheck()
        if res.ok:
            print(f"  [+] reachable, model={res.model} ({res.duration_seconds:.1f}s)")
        else:
            print(f"  [-] {res.failure_kind}: {res.error}")
            print("    (VEYRON scanning works without AI)")
            ok_all = False

    print("")
    print("Configuration:")
    problems = cfg.validate()
    if problems:
        for prob in problems:
            print(f"  [-] {prob}")
        ok_all = False
    else:
        print("  [+] valid")

    print("")
    print("Dynamic testing:")
    if cfg.dast.enabled:
        print(f"  enabled, allowlist={cfg.dast.allowlist}, dry_run={cfg.dast.dry_run}, "
              f"budget={cfg.dast.max_requests} req / {cfg.dast.max_minutes} min")
    else:
        print("  disabled (run `veyron dast --help` to configure authorised targets)")
    return 0 if ok_all else 1


def cmd_history(args: argparse.Namespace, cfg: Config) -> int:
    if not cfg.history_path.exists():
        print("No assessments recorded yet.")
        return 0
    entries: list[dict[str, Any]] = []
    for line in cfg.history_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    for e in entries[-20:]:
        flag = "! partial" if e.get("interrupted") else "complete"
        sev = " ".join(f"{k}={v}" for k, v in sorted((e.get("severity_counts") or {}).items()))
        failed = f" failed_scanners={e.get('failed_scanners')}" if e.get("failed_scanners") else ""
        print(f"{e.get('assessment_id')}  {e.get('generated_at')}  {flag}  "
              f"findings={e.get('findings')} [{sev}]{failed}")
        print(f"  target: {e.get('target')}")
    return 0


def cmd_config(args: argparse.Namespace, cfg: Config) -> int:
    payload = cfg.to_display()
    print(json.dumps(payload, indent=2, default=str))
    return 0


def cmd_ai(args: argparse.Namespace, cfg: Config) -> int:
    ai = AIAdapter(cfg.ai)
    if args.ai_command == "status":
        res = ai.healthcheck()
        payload = {
            "enabled": cfg.ai.enabled,
            "base_url": cfg.ai.base_url,
            "model": cfg.ai.model,
            "ok": res.ok,
            "failure_kind": res.failure_kind,
            "error": res.error,
            "latency_seconds": round(res.duration_seconds, 2),
        }
        print(json.dumps(payload, indent=2))
        return 0 if res.ok else 1
    if args.ai_command == "models":
        print(json.dumps({"configured_model": cfg.ai.model,
                          "base_url": cfg.ai.base_url,
                          "note": "Route must resolve to a verified free model at the gateway."},
                         indent=2))
        return 0
    return 2


def cmd_dast(args: argparse.Namespace, cfg: Config) -> int:
    from .dast import run_dast

    if not args.target_url:
        print("error: target URL required", file=sys.stderr)
        return 2
    execute = bool(args.execute)
    result = run_dast(
        cfg.dast,
        target_url=args.target_url,
        execute=execute,
        authorized=bool(args.authorize),
    )
    # DASTResult is a dataclass: serialise with asdict() and read fields
    # via attribute access (there is no .get()).
    print(json.dumps(asdict(result), indent=2, default=str))
    if not result.authorized_ok:
        return 3
    if not execute:
        return 0
    return 0 if result.ok else 1


def cmd_proxy(args: argparse.Namespace, cfg: Config) -> int:
    if args.proxy_command == "status":
        status = proxy_status(
            cfg.proxy, proxy_bypass_loopback=cfg.network.proxy_bypass_loopback
        )
        if getattr(args, "json", False):
            print(json.dumps(status, indent=2, default=str))
        else:
            _print(f"{APP_DISPLAY_NAME} - proxy status")
            _print(f"  configured: {status['proxy_configured']}")
            _print(f"  routing: {status['routing']}")
            _print(f"  configured_proxy: {status['configured_proxy'].get('endpoint') or '(none)'}")
            _print(f"  has_credentials: {status['configured_proxy'].get('has_credentials')}")
            _print(f"  tor_mode: {status['tor_mode']}")
            _print(f"  reachable: {status['reachable']}")
            if status.get("reachability_error"):
                _print(f"  reachability_error: {status['reachability_error']}")
            _print(f"  direct_fallback_possible: {status['direct_fallback_possible']}")
            _print(f"  loopback_bypasses_proxy: {status['loopback_bypasses_proxy']}")
            for note in status.get("limitations", []):
                _print(f"  - {note}")
        return 0

    if args.proxy_command == "probe":
        if not cfg.proxy.configured:
            print("error: no proxy configured (set proxy.url or VEYRON_PROXY_URL)", file=sys.stderr)
            return 2
        result = probe_proxy_route(
            cfg.proxy,
            args.url,
            timeout=cfg.network.timeout_seconds,
            verify_tls=not args.no_verify_tls,
            proxy_bypass_loopback=cfg.network.proxy_bypass_loopback,
        )
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2, default=str))
        else:
            _print(f"{APP_DISPLAY_NAME} - proxy probe")
            _print(f"  url: {result['url']}")
            _print(f"  ok: {result['ok']}")
            _print(f"  status: {result['status']}")
            _print(f"  via_proxy: {result['via_proxy']}")
            _print(f"  direct_fallback_possible: {result['direct_fallback_possible']}")
            if result.get("error"):
                _print(f"  error: {result['error']} ({result.get('error_kind')})")
            _print(f"  stats: {result['stats']}")
        return 0 if result.get("ok") else 1

    parser = _build_parser()
    parser.parse_args(["proxy", "--help"])
    return 2


def cmd_dashboard(args: argparse.Namespace, cfg: Config) -> int:
    from .dashboard import serve

    host = args.host or cfg.dashboard_host
    port = args.port or cfg.dashboard_port
    return serve(cfg, host=host, port=port)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    cfg = Config.load(args.config)

    handlers = {
        "scan": cmd_scan,
        "doctors": cmd_doctors,
        "scanners": cmd_scanners,
        "history": cmd_history,
        "config": cmd_config,
        "ai": cmd_ai,
        "proxy": cmd_proxy,
        "dashboard": cmd_dashboard,
        "dast": cmd_dast,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args, cfg)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
