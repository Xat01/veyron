"""Software Composition Analysis via the free OSV.dev API.

Manifests/lockfiles are parsed locally; advisories are queried against the
public OSV API (Google's free, open vulnerability database). Offline runs
fall back to a local cache and clearly mark results as cached.

Advisory presence is NOT exploitability: findings produced here are marked
ANALYSED at most, never VALIDATED.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..constants import DEFAULT_CACHE_DIR
from ..finding import Finding, stable_finding_id
from .base import ScannerAdapter, ScanResult

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
USER_AGENT = "veyron-sca/0.1 (+local security assessment tool)"


@dataclass
class Package:
    name: str
    version: str
    ecosystem: str
    manifest: Path
    source: str  # parsing rule used


@dataclass
class SCACache:
    path: Path
    entries: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "SCACache":
        entries: dict[str, Any] = {}
        try:
            if path.exists():
                entries = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            entries = {}
        return cls(path=path, entries=entries)

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.entries, indent=1), encoding="utf-8")
        except OSError:
            pass  # cache write failures must not break an assessment


def _parse_requirements(text: str, manifest: Path) -> list[Package]:
    pkgs: list[Package] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        if "==" in line:
            name, _, version = line.partition("==")
            name, version = name.strip(), version.strip()
            if name and version and "<" not in version and ">" not in version and "~" not in version and "*" not in version:
                pkgs.append(Package(name=name, version=version, ecosystem="PyPI", manifest=manifest, source="requirements.txt pin"))
    return pkgs


def _parse_package_json(text: str, manifest: Path) -> list[Package]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs: list[Package] = []
    deps = data.get("dependencies", {}) or {}
    if isinstance(deps, dict):
        for name, spec in deps.items():
            ver = str(spec).strip().lstrip("^~>=< ")
            if ver and all(c.isdigit() or c in ".-" for c in ver) and any(c.isdigit() for c in ver):
                pkgs.append(Package(name=name, version=ver, ecosystem="npm", manifest=manifest, source="package.json exact version"))
    return pkgs


def _parse_lockfile_package_json(text: str, manifest: Path) -> list[Package]:
    """Parse package-lock.json (lockfileVersion 2/3) into pinned packages."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs: list[Package] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path_key, meta in packages.items():
            if not path_key or not isinstance(meta, dict):
                continue
            name = path_key.split("node_modules/")[-1]
            version = meta.get("version")
            if name and version:
                pkgs.append(Package(name=name, version=str(version), ecosystem="npm", manifest=manifest, source="package-lock.json pin"))
    elif isinstance(data.get("dependencies"), dict):
        for name, meta in data["dependencies"].items():
            if isinstance(meta, dict) and meta.get("version"):
                pkgs.append(Package(name=name, version=str(meta["version"]), ecosystem="npm", manifest=manifest, source="package-lock.json pin"))
    return pkgs


def _parse_go_mod(text: str, manifest: Path) -> list[Package]:
    pkgs: list[Package] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            parts = line[len("require "):].split()
            if len(parts) >= 2:
                pkgs.append(Package(name=parts[0], version=parts[1], ecosystem="Go", manifest=manifest, source="go.mod require"))
            continue
        if in_block:
            parts = line.split()
            if len(parts) >= 2:
                pkgs.append(Package(name=parts[0], version=parts[1], ecosystem="Go", manifest=manifest, source="go.mod require"))
    return pkgs


MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_lockfile_package_json,
    "go.mod": _parse_go_mod,
}


class OSVAdapter(ScannerAdapter):
    name = "osv"
    kind = "sca"

    def __init__(self, *, executable: str | None = None, timeout: int = 60, config: dict[str, Any] | None = None):
        super().__init__(executable=executable or "osv", timeout=timeout, config=config)
        self.offline = bool(self.config.get("offline", False))
        self.cache = SCACache.load(Path(self.config.get("cache_path", DEFAULT_CACHE_DIR / "osv_cache.json")))

    def validate_config(self) -> tuple[bool, str | None]:
        # OSV adapter requires no local executable; network or cache needed.
        if self.offline and not self.cache.entries:
            return False, "OSV adapter offline but no advisory cache available"
        return True, None

    def version(self) -> str | None:
        return "osv.dev API (v1)"

    def scan(self, root: Path, files: list[Path] | None = None) -> ScanResult:
        started = time.monotonic()
        targets = files or [p for p in root.rglob("*") if p.is_file()]
        packages: list[Package] = []
        seen_manifests: set[Path] = set()
        for path in targets:
            if path.name not in MANIFEST_PARSERS:
                continue
            # Only parse manifests within root, skip nested build dirs.
            if any(part in {"node_modules", ".venv", "venv", "dist", "build"} for part in path.parts):
                continue
            if path in seen_manifests:
                continue
            seen_manifests.add(path)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            parser = MANIFEST_PARSERS[path.name]
            packages.extend(parser(text, path))

        if not packages:
            return ScanResult(scanner=self.name, ok=True, findings=[],
                              tool_version=self.version(),
                              duration_seconds=time.monotonic() - started,
                              metadata={"manifests_parsed": len(seen_manifests), "packages": 0,
                                        "database": "none required (no recognised packages)"})

        # Deduplicate on (ecosystem, name, version) for querying.
        unique = {(p.ecosystem, p.name, p.version): p for p in packages}
        results_meta: dict[str, Any] = {
            "manifests_parsed": len(seen_manifests),
            "packages": len(unique),
            "database": "live OSV API",
            "data_freshness": "live at scan time",
        }

        vulns_by_key: dict[tuple, list[dict[str, Any]]] = {}
        network_error: str | None = None

        if not self.offline:
            try:
                vulns_by_key = self._query_osv_batch(list(unique.keys()))
            except OSError as exc:
                network_error = str(exc)

        if network_error or self.offline:
            # Fall back to cache; be explicit that data may be stale.
            results_meta["database"] = "local cache"
            results_meta["data_freshness"] = "cached (may be stale — not current)"
            for key, entry in self.cache.entries.items():
                eco, name, ver = json.loads(key)
                vulns_by_key.setdefault((eco, name, ver), entry.get("vulns", []))
            if network_error:
                results_meta["network_error"] = network_error[:300]

        findings: list[Finding] = []
        for key, pkg in unique.items():
            for vuln in vulns_by_key.get(key, []):
                f = self._to_finding(pkg, vuln, results_meta)
                if f:
                    findings.append(f)

        return ScanResult(
            scanner=self.name, ok=True, findings=findings,
            tool_version=self.version(), duration_seconds=time.monotonic() - started,
            metadata=results_meta,
        )

    # -- OSV HTTP -------------------------------------------------------------

    def _query_osv_batch(self, keys: list[tuple]) -> dict[tuple, list[dict[str, Any]]]:
        out: dict[tuple, list[dict[str, Any]]] = {}
        chunk_size = 500
        for i in range(0, len(keys), chunk_size):
            chunk = keys[i:i + chunk_size]
            body = json.dumps({
                "queries": [
                    {"package": {"name": n, "ecosystem": e}, "version": v}
                    for (e, n, v) in chunk
                ]
            }).encode("utf-8")
            req = urllib.request.Request(OSV_BATCH_URL, data=body, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            results = payload.get("results", [])
            for key, res in zip(chunk, results):
                vulns = res.get("vulns", []) or []
                # querybatch returns minimal vuln objects; enrich lazily.
                enriched = [self._enrich(v.get("id", "")) for v in vulns]
                out[key] = [v for v in enriched if v]
                self.cache.entries[json.dumps(list(key))] = {"vulns": out[key], "at": int(time.time())}
        self.cache.save()
        return out

    def _enrich(self, vuln_id: str) -> dict[str, Any] | None:
        cache_key = f"vuln::{vuln_id}"
        if cache_key in self.cache.entries:
            return self.cache.entries[cache_key]
        try:
            req = urllib.request.Request(OSV_VULN_URL.format(id=vuln_id), headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (OSError, json.JSONDecodeError, urllib.error.URLError):
            return {"id": vuln_id, "summary": "", "enriched": False}
        self.cache.entries[cache_key] = data
        self.cache.save()
        return data

    # -- normalisation --------------------------------------------------------

    def _to_finding(self, pkg: Package, vuln: dict[str, Any], meta: dict[str, Any]) -> Finding | None:
        vuln_id = vuln.get("id") or ""
        if not vuln_id:
            return None
        summary = (vuln.get("summary") or "").strip()
        title = summary or f"{pkg.name} {pkg.version} affected by {vuln_id}"
        severity = "unknown"
        for sev in vuln.get("severity", []) or []:
            # OSV severity entries carry a score string (often CVSS); we do
            # not fabricate CVSS numbers — only carry the vector if present.
            if isinstance(sev, dict) and sev.get("score"):
                severity = "unknown"
                break
        db_specific = vuln.get("database_specific", {}) or {}
        if db_specific.get("severity"):
            sev_text = str(db_specific["severity"]).lower()
            if sev_text in {"critical", "high", "medium", "low"}:
                severity = sev_text
        affected_desc = ""
        for aff in vuln.get("affected", []) or []:
            pkg_meta = aff.get("package", {}) or {}
            if pkg_meta.get("name") == pkg.name:
                for rng in aff.get("ranges", []) or []:
                    fixed = [ev.get("fixed") for ev in rng.get("events", []) if isinstance(ev, dict) and ev.get("fixed")]
                    if fixed:
                        affected_desc = f"fixed in {fixed[-1]}"
                    break
        fid = stable_finding_id("sca.osv", vuln_id, str(pkg.manifest), None, title)
        refs = [r.get("url", "") for r in vuln.get("references", []) if isinstance(r, dict)][:8]
        return Finding(
            id=fid,
            title=title[:200],
            description=(
                f"Package {pkg.name} {pkg.version} ({pkg.ecosystem}) matches advisory {vuln_id}. "
                f"{affected_desc}. Detection source: {meta.get('database', 'OSV')}, "
                f"{meta.get('data_freshness', '')}. Advisory match only — exploitability in this "
                "application's configuration has not been established."
            ).strip(),
            category="vulnerable-dependency",
            severity=severity,
            confidence="medium",
            validation_status="ANALYSED",  # advisory match ≠ exploitable
            source="sca.osv",
            file_path=str(pkg.manifest),
            line=None,
            evidence=f"ecosystem={pkg.ecosystem}\npackage={pkg.name}\nversion={pkg.version}\n"
                     f"parsed_from={pkg.source}\nadvisory={vuln_id}\n{affected_desc}".strip(),
            remediation=f"Upgrade {pkg.name} to {affected_desc.replace('fixed in ', '')} or later."
                        if affected_desc.startswith("fixed in") else
                        f"Review advisory {vuln_id} for a fixed version or mitigation.",
            rule_id=vuln_id,
            tool="osv",
            advisory_refs=refs + ([f"OSV:{vuln_id}"] if vuln_id else []),
            raw={"osv_id": vuln_id, "summary": summary, "freshness": meta.get("data_freshness"),
                 "package": {"name": pkg.name, "version": pkg.version, "ecosystem": pkg.ecosystem}},
        )
