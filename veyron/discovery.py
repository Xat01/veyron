"""Repository discovery: inventory files, languages, manifests, exclusions."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Set

from .constants import (
    DEFAULT_EXCLUDED_DIRECTORIES,
    DEFAULT_SUPPORTED_EXTENSIONS,
    SUPPORTED_MANIFEST_FILES,
)


@dataclass
class Component:
    """A detected repository component (language or dependency manifest)."""

    type: str  # "language" or "manifest"
    name: str
    path: Path | None = None
    evidence: str | None = None


@dataclass
class DiscoveryResult:
    root: Path
    files: list[Path] = field(default_factory=list)
    excluded_dirs: list[str] = field(default_factory=list)
    unsupported_extensions: set[str] = field(default_factory=set)
    components: list[Component] = field(default_factory=list)
    total_bytes: int = 0
    skipped_files: list[Path] = field(default_factory=list)

    def summary(self) -> dict:
        """Return a JSON-serialisable summary of the discovery result."""
        return {
            "root": str(self.root),
            "file_count": len(self.files),
            "total_bytes": self.total_bytes,
            "excluded_dirs": list(self.excluded_dirs),
            "skipped_files": [str(p.relative_to(self.root)) for p in self.skipped_files],
            "unsupported_extensions": sorted(self.unsupported_extensions),
            "components": [
                {"type": c.type, "name": c.name, "path": str(c.path) if c.path else None,
                 "evidence": c.evidence}
                for c in self.components
            ],
        }


class Discovery:
    """Inspects a local repository without executing any of its scripts."""

    def __init__(
        self,
        root: str | Path,
        *,
        excluded_directories: Set[str] | None = None,
        supported_extensions: Set[str] | None = None,
        max_file_size: int = 2_000_000,
        exclusions: list[str] | None = None,
    ):
        self.root = Path(root).resolve()
        self.excluded_directories = set(excluded_directories or DEFAULT_EXCLUDED_DIRECTORIES)
        self.supported_extensions = set(supported_extensions or DEFAULT_SUPPORTED_EXTENSIONS)
        self.max_file_size = max_file_size
        self.exclusions = [self._compile_glob(p) for p in (exclusions or [])]

    def _compile_glob(self, pattern: str):
        return pattern

    def _is_excluded(self, path: Path) -> bool:
        parts = set(path.relative_to(self.root).parts)
        if parts & self.excluded_directories:
            return True
        for pattern in self.exclusions:
            if fnmatch.fnmatch(str(path.relative_to(self.root)), pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
        return False

    def run(self) -> DiscoveryResult:
        result = DiscoveryResult(root=self.root)

        for path in sorted(self.root.rglob("*")):
            if path.is_dir():
                if path != self.root and self._is_excluded(path):
                    result.excluded_dirs.append(path.relative_to(self.root).as_posix())
                    continue
                continue

            if self._is_excluded(path):
                result.skipped_files.append(path)
                continue

            try:
                size = path.stat().st_size
            except OSError:
                result.skipped_files.append(path)
                continue

            if size > self.max_file_size:
                result.skipped_files.append(path)
                continue

            result.files.append(path)
            result.total_bytes += size

            ext = path.suffix.lower()
            if ext and ext not in self.supported_extensions:
                result.unsupported_extensions.add(ext)

        result.components = self._detect_components(result.files)
        return result

    def _detect_components(self, files: Iterable[Path]) -> list[Component]:
        components: list[Component] = []
        languages: dict[str, str] = {}
        manifest_seen: Set[str] = set()

        for path in files:
            ext = path.suffix.lower()
            if ext:
                languages.setdefault(ext, path.name)

            if path.name in SUPPORTED_MANIFEST_FILES and path.name not in manifest_seen:
                manifest_seen.add(path.name)
                components.append(
                    Component(
                        type="manifest",
                        name=path.name,
                        path=path,
                        evidence=f"Dependency manifest {path.name} detected",
                    )
                )

        for ext, sample in sorted(languages.items()):
            components.append(
                Component(type="language", name=ext.lstrip(".") or ext, path=None, evidence=f"Source file {sample} uses {ext}")
            )

        return components
