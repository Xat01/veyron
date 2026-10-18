"""Scanner adapter contract and shared result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..finding import Finding


@dataclass
class ScanResult:
    """Outcome of a single scanner invocation.

    Distinguishes scanner failure from a clean result (spec 6.2):
    ``ok=False`` means the scanner did not complete; findings from a failed
    scan must not be reported as "clean".
    """

    scanner: str
    ok: bool
    findings: list[Finding] = field(default_factory=list)
    tool_version: str | None = None
    duration_seconds: float = 0.0
    error: str | None = None
    failure_kind: str | None = None  # "missing_executable" | "timeout" | "nonzero_exit" | "malformed_output" | "config"
    exit_code: int | None = None
    raw_output: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ScannerAdapter:
    """Base class for scanner adapters.

    Every adapter must:
      1. validate its configuration,
      2. invoke the scanner safely (argument arrays),
      3. capture exit status and output,
      4. parse supported structured output,
      5. handle missing executables,
      6. handle timeouts,
      7. handle malformed output,
      8. distinguish scanner failure from a clean result,
      9. record scanner version and execution metadata,
      10. preserve original evidence.
    """

    name: str = "base"
    kind: str = "generic"  # "sast" | "sca" | "secret" | "dynamic"

    def __init__(self, *, executable: str | None = None, timeout: int = 600, config: dict[str, Any] | None = None):
        self.executable = executable
        self.timeout = timeout
        self.config = dict(config or {})

    # -- contract -------------------------------------------------------------

    def validate_config(self) -> tuple[bool, str | None]:
        """Return (valid, reason). Default: executable must be resolvable."""
        return (True, None)

    def available(self) -> bool:
        ok, _ = self.validate_config()
        return ok

    def version(self) -> str | None:
        return None

    def scan(self, root: Path, files: list[Path] | None = None) -> ScanResult:
        raise NotImplementedError
