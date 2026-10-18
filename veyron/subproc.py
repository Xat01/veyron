"""Safe subprocess execution for scanner adapters."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    args: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None


def run_command(
    args: list[str],
    *,
    timeout: int = 600,
    cwd: str | Path | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Run a command as an argument array — never through a shell.

    Returns a CommandResult capturing exit status, stdout, stderr, and
    timeout/failure information. Raises FileNotFoundError only through the
    returned result (`error`) so callers can distinguish missing executables.
    """
    if not args:
        return CommandResult(args=[], returncode=None, stdout="", stderr="", error="empty argument list")

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            input=input_text,
            shell=False,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(
            args=args, returncode=None, stdout="", stderr="",
            error=f"executable not found: {args[0]}",
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args=args,
            returncode=None,
            stdout=(exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            timed_out=True,
            error=f"timeout after {timeout}s",
        )
    except OSError as exc:
        return CommandResult(
            args=args, returncode=None, stdout="", stderr="", error=str(exc)
        )

    return CommandResult(
        args=args,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )


def which(executable: str) -> str | None:
    """Locate an executable on PATH, respecting .exe on Windows."""
    import shutil

    return shutil.which(executable)
