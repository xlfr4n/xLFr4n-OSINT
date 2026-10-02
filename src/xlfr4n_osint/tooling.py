from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from xlfr4n_osint.providers.base import ProviderError


class ExternalToolError(ProviderError):
    """Base error for an unavailable or failed external tool."""


class ExternalToolNotFoundError(ExternalToolError):
    """The configured executable is not available on PATH."""


class ExternalToolTimeoutError(ExternalToolError):
    """The external command exceeded its execution budget."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def run_external_command(
    argv: list[str],
    *,
    timeout: float,
    cwd: str | None = None,
) -> CommandResult:
    if not argv or not argv[0].strip():
        raise ValueError("external command cannot be empty")
    if timeout <= 0:
        raise ValueError("external command timeout must be greater than zero")

    executable = shutil.which(argv[0])
    if executable is None:
        raise ExternalToolNotFoundError(f"external tool not installed: {argv[0]}")

    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")

    try:
        completed = subprocess.run(
            [executable, *argv[1:]],
            cwd=cwd,
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolTimeoutError(
            f"external tool timed out after {timeout:.1f}s: {argv[0]}"
        ) from exc
    except OSError as exc:
        raise ExternalToolError(f"failed to execute {argv[0]}: {exc}") from exc

    return CommandResult(
        argv=tuple(argv),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
