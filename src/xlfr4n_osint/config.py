from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


DEFAULT_TIMEOUT = 10.0
DEFAULT_USER_AGENT = "xLFr4n-OSINT/0.1.0"
DEFAULT_PROVIDER_WORKERS = 6
MAX_PROVIDER_WORKERS = 32


@dataclass(frozen=True, slots=True)
class ScanConfig:
    timeout: float = DEFAULT_TIMEOUT
    user_agent: str = DEFAULT_USER_AGENT
    provider_workers: int = DEFAULT_PROVIDER_WORKERS

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if not self.user_agent.strip():
            raise ValueError("user_agent cannot be empty")
        if not 1 <= self.provider_workers <= MAX_PROVIDER_WORKERS:
            raise ValueError(
                f"provider_workers must be between 1 and {MAX_PROVIDER_WORKERS}"
            )

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "ScanConfig":
        candidates: list[Path] = []
        if path is not None:
            candidates.append(Path(path).expanduser())
        else:
            candidates.append(
                Path.home() / ".config" / "xlfr4n-osint" / "config.toml"
            )

        values: dict[str, object] = {}
        for candidate in candidates:
            if not candidate.exists():
                continue
            with candidate.open("rb") as handle:
                payload = tomllib.load(handle)
            scan = payload.get("scan", {})
            if scan is None:
                scan = {}
            if not isinstance(scan, dict):
                raise ValueError("[scan] must be a TOML table")
            values.update(scan)
            break

        if "timeout" in values and not isinstance(values["timeout"], (int, float)):
            raise ValueError("scan.timeout must be numeric")
        if "user_agent" in values and not isinstance(values["user_agent"], str):
            raise ValueError("scan.user_agent must be a string")
        if "provider_workers" in values and not isinstance(values["provider_workers"], int):
            raise ValueError("scan.provider_workers must be an integer")

        if "XLFR4N_OSINT_TIMEOUT" in os.environ:
            values["timeout"] = float(os.environ["XLFR4N_OSINT_TIMEOUT"])
        if "XLFR4N_OSINT_USER_AGENT" in os.environ:
            values["user_agent"] = os.environ["XLFR4N_OSINT_USER_AGENT"]
        if "XLFR4N_OSINT_PROVIDER_WORKERS" in os.environ:
            values["provider_workers"] = int(
                os.environ["XLFR4N_OSINT_PROVIDER_WORKERS"]
            )

        return cls(
            timeout=float(values.get("timeout", DEFAULT_TIMEOUT)),
            user_agent=str(values.get("user_agent", DEFAULT_USER_AGENT)),
            provider_workers=int(
                values.get("provider_workers", DEFAULT_PROVIDER_WORKERS)
            ),
        )
