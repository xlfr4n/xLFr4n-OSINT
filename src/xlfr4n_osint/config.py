from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScanConfig:
    timeout: float = 10.0
    user_agent: str = "xLFr4n-OSINT/0.1.0"

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if not self.user_agent.strip():
            raise ValueError("user_agent cannot be empty")

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

        if "XLFR4N_OSINT_TIMEOUT" in os.environ:
            values["timeout"] = float(os.environ["XLFR4N_OSINT_TIMEOUT"])
        if "XLFR4N_OSINT_USER_AGENT" in os.environ:
            values["user_agent"] = os.environ["XLFR4N_OSINT_USER_AGENT"]

        return cls(
            timeout=float(values.get("timeout", cls.timeout)),
            user_agent=str(values.get("user_agent", cls.user_agent)),
        )
