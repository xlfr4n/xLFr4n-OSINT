from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanConfig:
    timeout: float = 10.0
    user_agent: str = "xLFr4n-OSINT/0.1.0"

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if not self.user_agent.strip():
            raise ValueError("user_agent cannot be empty")
