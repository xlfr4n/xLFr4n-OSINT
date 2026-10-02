from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Finding:
    source: str
    category: str
    identifier: str
    title: str
    url: str
    observed_at: str
    confidence: str = "unknown"
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(cls, **kwargs: Any) -> "Finding":
        return cls(observed_at=datetime.now(timezone.utc).isoformat(), **kwargs)


@dataclass(slots=True)
class ScanReport:
    query: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "findings": [
                {
                    "source": item.source,
                    "category": item.category,
                    "identifier": item.identifier,
                    "title": item.title,
                    "url": item.url,
                    "observed_at": item.observed_at,
                    "confidence": item.confidence,
                    "data": item.data,
                }
                for item in self.findings
            ],
            "errors": self.errors,
        }
