from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


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
    provenance: dict[str, str] = field(default_factory=dict)

    @classmethod
    def now(cls, **kwargs: Any) -> "Finding":
        return cls(observed_at=datetime.now(timezone.utc).isoformat(), **kwargs)


@dataclass(slots=True)
class ScanReport:
    query: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    provider_runs: list[dict[str, Any]] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: uuid4().hex)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.2",
            "scan_id": self.scan_id,
            "query": self.query,
            "started_at": self.started_at,
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
                    "provenance": item.provenance,
                }
                for item in self.findings
            ],
            "errors": self.errors,
            "provider_runs": self.provider_runs,
        }
