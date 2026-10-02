from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from xlfr4n_osint.correlation import CorrelationEngine
from xlfr4n_osint.models import ScanReport


@dataclass(frozen=True, slots=True)
class InvestigationSummary:
    finding_count: int
    source_count: int
    category_count: int
    error_count: int
    entity_count: int
    relationship_count: int
    duplicate_group_count: int
    sources: tuple[tuple[str, int], ...]
    categories: tuple[tuple[str, int], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_count": self.finding_count,
            "source_count": self.source_count,
            "category_count": self.category_count,
            "error_count": self.error_count,
            "entity_count": self.entity_count,
            "relationship_count": self.relationship_count,
            "duplicate_group_count": self.duplicate_group_count,
            "sources": dict(self.sources),
            "categories": dict(self.categories),
        }


def build_summary(report: ScanReport) -> InvestigationSummary:
    correlation = CorrelationEngine().build(report)
    sources = Counter(item.source for item in report.findings)
    categories = Counter(item.category for item in report.findings)

    return InvestigationSummary(
        finding_count=len(report.findings),
        source_count=len(sources),
        category_count=len(categories),
        error_count=len(report.errors),
        entity_count=len(correlation.entities),
        relationship_count=len(correlation.relationships),
        duplicate_group_count=len(correlation.duplicates),
        sources=tuple(sorted(sources.items())),
        categories=tuple(sorted(categories.items())),
    )
