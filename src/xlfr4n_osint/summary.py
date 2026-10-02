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
    provider_count: int
    providers_with_findings: int
    providers_without_findings: int
    provider_errors: int
    provider_timeouts: int
    provider_skipped: int
    total_provider_seconds: float
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
            "provider_count": self.provider_count,
            "providers_with_findings": self.providers_with_findings,
            "providers_without_findings": self.providers_without_findings,
            "provider_errors": self.provider_errors,
            "provider_timeouts": self.provider_timeouts,
            "provider_skipped": self.provider_skipped,
            "total_provider_seconds": round(self.total_provider_seconds, 3),
            "sources": dict(self.sources),
            "categories": dict(self.categories),
        }


def build_summary(report: ScanReport) -> InvestigationSummary:
    correlation = CorrelationEngine().build(report)
    sources = Counter(item.source for item in report.findings)
    categories = Counter(item.category for item in report.findings)
    executions = list(report.provider_runs)

    return InvestigationSummary(
        finding_count=len(report.findings),
        source_count=len(sources),
        category_count=len(categories),
        error_count=len(report.errors),
        entity_count=len(correlation.entities),
        relationship_count=len(correlation.relationships),
        duplicate_group_count=len(correlation.duplicates),
        provider_count=len(executions),
        providers_with_findings=sum(
            execution.get("status") == "findings" for execution in executions
        ),
        providers_without_findings=sum(
            execution.get("status") == "no-findings" for execution in executions
        ),
        provider_errors=sum(
            execution.get("status") == "error" for execution in executions
        ),
        provider_timeouts=sum(
            execution.get("status") == "timeout" for execution in executions
        ),
        provider_skipped=sum(
            execution.get("status") == "skipped" for execution in executions
        ),
        total_provider_seconds=sum(
            float(execution.get("duration_seconds", 0) or 0)
            for execution in executions
        ),
        sources=tuple(sorted(sources.items())),
        categories=tuple(sorted(categories.items())),
    )
