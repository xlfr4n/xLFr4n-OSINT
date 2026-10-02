from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from xlfr4n_osint.models import Finding, ScanReport


def finding_key(finding: Finding) -> str:
    canonical = "\x1f".join(
        (
            finding.source.casefold(),
            finding.category.casefold(),
            finding.identifier.strip().casefold(),
            finding.url.strip(),
        )
    )
    return sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class Entity:
    key: str
    kind: str
    value: str
    findings: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def add(self, finding_id: str, source: str) -> None:
        if finding_id not in self.findings:
            self.findings.append(finding_id)
        if source not in self.sources:
            self.sources.append(source)


@dataclass(slots=True)
class CorrelationReport:
    entities: list[Entity] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entities": [
                {
                    "key": entity.key,
                    "kind": entity.kind,
                    "value": entity.value,
                    "findings": entity.findings,
                    "sources": entity.sources,
                }
                for entity in self.entities
            ]
        }


class CorrelationEngine:
    """Deterministic exact-match correlation; no probabilistic identity inference."""

    def build(self, report: ScanReport) -> CorrelationReport:
        groups: dict[tuple[str, str], Entity] = {}

        for finding in report.findings:
            kind = finding.category.casefold()
            value = finding.identifier.strip().casefold()
            group_key = (kind, value)

            entity = groups.get(group_key)
            if entity is None:
                entity = Entity(
                    key=f"{kind}:{value}",
                    kind=finding.category,
                    value=finding.identifier,
                )
                groups[group_key] = entity

            entity.add(finding_key(finding), finding.source)

        return CorrelationReport(entities=list(groups.values()))
