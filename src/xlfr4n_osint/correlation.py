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


def semantic_finding_key(finding: Finding) -> str:
    canonical = "\x1f".join(
        (
            finding.category.casefold(),
            finding.identifier.strip().casefold(),
            finding.url.strip(),
        )
    )
    return sha256(canonical.encode("utf-8")).hexdigest()[:16]


def exact_selectors(finding: Finding) -> tuple[str, ...]:
    selectors: set[str] = set()

    identifier = finding.identifier.strip().casefold()
    if identifier:
        selectors.add(f"identifier:{identifier}")

    data = finding.data or {}
    for key, prefix in (
        ("username", "username"),
        ("login", "username"),
        ("email", "email"),
        ("phone", "phone"),
        ("domain", "domain"),
        ("website_domain", "domain"),
    ):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            selectors.add(f"{prefix}:{value.strip().casefold()}")

    url = finding.url.strip()
    if url:
        selectors.add(f"url:{url}")

    if identifier.startswith(("username:", "email:", "phone:", "domain:")):
        selectors.add(identifier)

    return tuple(sorted(selectors))


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
class Relationship:
    left_entity: str
    right_entity: str
    relation: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_entity": self.left_entity,
            "right_entity": self.right_entity,
            "relation": self.relation,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class CorrelationReport:
    entities: list[Entity] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    duplicates: dict[str, list[str]] = field(default_factory=dict)

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
            ],
            "relationships": [
                item.to_dict() for item in self.relationships
            ],
            "duplicates": self.duplicates,
        }


class CorrelationEngine:
    """Exact-match correlation only; never infers identity from weak signals."""

    def build(self, report: ScanReport) -> CorrelationReport:
        groups: dict[tuple[str, str], Entity] = {}
        semantic_groups: dict[str, list[str]] = {}
        selector_groups: dict[str, list[str]] = {}
        duplicates: dict[str, list[str]] = {}

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

            full_key = finding_key(finding)
            entity.add(full_key, finding.source)

            semantic_key = semantic_finding_key(finding)
            semantic_groups.setdefault(semantic_key, []).append(full_key)

            for selector in exact_selectors(finding):
                selector_groups.setdefault(selector, []).append(entity.key)

        for semantic_key, finding_ids in semantic_groups.items():
            unique_ids = list(dict.fromkeys(finding_ids))
            if len(unique_ids) > 1:
                duplicates[semantic_key] = unique_ids

        relationships_by_pair: dict[tuple[str, str, str], Relationship] = {}
        for selector, entity_keys in selector_groups.items():
            unique_entities = list(dict.fromkeys(entity_keys))
            if len(unique_entities) < 2:
                continue

            # Represent a shared-selector group as a deterministic spanning star
            # instead of a quadratic clique. The full selector remains in the
            # evidence so consumers can reconstruct the exact correlation group.
            anchor = unique_entities[0]
            evidence = f"selector:{selector}"
            for right in unique_entities[1:]:
                if anchor == right:
                    continue
                pair = tuple(sorted((anchor, right)))
                marker = (pair[0], pair[1], "exact-shared-selector")
                relationship = relationships_by_pair.get(marker)
                if relationship is None:
                    relationship = Relationship(
                        left_entity=pair[0],
                        right_entity=pair[1],
                        relation="exact-shared-public-selector",
                        evidence=[evidence],
                    )
                    relationships_by_pair[marker] = relationship
                elif evidence not in relationship.evidence:
                    relationship.evidence.append(evidence)

        relationships = list(relationships_by_pair.values())

        return CorrelationReport(
            entities=list(groups.values()),
            relationships=relationships,
            duplicates=duplicates,
        )
