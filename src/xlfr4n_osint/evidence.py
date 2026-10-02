from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from xlfr4n_osint.correlation import finding_key
from xlfr4n_osint.models import Finding, ScanReport


def payload_fingerprint(finding: Finding) -> str:
    serialized = json.dumps(
        finding.data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class EvidenceRecord:
    evidence_id: str
    source: str
    category: str
    identifier: str
    source_url: str
    observed_at: str
    confidence: str
    data_fingerprint: str
    provenance: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "category": self.category,
            "identifier": self.identifier,
            "source_url": self.source_url,
            "observed_at": self.observed_at,
            "confidence": self.confidence,
            "data_fingerprint": self.data_fingerprint,
            "provenance": self.provenance,
        }


@dataclass(slots=True)
class EvidenceBundle:
    scan_id: str
    records: list[EvidenceRecord]

    @classmethod
    def from_report(cls, report: ScanReport) -> "EvidenceBundle":
        return cls(
            scan_id=report.scan_id,
            records=[
                EvidenceRecord(
                    evidence_id=finding_key(finding),
                    source=finding.source,
                    category=finding.category,
                    identifier=finding.identifier,
                    source_url=finding.url,
                    observed_at=finding.observed_at,
                    confidence=finding.confidence,
                    data_fingerprint=payload_fingerprint(finding),
                    provenance=dict(finding.provenance),
                )
                for finding in report.findings
            ],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "scan_id": self.scan_id,
            "records": [record.to_dict() for record in self.records],
        }
