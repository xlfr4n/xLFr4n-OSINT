from __future__ import annotations

from xlfr4n_osint.evidence import EvidenceBundle, payload_fingerprint
from xlfr4n_osint.models import Finding, ScanReport


def test_evidence_bundle_preserves_provenance_and_scan_id() -> None:
    finding = Finding.now(
        source="github",
        category="public-profile",
        identifier="xLFr4n",
        title="xLFr4n",
        url="https://github.com/xLFr4n",
        confidence="high",
        provenance={
            "source_url": "https://api.github.com/users/xLFr4n",
            "retrieval_method": "GitHub REST API public endpoint",
            "provider": "github",
        },
        data={"public_repos": 7},
    )
    report = ScanReport(query="xLFr4n", findings=[finding])

    bundle = EvidenceBundle.from_report(report)
    payload = bundle.to_dict()

    assert payload["schema_version"] == "1.0"
    assert payload["scan_id"] == report.scan_id
    assert payload["records"][0]["source"] == "github"
    assert payload["records"][0]["provenance"]["provider"] == "github"
    assert payload["records"][0]["data_fingerprint"] == payload_fingerprint(finding)


def test_payload_fingerprint_changes_when_data_changes() -> None:
    first = Finding.now(
        source="test",
        category="example",
        identifier="demo",
        title="Demo",
        url="https://example.test",
        data={"value": 1},
    )
    second = Finding.now(
        source="test",
        category="example",
        identifier="demo",
        title="Demo",
        url="https://example.test",
        data={"value": 2},
    )

    assert payload_fingerprint(first) != payload_fingerprint(second)
