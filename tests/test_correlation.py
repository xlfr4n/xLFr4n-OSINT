from __future__ import annotations

from xlfr4n_osint.correlation import CorrelationEngine, semantic_finding_key
from xlfr4n_osint.models import Finding, ScanReport


def _finding(
    source: str,
    category: str,
    identifier: str,
    url: str,
) -> Finding:
    return Finding.now(
        source=source,
        category=category,
        identifier=identifier,
        title=identifier,
        url=url,
    )


def test_correlation_groups_exact_entities_and_shared_selectors() -> None:
    report = ScanReport(query="example.com")
    report.findings.extend([
        _finding("dns", "dns-a", "example.com", "https://example.com"),
        _finding("crtsh", "certificate-hosts", "example.com", "https://example.com"),
        _finding("dns-backup", "dns-a", "example.com", "https://example.com"),
    ])

    result = CorrelationEngine().build(report)

    assert len(result.entities) == 2
    assert result.relationships
    assert result.relationships[0].relation == "exact-shared-selector"
    assert any(result.duplicates.values())


def test_semantic_finding_key_ignores_source() -> None:
    left = _finding("source-a", "category", "selector", "https://example.com")
    right = _finding("source-b", "category", "selector", "https://example.com")

    assert semantic_finding_key(left) == semantic_finding_key(right)
