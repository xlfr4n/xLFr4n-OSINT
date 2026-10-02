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
    assert result.relationships[0].relation == "exact-shared-public-selector"
    assert any(result.duplicates.values())


def test_semantic_finding_key_ignores_source() -> None:
    left = _finding("source-a", "category", "selector", "https://example.com")
    right = _finding("source-b", "category", "selector", "https://example.com")

    assert semantic_finding_key(left) == semantic_finding_key(right)


def test_username_selector_links_distinct_categories_without_identity_assertion() -> None:
    report = ScanReport(query="xLFr4n")
    report.findings.extend([
        Finding.now(
            source="github",
            category="public-profile",
            identifier="xlfr4n",
            title="xLFr4n",
            url="https://github.com/xlfr4n",
            data={"login": "xlfr4n"},
        ),
        Finding.now(
            source="sherlock",
            category="username-account",
            identifier="github:xlfr4n",
            title="GitHub",
            url="https://github.com/xLFr4n",
            data={"username": "xLFr4n"},
        ),
    ])

    result = CorrelationEngine().build(report)

    assert any(
        relationship.relation == "exact-shared-public-selector"
        and "selector:username:xlfr4n" in relationship.evidence
        for relationship in result.relationships
    )


def test_shared_selector_uses_spanning_graph_not_quadratic_clique() -> None:
    report = ScanReport(query="xLFr4n")
    for platform in ("github", "gitlab", "gitea", "sherlock"):
        report.findings.append(
            Finding.now(
                source=platform,
                category="username-account",
                identifier=f"{platform}:xLFr4n",
                title=platform,
                url=f"https://{platform}.example/xLFr4n",
                data={"username": "xLFr4n"},
            )
        )

    result = CorrelationEngine().build(report)

    assert len(result.entities) == 4
    assert len(result.relationships) == 3
    assert all(
        relationship.relation == "exact-shared-public-selector"
        for relationship in result.relationships
    )
    assert all(
        "selector:username:xlfr4n" in relationship.evidence
        for relationship in result.relationships
    )
