from __future__ import annotations

from xlfr4n_osint.correlation import CorrelationEngine
from xlfr4n_osint.models import Finding, ScanReport


def test_correlation_groups_exact_case_insensitive_identifiers() -> None:
    report = ScanReport(
        query="xLFr4n",
        findings=[
            Finding.now(
                source="github",
                category="public-profile",
                identifier="xLFr4n",
                title="xLFr4n",
                url="https://github.com/xLFr4n",
            ),
            Finding.now(
                source="gitlab",
                category="public-profile",
                identifier="XLFR4N",
                title="xLFr4n",
                url="https://gitlab.com/XLFR4N",
            ),
        ],
    )

    correlated = CorrelationEngine().build(report)

    assert len(correlated.entities) == 1
    entity = correlated.entities[0]
    assert entity.kind == "public-profile"
    assert entity.value == "xLFr4n"
    assert entity.sources == ["github", "gitlab"]


def test_correlation_does_not_merge_different_categories() -> None:
    report = ScanReport(
        query="example.com",
        findings=[
            Finding.now(
                source="rdap",
                category="domain-registration",
                identifier="example.com",
                title="example.com",
                url="https://example.com",
            ),
            Finding.now(
                source="dns",
                category="dns-records",
                identifier="example.com",
                title="DNS records — example.com",
                url="https://example.com",
            ),
        ],
    )

    correlated = CorrelationEngine().build(report)

    assert len(correlated.entities) == 2
