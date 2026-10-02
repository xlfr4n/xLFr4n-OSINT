from __future__ import annotations

from xlfr4n_osint.logging_utils import configure_logging, get_logger
from xlfr4n_osint.models import Finding, ScanReport
from xlfr4n_osint.summary import build_summary


def test_investigation_summary_counts_sources_categories_and_relationships() -> None:
    report = ScanReport(query="example.com")
    report.findings.extend([
        Finding.now(
            source="dns",
            category="dns-a",
            identifier="example.com",
            title="A",
            url="https://example.com",
        ),
        Finding.now(
            source="crtsh",
            category="certificate-hosts",
            identifier="example.com",
            title="A",
            url="https://example.com",
        ),
    ])
    report.errors.append({"source": "test", "error": "example", "type": "ProviderError"})

    summary = build_summary(report)

    assert summary.finding_count == 2
    assert summary.source_count == 2
    assert summary.category_count == 2
    assert summary.error_count == 1
    assert summary.entity_count == 2
    assert summary.relationship_count == 1


def test_logging_configuration_accepts_standard_levels() -> None:
    configure_logging("INFO")
    logger = get_logger("test")
    assert logger.getEffectiveLevel() <= 20
