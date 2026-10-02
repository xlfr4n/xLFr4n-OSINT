from xlfr4n_osint.models import Finding, ScanReport


def test_finding_now_sets_timestamp() -> None:
    finding = Finding.now(
        source="test",
        category="example",
        identifier="demo",
        title="Demo",
        url="https://example.com",
    )

    assert finding.observed_at
    assert finding.identifier == "demo"


def test_scan_report_serializes_findings() -> None:
    finding = Finding.now(
        source="test",
        category="example",
        identifier="demo",
        title="Demo",
        url="https://example.com",
    )
    report = ScanReport(query="demo", findings=[finding])

    payload = report.to_dict()

    assert payload["query"] == "demo"
    assert payload["findings"][0]["source"] == "test"
