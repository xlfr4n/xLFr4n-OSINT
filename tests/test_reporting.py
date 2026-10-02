from __future__ import annotations

from pathlib import Path

from xlfr4n_osint.models import Finding, ScanReport
from xlfr4n_osint.reporting import build_json_report, render_markdown_report, write_json, write_markdown


def make_report() -> ScanReport:
    finding = Finding.now(
        source="github",
        category="public-profile",
        identifier="xLFr4n",
        title="xLFr4n",
        url="https://github.com/xLFr4n",
        confidence="high",
        provenance={"provider": "github", "source_url": "https://api.github.com/users/xLFr4n"},
        data={"public_repos": 7},
    )
    return ScanReport(query="xLFr4n", findings=[finding])


def test_build_json_report_includes_correlation_and_evidence() -> None:
    payload = build_json_report(make_report())

    assert payload["query"] == "xLFr4n"
    assert len(payload["correlation"]["entities"]) == 1
    assert len(payload["evidence"]["records"]) == 1


def test_render_markdown_contains_key_sections() -> None:
    markdown = render_markdown_report(make_report())

    assert "# ⚡ xLFr4n-OSINT Investigation Report" in markdown
    assert "## Findings" in markdown
    assert "## Exact-selector correlation" in markdown
    assert "## Evidence ledger" in markdown


def test_report_writers_create_parent_directory(tmp_path: Path) -> None:
    report = make_report()
    json_path = write_json(report, tmp_path / "nested" / "report.json")
    md_path = write_markdown(report, tmp_path / "nested" / "report.md")

    assert json_path.exists()
    assert md_path.exists()
    assert "scan_id" in json_path.read_text(encoding="utf-8")
    assert "Investigation Report" in md_path.read_text(encoding="utf-8")
