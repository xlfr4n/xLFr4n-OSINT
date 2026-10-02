from __future__ import annotations

from pathlib import Path

from xlfr4n_osint.cli import _print_report, build_parser, build_registry
from xlfr4n_osint.models import ScanReport


def test_parser_exposes_report_output_options() -> None:
    parser = build_parser(build_registry())
    args = parser.parse_args([
        "domain",
        "example.com",
        "--output",
        "report.md",
        "--format",
        "markdown",
    ])

    assert args.output == "report.md"
    assert args.format == "markdown"


def test_print_report_writes_requested_markdown(
    tmp_path: Path,
    capsys,
) -> None:
    report = ScanReport(query="example.com")
    output = tmp_path / "report.md"

    _print_report(
        report,
        False,
        subject="domain",
        output=str(output),
        output_format="markdown",
    )

    assert output.exists()
    assert "Investigation Report" in output.read_text(encoding="utf-8")
    assert "domain: example.com" in capsys.readouterr().out
