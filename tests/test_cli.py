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


def test_parser_exposes_all_identifier_commands() -> None:
    parser = build_parser(build_registry())

    username = parser.parse_args(["username", "xLFr4n"])
    email = parser.parse_args(["email", "user@example.com"])
    phone = parser.parse_args(["phone", "+34123456789"])
    password = parser.parse_args(["password"])
    ip = parser.parse_args(["ip", "192.0.2.10"])
    asn = parser.parse_args(["asn", "AS64500"])

    assert username.command == "username"
    assert email.command == "email"
    assert phone.command == "phone"
    assert password.command == "password"
    assert ip.command == "ip"
    assert asn.command == "asn"


def test_parser_exposes_opt_in_external_providers() -> None:
    parser = build_parser(build_registry())

    args = parser.parse_args([
        "username",
        "xLFr4n",
        "--source",
        "maigret",
        "--source",
        "sherlock",
    ])
    domain = parser.parse_args([
        "domain",
        "example.com",
        "--source",
        "subfinder",
        "--source",
        "amass",
    ])
    email = parser.parse_args([
        "email",
        "user@example.com",
        "--source",
        "leakcheck",
    ])

    assert args.source == ["maigret", "sherlock"]
    assert domain.source == ["subfinder", "amass"]
    assert email.source == ["leakcheck"]


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
