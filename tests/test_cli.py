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
    url = parser.parse_args(["url", "https://example.com/path"])
    person = parser.parse_args(["person", "Jane Doe"])
    hash = parser.parse_args(["hash", "a" * 64])
    file_cmd = parser.parse_args(["file", "examples/batch.jsonl"])

    assert username.command == "username"
    assert email.command == "email"
    assert phone.command == "phone"
    assert password.command == "password"
    assert ip.command == "ip"
    assert asn.command == "asn"
    assert url.command == "url"
    assert person.command == "person"
    assert hash.command == "hash"
    assert file_cmd.command == "file"


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


def test_parser_exposes_all_source_mode() -> None:
    parser = build_parser(build_registry())

    args = parser.parse_args([
        "email",
        "user@example.com",
        "--all-sources",
    ])

    assert args.all_sources is True
    assert args.source is None


def test_core_targets_expose_all_source_mode() -> None:
    parser = build_parser(build_registry())

    for command, value in [
        ("username", "xLFr4n"),
        ("domain", "example.com"),
        ("ip", "192.0.2.10"),
        ("asn", "AS64500"),
    ]:
        args = parser.parse_args([command, value, "--all-sources"])
        assert args.all_sources is True


def test_parser_exposes_doctor_command() -> None:
    parser = build_parser(build_registry())
    args = parser.parse_args(["doctor", "--json"])
    assert args.command == "doctor"
    assert args.json is True


def test_parser_exposes_gui_command() -> None:
    parser = build_parser(build_registry())
    args = parser.parse_args([
        "gui",
        "--host",
        "127.0.0.1",
        "--port",
        "8787",
        "--no-browser",
    ])

    assert args.command == "gui"
    assert args.host == "127.0.0.1"
    assert args.port == 8787
    assert args.no_browser is True
    assert args.allow_remote is False
