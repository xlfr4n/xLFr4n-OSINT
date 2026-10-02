from __future__ import annotations

import argparse
import json

from xlfr4n_osint.config import ScanConfig

from xlfr4n_osint.correlation import CorrelationEngine

from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.reporting import build_json_report, write_json, write_markdown
from xlfr4n_osint.providers.github import GitHubProvider
from xlfr4n_osint.providers.gitlab import GitLabProvider
from xlfr4n_osint.providers.gitea import GiteaProvider
from xlfr4n_osint.providers.http import HTTPProvider
from xlfr4n_osint.providers.rdap import RDAPProvider
from xlfr4n_osint.providers.rdap_number import RDAPNumberProvider
from xlfr4n_osint.providers.dns import DNSProvider
from xlfr4n_osint.providers.ctlogs import CTLogsProvider
from xlfr4n_osint.providers.tls import TLSProvider
from xlfr4n_osint.registry import ProviderRegistry
from xlfr4n_osint.scanner import UsernameScanner


def build_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register("github", GitHubProvider, capabilities={"username"})
    registry.register("gitlab", GitLabProvider, capabilities={"username"})
    registry.register("gitea", GiteaProvider, capabilities={"username"})
    registry.register("http", HTTPProvider, capabilities={"domain"})
    registry.register("rdap", RDAPProvider, capabilities={"domain"})
    registry.register("dns", DNSProvider, capabilities={"domain"})
    registry.register("ctlogs", CTLogsProvider, capabilities={"domain"})
    registry.register("tls", TLSProvider, capabilities={"domain"})
    registry.register("rdap-number", RDAPNumberProvider, capabilities={"ip", "asn"})
    return registry


def build_parser(registry: ProviderRegistry | None = None) -> argparse.ArgumentParser:
    registry = registry or build_registry()

    parser = argparse.ArgumentParser(
        prog="xlfr4n-osint",
        description="Public-source OSINT toolkit by xLFr4n.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    username = subparsers.add_parser(
        "username",
        help="Research a public username across enabled providers.",
    )
    username.add_argument("value", help="Public username/handle to research.")
    username.add_argument(
        "--source",
        action="append",
        choices=registry.names("username"),
        help="Limit the scan to one or more enabled username providers.",
    )
    username.add_argument("--timeout", type=float, default=None)
    username.add_argument("--user-agent", default=None)
    username.add_argument("--config", help="Path to a TOML config file.")
    username.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    username.add_argument("--output", help="Write a report file.")
    username.add_argument("--format", choices=["json", "markdown"], default="json")

    domain = subparsers.add_parser(
        "domain",
        help="Research public registration data for a domain.",
    )
    domain.add_argument("value", help="Domain name to research.")
    domain.add_argument(
        "--source",
        action="append",
        choices=registry.names("domain"),
        help="Limit the scan to one or more enabled domain providers.",
    )
    domain.add_argument("--timeout", type=float, default=None)
    domain.add_argument("--user-agent", default=None)
    domain.add_argument("--config", help="Path to a TOML config file.")
    domain.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    domain.add_argument("--output", help="Write a report file.")
    domain.add_argument("--format", choices=["json", "markdown"], default="json")

    ip = subparsers.add_parser(
        "ip",
        help="Research public RDAP registration data for an IP address.",
    )
    ip.add_argument("value", help="IPv4 or IPv6 address to research.")
    ip.add_argument(
        "--source",
        action="append",
        choices=registry.names("ip"),
        help="Limit the scan to one or more enabled IP providers.",
    )
    ip.add_argument("--timeout", type=float, default=None)
    ip.add_argument("--user-agent", default=None)
    ip.add_argument("--config", help="Path to a TOML config file.")
    ip.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    ip.add_argument("--output", help="Write a report file.")
    ip.add_argument("--format", choices=["json", "markdown"], default="json")

    asn = subparsers.add_parser(
        "asn",
        help="Research public RDAP registration data for an AS number.",
    )
    asn.add_argument("value", help="AS number, with or without the AS prefix.")
    asn.add_argument(
        "--source",
        action="append",
        choices=registry.names("asn"),
        help="Limit the scan to one or more enabled ASN providers.",
    )
    asn.add_argument("--timeout", type=float, default=None)
    asn.add_argument("--user-agent", default=None)
    asn.add_argument("--config", help="Path to a TOML config file.")
    asn.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    asn.add_argument("--output", help="Write a report file.")
    asn.add_argument("--format", choices=["json", "markdown"], default="json")

    sources = subparsers.add_parser("sources", help="List enabled providers.")
    sources.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    return parser


def _run_username(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        providers = registry.build(
            args.source,
            capability="username",
            timeout=timeout,
            user_agent=user_agent,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query=args.value.strip())
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        _print_report(report, args.json, subject="username", output=args.output, output_format=args.format)
        return 2

    report = UsernameScanner(providers).run(args.value)
    _print_report(report, args.json, subject="username", output=args.output, output_format=args.format)
    return 0 if not report.errors else 2


def _run_number(
    args: argparse.Namespace,
    registry: ProviderRegistry,
    *,
    capability: str,
    subject: str,
    method_name: str,
) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        providers = registry.build(
            args.source,
            capability=capability,
            timeout=timeout,
            user_agent=user_agent,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query=args.value.strip())
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        _print_report(
            report,
            args.json,
            subject=subject,
            output=args.output,
            output_format=args.format,
        )
        return 2

    report = ScanReport(query=args.value.strip())
    for provider in providers:
        try:
            method = getattr(provider, method_name)
            report.findings.extend(method(args.value))
        except Exception as exc:
            report.errors.append({
                "source": provider.name,
                "error": str(exc),
                "type": type(exc).__name__,
            })

    _print_report(
        report,
        args.json,
        subject=subject,
        output=args.output,
        output_format=args.format,
    )
    return 0 if not report.errors else 2


def _run_ip(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    return _run_number(
        args,
        registry,
        capability="ip",
        subject="ip",
        method_name="search_ip",
    )


def _run_asn(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    return _run_number(
        args,
        registry,
        capability="asn",
        subject="asn",
        method_name="search_asn",
    )


def _run_domain(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        providers = registry.build(
            args.source,
            capability="domain",
            timeout=timeout,
            user_agent=user_agent,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query=args.value.strip())
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        _print_report(report, args.json, subject="domain", output=args.output, output_format=args.format)
        return 2

    report = ScanReport(query=args.value.strip())
    for provider in providers:
        try:
            report.findings.extend(provider.search_domain(args.value))
        except Exception as exc:
            report.errors.append({
                "source": provider.name,
                "error": str(exc),
                "type": type(exc).__name__,
            })

    _print_report(report, args.json, subject="domain", output=args.output, output_format=args.format)
    return 0 if not report.errors else 2


def _print_report(
    report: ScanReport,
    as_json: bool,
    *,
    subject: str,
    output: str | None = None,
    output_format: str = "json",
) -> None:
    if output:
        if output_format == "markdown":
            write_markdown(report, output)
        else:
            write_json(report, output)

    if as_json:
        print(json.dumps(build_json_report(report), ensure_ascii=False, indent=2))
        return

    print(f"⚡ xLFr4n // OSINT — {subject}: {report.query}")
    print()

    if report.findings:
        for finding in report.findings:
            print(f"[{finding.source}] {finding.title}")
            print(f"  {finding.url}")
            print(f"  confidence={finding.confidence}")
    else:
        print("No public findings returned by the selected providers.")

    if report.findings:
        entities = CorrelationEngine().build(report).entities
        print()
        print(f"Correlated entities: {len(entities)}")

    if report.errors:
        print()
        print("Provider errors:")
        for error in report.errors:
            print(f"  - {error['source']}: {error['error']}")


def main() -> int:
    registry = build_registry()
    parser = build_parser(registry)
    args = parser.parse_args()

    if args.command == "username":
        return _run_username(args, registry)

    if args.command == "domain":
        return _run_domain(args, registry)

    if args.command == "ip":
        return _run_ip(args, registry)

    if args.command == "asn":
        return _run_asn(args, registry)

    if args.command == "sources":
        if args.json:
            print(json.dumps({"sources": list(registry.names())}, indent=2))
        else:
            print("⚡ xLFr4n // OSINT — enabled sources")
            for name in registry.names():
                print(f"  - {name}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
