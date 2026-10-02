from __future__ import annotations

import argparse
import json

from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.providers.github import GitHubProvider
from xlfr4n_osint.providers.gitlab import GitLabProvider
from xlfr4n_osint.providers.gitea import GiteaProvider
from xlfr4n_osint.providers.rdap import RDAPProvider
from xlfr4n_osint.providers.dns import DNSProvider
from xlfr4n_osint.providers.ctlogs import CTLogsProvider
from xlfr4n_osint.registry import ProviderRegistry
from xlfr4n_osint.scanner import UsernameScanner


def build_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register("github", GitHubProvider, capabilities={"username"})
    registry.register("gitlab", GitLabProvider, capabilities={"username"})
    registry.register("gitea", GiteaProvider, capabilities={"username"})
    registry.register("rdap", RDAPProvider, capabilities={"domain"})
    registry.register("dns", DNSProvider, capabilities={"domain"})
    registry.register("ctlogs", CTLogsProvider, capabilities={"domain"})
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
    username.add_argument("--timeout", type=float, default=10.0)
    username.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

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
    domain.add_argument("--timeout", type=float, default=10.0)
    domain.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    sources = subparsers.add_parser("sources", help="List enabled providers.")
    sources.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    return parser


def _run_username(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        providers = registry.build(
            args.source,
            capability="username",
            timeout=args.timeout,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query=args.value.strip())
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        _print_report(report, args.json, subject="username")
        return 2

    report = UsernameScanner(providers).run(args.value)
    _print_report(report, args.json, subject="username")
    return 0 if not report.errors else 2


def _run_domain(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        providers = registry.build(
            args.source,
            capability="domain",
            timeout=args.timeout,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query=args.value.strip())
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        _print_report(report, args.json, subject="domain")
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

    _print_report(report, args.json, subject="domain")
    return 0 if not report.errors else 2


def _print_report(
    report: ScanReport,
    as_json: bool,
    *,
    subject: str,
) -> None:
    if as_json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
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
