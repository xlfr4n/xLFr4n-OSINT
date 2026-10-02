from __future__ import annotations

import argparse
import json
from getpass import getpass

from xlfr4n_osint.batch import load_jsonl, run_batch
from xlfr4n_osint.filemeta import ExifToolProvider
from xlfr4n_osint.logging_utils import configure_logging
from xlfr4n_osint.notifications import notify_report_file
from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.correlation import CorrelationEngine
from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.reporting import (
    build_batch_json,
    build_json_report,
    write_batch_json,
    write_batch_jsonl,
    write_json,
    write_markdown,
)
from xlfr4n_osint.providers.crtsh import CRTShProvider
from xlfr4n_osint.providers.censys import CensysProvider
from xlfr4n_osint.providers.shodan import ShodanProvider
from xlfr4n_osint.providers.securitytrails import SecurityTrailsProvider
from xlfr4n_osint.providers.virustotal import VirusTotalProvider
from xlfr4n_osint.providers.hunter import HunterProvider
from xlfr4n_osint.providers.ctlogs import CTLogsProvider
from xlfr4n_osint.providers.dns import DNSProvider
from xlfr4n_osint.providers.external_domain import AmassProvider, SubfinderProvider
from xlfr4n_osint.providers.external_username import HoleheProvider, MaigretProvider, SherlockProvider
from xlfr4n_osint.providers.gitea import GiteaProvider
from xlfr4n_osint.providers.github import GitHubProvider
from xlfr4n_osint.providers.gitlab import GitLabProvider
from xlfr4n_osint.providers.hibp_breaches import HIBPBreachesProvider
from xlfr4n_osint.providers.intelligence_x import IntelligenceXProvider
from xlfr4n_osint.providers.hibp_passwords import HIBPPwnedPasswordsProvider
from xlfr4n_osint.providers.hudsonrock import HudsonRockProvider
from xlfr4n_osint.providers.http import HTTPProvider
from xlfr4n_osint.providers.leakcheck import LeakCheckProvider
from xlfr4n_osint.providers.rdap import RDAPProvider
from xlfr4n_osint.providers.rdap_number import RDAPNumberProvider
from xlfr4n_osint.providers.spiderfoot import SpiderFootProvider
from xlfr4n_osint.providers.theharvester import TheHarvesterProvider
from xlfr4n_osint.providers.tls import TLSProvider
from xlfr4n_osint.providers.urlscan import URLScanProvider
from xlfr4n_osint.providers.archives import CommonCrawlProvider, WaybackProvider
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
    registry.register("crtsh", CRTShProvider, capabilities={"domain"}, default_enabled=False)
    registry.register("tls", TLSProvider, capabilities={"domain"})
    registry.register("rdap-number", RDAPNumberProvider, capabilities={"ip", "asn"})
    registry.register("leakcheck", LeakCheckProvider, capabilities={"username", "email", "phone"}, default_enabled=False)
    registry.register("maigret", MaigretProvider, capabilities={"username"}, default_enabled=False)
    registry.register("sherlock", SherlockProvider, capabilities={"username"}, default_enabled=False)
    registry.register("holehe", HoleheProvider, capabilities={"email"}, default_enabled=False)
    registry.register("subfinder", SubfinderProvider, capabilities={"domain"}, default_enabled=False)
    registry.register("amass", AmassProvider, capabilities={"domain"}, default_enabled=False)
    registry.register("theharvester", TheHarvesterProvider, capabilities={"domain"}, default_enabled=False)
    registry.register("spiderfoot", SpiderFootProvider, capabilities={"username", "email", "phone", "domain", "ip", "asn", "person"}, default_enabled=False)
    registry.register("urlscan", URLScanProvider, capabilities={"domain", "ip", "url"}, default_enabled=False)
    registry.register("wayback", WaybackProvider, capabilities={"domain", "url"}, default_enabled=False)
    registry.register("commoncrawl", CommonCrawlProvider, capabilities={"domain", "url"}, default_enabled=False)
    registry.register("censys", CensysProvider, capabilities={"ip"}, default_enabled=False)
    registry.register("shodan", ShodanProvider, capabilities={"ip"}, default_enabled=False)
    registry.register("securitytrails", SecurityTrailsProvider, capabilities={"domain"}, default_enabled=False)
    registry.register("virustotal", VirusTotalProvider, capabilities={"domain", "ip", "hash"}, default_enabled=False)
    registry.register("hunter", HunterProvider, capabilities={"domain", "email"}, default_enabled=False)
    registry.register("hudsonrock", HudsonRockProvider, capabilities={"domain"}, default_enabled=False)
    registry.register("intelligence-x", IntelligenceXProvider, capabilities={"domain", "email", "phone", "ip", "url"}, default_enabled=False)
    registry.register("hibp-passwords", HIBPPwnedPasswordsProvider, capabilities={"password"})
    registry.register("exiftool", ExifToolProvider, capabilities={"file"}, default_enabled=False)
    registry.register("hibp-breaches", HIBPBreachesProvider, capabilities={"email"}, default_enabled=False)
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

    email = subparsers.add_parser(
        "email",
        help="Research public breach-exposure metadata for an email address.",
    )
    email.add_argument("value", help="Email address to research.")
    email.add_argument("--all-sources", action="store_true", help="Run every registered provider for this capability.")
    email.add_argument(
        "--source",
        action="append",
        choices=registry.names("email"),
        help="Limit the scan to one or more enabled email providers.",
    )
    email.add_argument("--timeout", type=float, default=None)
    email.add_argument("--user-agent", default=None)
    email.add_argument("--config", help="Path to a TOML config file.")
    email.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    email.add_argument("--output", help="Write a report file.")
    email.add_argument("--format", choices=["json", "markdown"], default="json")

    phone = subparsers.add_parser(
        "phone",
        help="Research public breach-exposure metadata for a phone number.",
    )
    phone.add_argument("value", help="Phone number to research.")
    phone.add_argument("--all-sources", action="store_true", help="Run every registered provider for this capability.")
    phone.add_argument(
        "--source",
        action="append",
        choices=registry.names("phone"),
        help="Limit the scan to one or more enabled phone providers.",
    )
    phone.add_argument("--timeout", type=float, default=None)
    phone.add_argument("--user-agent", default=None)
    phone.add_argument("--config", help="Path to a TOML config file.")
    phone.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    phone.add_argument("--output", help="Write a report file.")
    phone.add_argument("--format", choices=["json", "markdown"], default="json")

    password = subparsers.add_parser(
        "password",
        help="Check a password's public exposure without sending the password itself.",
    )
    password.add_argument(
        "value",
        nargs="?",
        help="Password to check. Omit this argument to enter it without shell history.",
    )
    password.add_argument("--all-sources", action="store_true", help="Run every registered provider for this capability.")
    password.add_argument(
        "--source",
        action="append",
        choices=registry.names("password"),
        help="Limit the check to one or more enabled password providers.",
    )
    password.add_argument("--timeout", type=float, default=None)
    password.add_argument("--user-agent", default=None)
    password.add_argument("--config", help="Path to a TOML config file.")
    password.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    password.add_argument("--output", help="Write a report file.")
    password.add_argument("--format", choices=["json", "markdown"], default="json")

    hash_cmd = subparsers.add_parser(
        "hash",
        help="Research a file hash using enabled hash providers.",
    )
    hash_cmd.add_argument("value", help="MD5, SHA-1 or SHA-256 hash.")
    hash_cmd.add_argument("--all-sources", action="store_true", help="Run every registered provider for this capability.")
    hash_cmd.add_argument("--source", action="append", choices=registry.names("hash"))
    hash_cmd.add_argument("--timeout", type=float, default=None)
    hash_cmd.add_argument("--user-agent", default=None)
    hash_cmd.add_argument("--config")
    hash_cmd.add_argument("--json", action="store_true")
    hash_cmd.add_argument("--output")
    hash_cmd.add_argument("--format", choices=["json", "markdown"], default="json")

    file_cmd = subparsers.add_parser(
        "file",
        help="Inspect a local file with enabled metadata providers.",
    )
    file_cmd.add_argument("value", help="Local file path.")
    file_cmd.add_argument("--source", action="append", choices=registry.names("file"))
    file_cmd.add_argument("--timeout", type=float, default=None)
    file_cmd.add_argument("--user-agent", default=None)
    file_cmd.add_argument("--config")
    file_cmd.add_argument("--json", action="store_true")
    file_cmd.add_argument("--output")
    file_cmd.add_argument("--format", choices=["json", "markdown"], default="json")

    batch = subparsers.add_parser(
        "batch",
        help="Run a bounded JSONL batch of public-source investigations.",
    )
    batch.add_argument("input", help="JSONL file containing {type,value,sources?} items.")
    batch.add_argument("--timeout", type=float, default=None)
    batch.add_argument("--user-agent", default=None)
    batch.add_argument("--config", help="Path to a TOML config file.")
    batch.add_argument("--workers", type=int, default=1)
    batch.add_argument(
        "--all-sources",
        action="store_true",
        help="Use every registered provider for each batch item's capability.",
    )
    batch.add_argument(
        "--output",
        help="Write the complete batch report to a JSON or JSONL file.",
    )
    batch.add_argument(
        "--format",
        choices=["json", "jsonl"],
        default="json",
    )
    batch.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    url = subparsers.add_parser(
        "url",
        help="Research public historical intelligence for a URL.",
    )
    url.add_argument("value", help="HTTP or HTTPS URL to research.")
    url.add_argument("--all-sources", action="store_true", help="Run every registered provider for this capability.")
    url.add_argument("--source", action="append", choices=registry.names("url"))
    url.add_argument("--timeout", type=float, default=None)
    url.add_argument("--user-agent", default=None)
    url.add_argument("--config")
    url.add_argument("--json", action="store_true")
    url.add_argument("--output")
    url.add_argument("--format", choices=["json", "markdown"], default="json")

    person = subparsers.add_parser(
        "person",
        help="Research a public name/person query.",
    )
    person.add_argument("value", help="Name or public person query.")
    person.add_argument("--all-sources", action="store_true", help="Run every registered provider for this capability.")
    person.add_argument("--source", action="append", choices=registry.names("person"))
    person.add_argument("--timeout", type=float, default=None)
    person.add_argument("--user-agent", default=None)
    person.add_argument("--config")
    person.add_argument("--json", action="store_true")
    person.add_argument("--output")
    person.add_argument("--format", choices=["json", "markdown"], default="json")

    notify_cmd = subparsers.add_parser(
        "notify",
        help="Send a report summary to the configured webhook.",
    )
    notify_cmd.add_argument("input", help="JSON report file.")
    notify_cmd.add_argument("--webhook", default=None)
    notify_cmd.add_argument("--timeout", type=float, default=None)
    notify_cmd.add_argument("--user-agent", default=None)
    
    sources = subparsers.add_parser("sources", help="List enabled providers.")
    sources.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    return parser


def _run_username(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        if args.all_sources and args.source:
            raise ValueError("--all-sources cannot be combined with --source")
        providers = registry.build(
            args.source,
            capability="username",
            all_sources=args.all_sources,
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
        if args.all_sources and args.source:
            raise ValueError("--all-sources cannot be combined with --source")
        providers = registry.build(
            args.source,
            capability=capability,
            all_sources=args.all_sources,
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


def _run_identifier(
    args: argparse.Namespace,
    registry: ProviderRegistry,
    *,
    capability: str,
    subject: str,
    method_name: str,
    query: str | None = None,
) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        if args.all_sources and args.source:
            raise ValueError("--all-sources cannot be combined with --source")
        providers = registry.build(
            args.source,
            capability=capability,
            all_sources=args.all_sources,
            timeout=timeout,
            user_agent=user_agent,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query=query or args.value.strip())
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

    report = ScanReport(query=query or args.value.strip())
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


def _run_hash(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    return _run_identifier(
        args,
        registry,
        capability="hash",
        subject="hash",
        method_name="search_hash",
    )


def _run_file(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        providers = registry.build(
            args.source,
            capability="file",
            timeout=timeout,
            user_agent=user_agent,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query=args.value)
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        _print_report(report, args.json, subject="file", output=args.output, output_format=args.format)
        return 2

    report = ScanReport(query=args.value)
    for provider in providers:
        try:
            report.findings.extend(provider.inspect_file(args.value))
        except Exception as exc:
            report.errors.append({
                "source": provider.name,
                "error": str(exc),
                "type": type(exc).__name__,
            })

    _print_report(report, args.json, subject="file", output=args.output, output_format=args.format)
    return 0 if not report.errors else 2


def _run_notify(args: argparse.Namespace) -> int:
    try:
        config = ScanConfig.from_file(None)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        notify_report_file(
            args.input,
            url=args.webhook,
            timeout=timeout,
            user_agent=user_agent,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"Notification error: {exc}")
        return 2
    return 0


def _run_url(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    return _run_identifier(
        args,
        registry,
        capability="url",
        subject="url",
        method_name="search_url",
    )


def _run_person(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    return _run_identifier(
        args,
        registry,
        capability="person",
        subject="person",
        method_name="search_person",
    )


def _run_email(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    return _run_identifier(
        args,
        registry,
        capability="email",
        subject="email",
        method_name="search_email",
    )


def _run_phone(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    return _run_identifier(
        args,
        registry,
        capability="phone",
        subject="phone",
        method_name="search_phone",
    )


def _run_password(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    secret = args.value
    if secret is None:
        secret = getpass("Password to check (input hidden): ")
    if not secret:
        print("Password cannot be empty.")
        return 2

    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        if args.all_sources and args.source:
            raise ValueError("--all-sources cannot be combined with --source")
        providers = registry.build(
            args.source,
            capability="password",
            all_sources=args.all_sources,
            timeout=timeout,
            user_agent=user_agent,
        )
    except (ValueError, TypeError) as exc:
        report = ScanReport(query="<redacted-password>")
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        _print_report(
            report,
            args.json,
            subject="password",
            output=args.output,
            output_format=args.format,
        )
        return 2

    report = ScanReport(query="<redacted-password>")
    for provider in providers:
        try:
            report.findings.extend(provider.check_password(secret))
        except Exception as exc:
            report.errors.append({
                "source": provider.name,
                "error": str(exc),
                "type": type(exc).__name__,
            })

    del secret
    _print_report(
        report,
        args.json,
        subject="password",
        output=args.output,
        output_format=args.format,
    )
    return 0 if not report.errors else 2


def _run_domain(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        if args.all_sources and args.source:
            raise ValueError("--all-sources cannot be combined with --source")
        providers = registry.build(
            args.source,
            capability="domain",
            all_sources=args.all_sources,
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


def _run_batch(args: argparse.Namespace, registry: ProviderRegistry) -> int:
    try:
        config = ScanConfig.from_file(args.config)
        timeout = args.timeout if args.timeout is not None else config.timeout
        user_agent = args.user_agent or config.user_agent
        items = load_jsonl(args.input)
        reports = run_batch(
            items,
            registry,
            timeout=timeout,
            user_agent=user_agent,
            max_workers=args.workers,
            all_sources=args.all_sources,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"Batch error: {exc}")
        return 2

    if args.output:
        if args.format == "jsonl":
            write_batch_jsonl(reports, args.output)
        else:
            write_batch_json(reports, args.output)

    if args.json:
        print(json.dumps(build_batch_json(reports), ensure_ascii=False, indent=2))
    else:
        print(f"⚡ xLFr4n // OSINT — batch: {len(reports)} reports")
        for report in reports:
            status = "ok" if not report.errors else "errors"
            subject = "<redacted-password>" if report.query == "<redacted-password>" else report.query
            print(f"  - {status} · {subject} · findings={len(report.findings)}")

    return 0 if all(not report.errors for report in reports) else 2


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
    configure_logging()
    registry = build_registry()
    parser = build_parser(registry)
    args = parser.parse_args()

    if args.command == "username":
        return _run_username(args, registry)

    if args.command == "domain":
        return _run_domain(args, registry)

    if args.command == "email":
        return _run_email(args, registry)

    if args.command == "url":
        return _run_url(args, registry)

    if args.command == "hash":
        return _run_hash(args, registry)

    if args.command == "file":
        return _run_file(args, registry)

    if args.command == "person":
        return _run_person(args, registry)

    if args.command == "phone":
        return _run_phone(args, registry)

    if args.command == "password":
        return _run_password(args, registry)

    if args.command == "ip":
        return _run_ip(args, registry)

    if args.command == "asn":
        return _run_asn(args, registry)

    if args.command == "batch":
        return _run_batch(args, registry)

    if args.command == "notify":
        return _run_notify(args)

    if args.command == "sources":
        if args.json:
            print(json.dumps({
                "sources": [
                    {
                        "name": name,
                        "capabilities": list(registry.capabilities(name)),
                        "default_enabled": registry.is_default_enabled(name),
                    }
                    for name in registry.names()
                ]
            }, indent=2))
        else:
            print("⚡ xLFr4n // OSINT — registered sources")
            for name in registry.names():
                status = "default" if registry.is_default_enabled(name) else "opt-in"
                capabilities = ", ".join(registry.capabilities(name))
                print(f"  - {name} [{status}] — {capabilities}")
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
