from __future__ import annotations

import argparse
import json

from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.providers.base import Provider
from xlfr4n_osint.providers.github import GitHubProvider


def build_parser() -> argparse.ArgumentParser:
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
        choices=["github"],
        help="Limit the scan to a provider. May be repeated.",
    )
    username.add_argument("--timeout", type=float, default=10.0)
    username.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    return parser


def _providers(args: argparse.Namespace) -> list[Provider]:
    selected = args.source or ["github"]
    providers: list[Provider] = []
    if "github" in selected:
        providers.append(GitHubProvider(timeout=args.timeout))
    return providers


def run_username(args: argparse.Namespace) -> int:
    query = args.value.strip()
    report = ScanReport(query=query)

    for provider in _providers(args):
        try:
            report.findings.extend(provider.search_username(query))
        except Exception as exc:
            report.errors.append({"source": provider.name, "error": str(exc)})

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return 0 if not report.errors else 2

    print(f"⚡ xLFr4n // OSINT — username: {query}")
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

    return 0 if not report.errors else 2


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "username":
        return run_username(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
