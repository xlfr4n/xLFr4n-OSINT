from __future__ import annotations

from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.providers.base import Provider


class UsernameScanner:
    """Run username research across a selected provider set."""

    def __init__(self, providers: list[Provider]) -> None:
        self.providers = providers

    def run(self, username: str) -> ScanReport:
        query = username.strip()
        report = ScanReport(query=query)

        for provider in self.providers:
            try:
                report.findings.extend(provider.search_username(query))
            except Exception as exc:
                report.errors.append({
                    "source": provider.name,
                    "error": str(exc),
                    "type": type(exc).__name__,
                })

        return report
