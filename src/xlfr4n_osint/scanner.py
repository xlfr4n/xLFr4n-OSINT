from __future__ import annotations

from xlfr4n_osint.execution import execute_providers
from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.providers.base import Provider


class UsernameScanner:
    """Run username research concurrently across a selected provider set."""

    def __init__(self, providers: list[Provider], *, max_workers: int = 6) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least 1")
        self.providers = providers
        self.max_workers = max_workers

    def run(self, username: str) -> ScanReport:
        query = username.strip()
        report = ScanReport(query=query)

        findings, errors, executions = execute_providers(
            self.providers,
            method_name="search_username",
            value=query,
            max_workers=self.max_workers,
        )
        report.findings.extend(findings)
        report.errors.extend(errors)
        report.provider_runs.extend(
            execution.to_dict() for execution in executions
        )
        return report
