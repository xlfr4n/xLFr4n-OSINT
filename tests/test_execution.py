from __future__ import annotations

import time

from xlfr4n_osint.execution import execute_providers
from xlfr4n_osint.providers.base import Provider


class DummyProvider(Provider):
    def __init__(self, name: str, *, findings: int = 0, delay: float = 0.0, fail: bool = False) -> None:
        self.name = name
        self.findings = findings
        self.delay = delay
        self.fail = fail

    def search_username(self, value: str):
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("synthetic failure")
        return [
            __import__("xlfr4n_osint.models", fromlist=["Finding"]).Finding.now(
                source=self.name,
                category="username-account",
                identifier=f"{self.name}:{value}",
                title=self.name,
                url=f"https://example.test/{value}",
                confidence="provider-reported",
                data={"username": value},
                provenance={"provider": self.name},
            )
            for _ in range(self.findings)
        ]


def test_execute_providers_runs_concurrently_and_records_statuses() -> None:
    providers = [
        DummyProvider("slow", findings=1, delay=0.25),
        DummyProvider("fast", findings=2, delay=0.01),
        DummyProvider("empty"),
        DummyProvider("broken", fail=True),
    ]

    started = time.monotonic()
    findings, errors, executions = execute_providers(
        providers,
        method_name="search_username",
        value="xLFr4n",
        max_workers=4,
    )
    elapsed = time.monotonic() - started

    assert elapsed < 0.45
    assert len(findings) == 3
    assert len(errors) == 1
    assert errors[0]["source"] == "broken"

    by_name = {item.provider: item for item in executions}
    assert by_name["slow"].status == "findings"
    assert by_name["fast"].status == "findings"
    assert by_name["empty"].status == "no-findings"
    assert by_name["broken"].status == "error"
    assert by_name["broken"].error == "synthetic failure"


def test_timeout_classification_uses_exception_type() -> None:
    from xlfr4n_osint.execution import _status_for_error
    from xlfr4n_osint.providers.base import ProviderError
    from xlfr4n_osint.tooling import ExternalToolTimeoutError

    assert _status_for_error(ProviderError("usage mentions timeout but command failed")) == "error"
    assert _status_for_error(ExternalToolTimeoutError("external tool timed out")) == "timeout"
