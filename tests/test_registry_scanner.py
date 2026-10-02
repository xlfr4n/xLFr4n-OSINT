from __future__ import annotations

from dataclasses import dataclass

from xlfr4n_osint.models import Finding
from xlfr4n_osint.registry import ProviderRegistry
from xlfr4n_osint.scanner import UsernameScanner
from xlfr4n_osint.providers.base import Provider


@dataclass
class FakeProvider(Provider):
    name: str = "fake"

    def search_username(self, username: str) -> list[Finding]:
        return [
            Finding.now(
                source=self.name,
                category="test",
                identifier=username,
                title=username,
                url="https://example.test/" + username,
            )
        ]


def test_registry_builds_registered_provider() -> None:
    registry = ProviderRegistry()
    registry.register("fake", FakeProvider, capabilities={"username"})

    providers = registry.build(["fake"])

    assert len(providers) == 1
    assert providers[0].name == "fake"


def test_scanner_preserves_provider_errors() -> None:
    class BrokenProvider(Provider):
        name = "broken"

        def search_username(self, username: str) -> list[Finding]:
            raise RuntimeError("network unavailable")

    report = UsernameScanner([BrokenProvider()]).run("demo")

    assert report.findings == []
    assert report.errors[0]["source"] == "broken"
    assert report.errors[0]["type"] == "RuntimeError"
    assert report.scan_id
    assert report.started_at


def test_report_has_stable_schema_version() -> None:
    report = UsernameScanner([FakeProvider()]).run("demo")

    payload = report.to_dict()

    assert payload["schema_version"] == "1.1"
    assert payload["scan_id"]
    assert payload["findings"][0]["identifier"] == "demo"


def test_registry_defaults_exclude_opt_in_providers() -> None:
    class OptionalProvider(Provider):
        name = "optional"

        def search_username(self, username: str) -> list[Finding]:
            return []

    registry = ProviderRegistry()
    registry.register("default", FakeProvider, capabilities={"username"})
    registry.register(
        "optional",
        OptionalProvider,
        capabilities={"username"},
        default_enabled=False,
    )

    assert registry.names("username", default_only=True) == ("default",)
    assert registry.names("username") == ("default", "optional")
    assert registry.is_default_enabled("optional") is False
