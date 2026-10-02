from __future__ import annotations

from xlfr4n_osint.batch import BatchItem, run_batch
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import UsernameProvider
from xlfr4n_osint.registry import ProviderRegistry


class FakeProvider(UsernameProvider):
    name = "fake"

    def search_username(self, username: str) -> list[Finding]:
        return [
            Finding.now(
                source=self.name,
                category="public-profile",
                identifier=username,
                title=username,
                url=f"https://example.test/{username}",
            )
        ]


def test_batch_preserves_input_order_with_multiple_workers() -> None:
    registry = ProviderRegistry()
    registry.register("fake", FakeProvider, capabilities={"username"})

    items = [
        BatchItem(type="username", value="first"),
        BatchItem(type="username", value="second"),
        BatchItem(type="username", value="third"),
    ]

    reports = run_batch(
        items,
        registry,
        timeout=1,
        user_agent="xLFr4n-test/1.0",
        max_workers=3,
    )

    assert [report.query for report in reports] == [
        "first",
        "second",
        "third",
    ]


def test_batch_redacts_password_report_query() -> None:
    registry = ProviderRegistry()
    registry.register("fake-password", FakeProvider, capabilities={"password"})

    item = BatchItem(type="password", value="secret")

    # Provider intentionally fails because it lacks check_password.
    reports = run_batch(
        [item],
        registry,
        timeout=1,
        user_agent="xLFr4n-test/1.0",
    )

    assert reports[0].query == "<redacted-password>"
    assert reports[0].errors
