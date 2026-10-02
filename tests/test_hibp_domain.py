from __future__ import annotations

from xlfr4n_osint.providers.hibp_domain import (
    HIBPDomainBreachesProvider,
    HIBPStealerLogDomainProvider,
)


def test_hibp_domain_breaches_normalize_aliases(monkeypatch) -> None:
    monkeypatch.setattr(
        "xlfr4n_osint.providers.hibp_domain.get_json",
        lambda *args, **kwargs: {
            "alice": ["Adobe", "Example"],
            "bob": ["Example"],
        },
    )
    provider = HIBPDomainBreachesProvider(api_key="0" * 32)

    findings = provider.search_domain("example.com")

    assert len(findings) == 2
    assert {item.data["alias"] for item in findings} == {"alice", "bob"}
    assert all(item.data["full_email_retained"] is False for item in findings)


def test_hibp_stealer_domain_keeps_alias_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "xlfr4n_osint.providers.hibp_domain.get_json",
        lambda *args, **kwargs: [
            "alice@example.net",
            "bob@example.org",
        ],
    )
    provider = HIBPStealerLogDomainProvider(api_key="0" * 32)

    findings = provider.search_domain("example.com")

    assert len(findings) == 2
    assert {item.data["email_alias"] for item in findings} == {"alice", "bob"}
    assert all(item.data["full_email_retained"] is False for item in findings)
