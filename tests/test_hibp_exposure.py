from __future__ import annotations

from xlfr4n_osint.providers.hibp_exposure import (
    HIBPPastesProvider,
    HIBPStealerLogsProvider,
)


def test_hibp_paste_metadata_is_normalized(monkeypatch) -> None:
    monkeypatch.setattr(
        "xlfr4n_osint.providers.hibp_exposure.get_json",
        lambda *args, **kwargs: [
            {
                "Source": "Pastebin",
                "Id": "abc123",
                "Title": "example",
                "Date": "2026-01-01",
                "EmailCount": 3,
            }
        ],
    )
    provider = HIBPPastesProvider(api_key="0" * 32)

    findings = provider.search_email("User@Example.com")

    assert len(findings) == 1
    assert findings[0].category == "paste-exposure"
    assert findings[0].data["email"] == "user@example.com"
    assert findings[0].data["raw_content_retained"] is False


def test_hibp_stealer_log_metadata_does_not_retain_credentials(monkeypatch) -> None:
    monkeypatch.setattr(
        "xlfr4n_osint.providers.hibp_exposure.get_json",
        lambda *args, **kwargs: ["example.com", "cdn.example.com"],
    )
    provider = HIBPStealerLogsProvider(api_key="0" * 32)

    findings = provider.search_email("user@example.com")

    assert len(findings) == 2
    assert all(item.category == "stealer-log-exposure" for item in findings)
    assert all(
        item.data["credential_values_retained"] is False
        for item in findings
    )
