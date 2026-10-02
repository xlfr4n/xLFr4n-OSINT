from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.hibp_breaches import HIBPBreachesProvider


def test_hibp_breach_provider_normalizes_metadata_only() -> None:
    payload = [
        {
            "Name": "ExampleBreach",
            "Title": "Example Breach",
            "Domain": "example.com",
            "BreachDate": "2024-01-01",
            "AddedDate": "2024-02-01T00:00:00Z",
            "ModifiedDate": "2024-03-01T00:00:00Z",
            "PwnCount": 1234,
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsFabricated": False,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
        }
    ]

    with patch(
        "xlfr4n_osint.providers.hibp_breaches.get_json",
        return_value=payload,
    ):
        findings = HIBPBreachesProvider(
            api_key="test-key",
            user_agent="xLFr4n-test/1.0",
        ).search_email("user@example.com")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.data["name"] == "ExampleBreach"
    assert finding.data["pwn_count"] == 1234
    assert "Passwords" in finding.data["data_classes"]
    assert finding.provenance["provider"] == "hibp-breaches"
