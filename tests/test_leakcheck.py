from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.leakcheck import LeakCheckProvider


def test_leakcheck_public_provider_normalizes_exposure_metadata() -> None:
    payload = {
        "success": True,
        "found": 2,
        "fields": ["email", "password"],
        "sources": [
            {"name": "Example Breach", "date": "2024-01"},
            {"name": "Another Breach", "date": ""},
        ],
    }

    with patch(
        "xlfr4n_osint.providers.leakcheck.get_json",
        return_value=payload,
    ):
        findings = LeakCheckProvider().search_email("Example@example.com")

    assert len(findings) == 1
    data = findings[0].data
    assert data["found_sources"] == 2
    assert data["password_values_returned"] is False
    assert data["full_records_returned"] is False
    assert data["sources"][0]["name"] == "Example Breach"
