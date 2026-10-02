from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.hudsonrock import HudsonRockProvider, _sanitize


def test_hudsonrock_sanitizer_redacts_credential_material() -> None:
    raw = {
        "domain": "example.com",
        "password": "never-store",
        "credentials": [{"username": "u", "password": "p"}],
        "nested": {"cookie": "session-cookie", "token": "token-value"},
    }

    clean = _sanitize(raw)

    assert clean["password"] == "[redacted]"
    assert clean["credentials"] == "[redacted]"
    assert clean["nested"]["cookie"] == "[redacted]"
    assert clean["nested"]["token"] == "[redacted]"


def test_hudsonrock_provider_returns_metadata_only() -> None:
    payload = {
        "status": "success",
        "total": 1,
        "results": [
            {
                "domain": "example.com",
                "password": "secret-password",
                "credentials": [{"username": "user", "password": "secret"}],
                "stealer": "example-stealer",
            }
        ],
    }

    with patch(
        "xlfr4n_osint.providers.hudsonrock.post_json",
        return_value=payload,
    ):
        finding = HudsonRockProvider(api_key="test-key").search_domain(
            "Example.com."
        )[0]

    serialized = str(finding.data)
    assert "secret-password" not in serialized
    assert "secret" not in serialized
    assert finding.data["credential_values_retained"] is False
    assert finding.data["sensitive_fields_redacted"] is True
    assert finding.provenance["api_tier"] == "authenticated"
