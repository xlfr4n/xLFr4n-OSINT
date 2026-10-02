from __future__ import annotations

from xlfr4n_osint.providers.crtsh import CRTShProvider


def test_crtsh_normalizes_certificate_names() -> None:
    payload = [
        {"name_value": "*.example.com\napi.example.com"},
        {"name_value": "other.example.org"},
        {"name_value": "example.com"},
    ]

    values = CRTShProvider._normalize_hosts(payload, "example.com")

    assert values == ["api.example.com", "example.com"]
