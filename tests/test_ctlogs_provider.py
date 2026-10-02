from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.ctlogs import CTLogsProvider


def test_ctlogs_provider_normalizes_certificate_hosts() -> None:
    payload = {
        "hosts": [
            {
                "host": "example.com",
                "certs": 4,
                "first_seen": "2024-01-01T00:00:00Z",
                "last_seen": "2026-09-01T00:00:00Z",
                "last_not_after": "2026-12-01T00:00:00Z",
                "dns": "ok",
                "a": ["192.0.2.10"],
            },
            {
                "host": "www.example.com",
                "certs": 2,
                "first_seen": "2025-01-01T00:00:00Z",
                "last_seen": "2026-09-02T00:00:00Z",
                "last_not_after": "2026-12-02T00:00:00Z",
                "dns": "ok",
                "a": ["192.0.2.11"],
            },
        ],
        "has_next": False,
    }

    with patch(
        "xlfr4n_osint.providers.ctlogs.get_json",
        return_value=payload,
    ):
        findings = CTLogsProvider().search_domain("Example.com.")

    assert len(findings) == 1
    data = findings[0].data
    assert data["host_count"] == 2
    assert data["hosts"][0]["host"] == "example.com"
    assert findings[0].provenance["provider"] == "ctlogs"
