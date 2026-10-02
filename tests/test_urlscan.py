from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.urlscan import URLScanProvider


def test_urlscan_search_normalizes_historical_results() -> None:
    payload = {
        "results": [
            {
                "_id": "scan-1",
                "indexedAt": "2026-09-20T00:00:00Z",
                "visibility": "public",
                "task": {"url": "https://example.com/"},
                "page": {
                    "domain": "example.com",
                    "ip": "192.0.2.10",
                    "asn": "AS64500",
                    "country": "ES",
                    "server": "example-server",
                },
            }
        ],
        "has_more": False,
    }

    with patch(
        "xlfr4n_osint.providers.urlscan.get_json",
        return_value=payload,
    ) as get_json:
        finding = URLScanProvider(api_key="test-key").search_domain("Example.com.")[0]

    assert finding.category == "historical-web-scan"
    assert finding.data["count"] == 1
    assert finding.data["results"][0]["domain"] == "example.com"
    request_url = get_json.call_args.args[0]
    assert "page.domain%3Aexample.com" in request_url
