from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.intelligence_x import IntelligenceXProvider


def test_intelx_provider_polls_and_keeps_metadata_only() -> None:
    started = {"status": 0, "id": "11111111-1111-1111-1111-111111111111"}
    result = {
        "status": 1,
        "records": [
            {
                "name": "Example Paste",
                "date": "2026-01-01T00:00:00Z",
                "bucket": "pastes",
                "media": 0,
                "contenttype": "text/plain",
                "size": 1024,
                "systemid": "secret-system-id",
                "content": "secret-content",
            }
        ],
    }

    with patch(
        "xlfr4n_osint.providers.intelligence_x.post_json",
        return_value=started,
    ) as post, patch(
        "xlfr4n_osint.providers.intelligence_x.get_json",
        return_value=result,
    ):
        finding = IntelligenceXProvider(
            api_key="test-key",
            poll_interval=0,
            max_polls=1,
        ).search_email("user@example.com")[0]

    assert finding.data["record_count"] == 1
    assert finding.data["records"][0]["name"] == "Example Paste"
    assert finding.data["records"][0]["system_id_present"] is True
    assert "content" not in finding.data["records"][0]
    assert "test-key" not in str(finding.provenance)
    request_url = post.call_args.args[0]
    assert "term=user%40example.com" in request_url
