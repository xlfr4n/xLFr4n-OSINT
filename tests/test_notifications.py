from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.notifications import WebhookNotifier


def test_webhook_notifier_sends_summary_only() -> None:
    report = {
        "schema_version": "1.1",
        "scan_id": "abc123",
        "query": "example.com",
        "summary": {
            "finding_count": 2,
            "source_count": 2,
            "category_count": 2,
            "error_count": 0,
            "entity_count": 2,
            "relationship_count": 1,
            "duplicate_group_count": 0,
        },
        "findings": [
            {"secret": "must-not-be-sent"},
        ],
    }

    with patch(
        "xlfr4n_osint.notifications.post_json",
        return_value={},
    ) as post:
        WebhookNotifier(url="https://webhook.example.test").notify(report)

    payload = post.call_args.kwargs["payload"] if "payload" in post.call_args.kwargs else post.call_args.args[1]
    assert payload["scan_id"] == "abc123"
    assert payload["summary"]["finding_count"] == 2
    assert "findings" not in payload
    assert "must-not-be-sent" not in str(payload)
