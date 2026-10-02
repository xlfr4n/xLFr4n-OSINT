from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.notifications import WebhookNotifier


def test_webhook_notifier_sends_discord_embed_summary_only() -> None:
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
            "provider_count": 4,
            "provider_skipped": 1,
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
    assert payload["content"] == "⚡ **xLFr4n // OSINT**"
    assert payload["allowed_mentions"] == {"parse": []}
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]
    assert "COMPLETED" in embed["title"]
    assert "example.com" in embed["description"]
    assert any(
        field["name"] == "Findings" and field["value"] == "2"
        for field in embed["fields"]
    )
    assert any(
        field["name"] == "Skipped providers" and field["value"] == "1"
        for field in embed["fields"]
    )
    assert "findings" not in payload
    assert "must-not-be-sent" not in str(payload)


def test_webhook_notifier_redacts_password_query() -> None:
    report = {
        "schema_version": "1.1",
        "scan_id": "secret123",
        "query": "<redacted-password>",
        "summary": {},
    }

    with patch(
        "xlfr4n_osint.notifications.post_json",
        return_value={},
    ) as post:
        WebhookNotifier(url="https://webhook.example.test").notify(report)

    payload = post.call_args.kwargs["payload"] if "payload" in post.call_args.kwargs else post.call_args.args[1]
    assert "<redacted-password>" in payload["embeds"][0]["description"]
