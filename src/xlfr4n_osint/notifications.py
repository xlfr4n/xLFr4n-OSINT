from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from xlfr4n_osint.http import post_json
from xlfr4n_osint.logging_utils import get_logger


_LOGGER = get_logger("notifications")


class WebhookNotifier:
    name = "webhook"

    def __init__(
        self,
        url: str | None = None,
        *,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.url = url or os.getenv("XLFR4N_OSINT_WEBHOOK_URL")
        self.timeout = timeout
        self.user_agent = user_agent

    def notify(self, report: dict[str, Any]) -> None:
        if not self.url:
            raise ValueError("XLFR4N_OSINT_WEBHOOK_URL is not configured")

        summary = report.get("summary", {})
        payload = {
            "event": "xlfr4n_osint_scan_completed",
            "schema_version": str(report.get("schema_version", "1.1")),
            "scan_id": report.get("scan_id"),
            "query": (
                "<redacted-password>"
                if report.get("query") == "<redacted-password>"
                else report.get("query")
            ),
            "summary": {
                "finding_count": summary.get("finding_count"),
                "source_count": summary.get("source_count"),
                "category_count": summary.get("category_count"),
                "error_count": summary.get("error_count"),
                "entity_count": summary.get("entity_count"),
                "relationship_count": summary.get("relationship_count"),
                "duplicate_group_count": summary.get("duplicate_group_count"),
            },
        }

        post_json(
            self.url,
            payload,
            timeout=self.timeout,
            user_agent=self.user_agent,
        )


def notify_report_file(
    path: str | Path,
    *,
    url: str | None = None,
    timeout: float = 10.0,
    user_agent: str = "xLFr4n-OSINT/0.1.0",
) -> None:
    import json

    report = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(report, dict) and isinstance(report.get("reports"), list):
        # Batch reports are summarized as one notification envelope.
        reports = report["reports"]
        totals = {
            "finding_count": 0,
            "source_count": 0,
            "category_count": 0,
            "error_count": 0,
            "entity_count": 0,
            "relationship_count": 0,
            "duplicate_group_count": 0,
        }
        for item in reports:
            if not isinstance(item, dict):
                continue
            summary = item.get("summary", {})
            if not isinstance(summary, dict):
                continue
            for key in totals:
                value = summary.get(key)
                if isinstance(value, int):
                    totals[key] += value
        envelope = {
            "schema_version": "1.0",
            "scan_id": None,
            "query": "batch",
            "summary": totals,
        }
        WebhookNotifier(
            url,
            timeout=timeout,
            user_agent=user_agent,
        ).notify(envelope)
        return

    if not isinstance(report, dict):
        raise ValueError("report file must contain a JSON object")

    WebhookNotifier(
        url,
        timeout=timeout,
        user_agent=user_agent,
    ).notify(report)
