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
        if not isinstance(summary, dict):
            summary = {}

        query = report.get("query")
        if query in (None, "", "<redacted-password>"):
            display_query = "<redacted-password>" if query == "<redacted-password>" else "batch"
        else:
            display_query = str(query)

        description = f"Target: `{display_query[:1000]}`"

        finding_count = int(summary.get("finding_count") or 0)
        source_count = int(summary.get("source_count") or 0)
        entity_count = int(summary.get("entity_count") or 0)
        relationship_count = int(summary.get("relationship_count") or 0)
        error_count = int(summary.get("error_count") or 0)
        skipped_count = int(summary.get("provider_skipped") or 0)
        provider_count = int(summary.get("provider_count") or 0)

        status = "COMPLETED"
        if error_count:
            status = f"COMPLETED · {error_count} ERROR(S)"
        elif skipped_count:
            status = f"COMPLETED · {skipped_count} SKIPPED"

        fields = [
            {"name": "Findings", "value": str(finding_count), "inline": True},
            {"name": "Sources", "value": str(source_count), "inline": True},
            {"name": "Providers", "value": str(provider_count), "inline": True},
            {"name": "Entities", "value": str(entity_count), "inline": True},
            {"name": "Relationships", "value": str(relationship_count), "inline": True},
            {"name": "Errors", "value": str(error_count), "inline": True},
        ]
        if skipped_count:
            fields.append({
                "name": "Skipped providers",
                "value": str(skipped_count),
                "inline": True,
            })

        payload = {
            "content": "⚡ **xLFr4n // OSINT**",
            "embeds": [
                {
                    "title": f"Investigation {status}",
                    "description": description,
                    "color": 0xF23A3A,
                    "fields": fields,
                    "footer": {
                        "text": f"scan {str(report.get('scan_id') or 'batch')[:96]} · JSON schema {report.get('schema_version', '1.1')}"
                    },
                    "timestamp": report.get("started_at"),
                }
            ],
            "allowed_mentions": {"parse": []},
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
            "provider_count": 0,
            "provider_skipped": 0,
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
