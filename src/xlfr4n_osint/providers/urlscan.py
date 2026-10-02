from __future__ import annotations

import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, IPProvider, ProviderError


class URLScanProvider(DomainProvider, IPProvider):
    name = "urlscan"
    endpoint = "https://urlscan.io/api/v1/search"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("URLSCAN_API_KEY")

    def _search(self, query: str, *, target_kind: str) -> list[Finding]:
        if not self.api_key:
            raise ProviderError("urlscan requires URLSCAN_API_KEY")

        params = urllib.parse.urlencode({
            "q": query,
            "size": "100",
            "datasource": "scans",
        })
        source_url = f"{self.endpoint}?{params}"
        payload = get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers={"api-key": self.api_key},
        )

        if not isinstance(payload, dict) or not isinstance(
            payload.get("results"),
            list,
        ):
            raise ProviderError("urlscan returned an unexpected response")

        records: list[dict[str, object]] = []
        for item in payload["results"]:
            if not isinstance(item, dict):
                continue
            page = item.get("page")
            task = item.get("task")
            if not isinstance(page, dict):
                page = {}
            if not isinstance(task, dict):
                task = {}

            records.append({
                "scan_id": item.get("_id") or item.get("id"),
                "date": item.get("indexedAt") or item.get("date"),
                "visibility": item.get("visibility"),
                "url": task.get("url") or page.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "asn": page.get("asn"),
                "country": page.get("country"),
                "server": page.get("server"),
            })

        if not records:
            return []

        target = query.split(":", 1)[-1]
        return [
            Finding.now(
                source=self.name,
                category="historical-web-scan",
                identifier=f"{target_kind}:{target}".casefold(),
                title=f"urlscan historical scans — {target}",
                url=f"https://urlscan.io/search/#{urllib.parse.quote(query, safe='')}",
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "urlscan.io historical search API",
                    "provider": self.name,
                    "visibility_scope": "public scans in search results",
                },
                data={
                    "target": target,
                    "target_kind": target_kind,
                    "results": records,
                    "count": len(records),
                    "has_more": bool(payload.get("has_more", False)),
                },
            )
        ]

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        return self._search(f"page.domain:{clean}", target_kind="domain")

    def search_ip(self, address: str) -> list[Finding]:
        value = address.strip()
        if not value:
            raise ValueError("IP address cannot be empty")
        return self._search(f"page.ip:{value}", target_kind="ip")
