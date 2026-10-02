from __future__ import annotations

import json
import urllib.parse
from typing import Any

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json, get_text
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError, URLProvider
from xlfr4n_osint.url import normalize_url


def _compact_wayback(payload: object, limit: int) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload:
        return []

    fields = payload[0]
    if not isinstance(fields, list):
        return []

    records: list[dict[str, Any]] = []
    for row in payload[1:]:
        if not isinstance(row, list):
            continue
        item = {
            str(fields[index]): row[index]
            for index in range(min(len(fields), len(row)))
        }
        records.append(item)
        if len(records) >= limit:
            break
    return records


def _parse_commoncrawl_jsonl(content: str, limit: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        records.append({
            "url": item.get("url"),
            "timestamp": item.get("timestamp"),
            "status": item.get("status"),
            "mime": item.get("mime"),
            "mime_detected": item.get("mime-detected"),
            "digest": item.get("digest"),
            "length": item.get("length"),
            "filename": item.get("filename"),
        })
        if len(records) >= limit:
            break
    return records


class WaybackProvider(DomainProvider, URLProvider):
    name = "wayback"
    endpoint = "https://web.archive.org/cdx/search/cdx"

    def __init__(
        self,
        timeout: float = 15.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        limit: int = 100,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.limit = max(1, min(limit, 500))

    def _search(self, pattern: str, *, kind: str, target: str) -> list[Finding]:
        params = urllib.parse.urlencode({
            "url": pattern,
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype,digest,length",
            "filter": "statuscode:200",
            "collapse": "urlkey",
            "limit": str(self.limit),
        })
        source_url = f"{self.endpoint}?{params}"
        payload = get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )
        records = _compact_wayback(payload, self.limit)
        if not records:
            return []

        return [
            Finding.now(
                source=self.name,
                category="web-archive",
                identifier=f"{kind}:{target}".casefold(),
                title=f"Wayback captures — {target}",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "Internet Archive Wayback CDX API",
                    "provider": self.name,
                    "archive": "Wayback",
                },
                data={
                    "target": target,
                    "target_type": kind,
                    "capture_count": len(records),
                    "captures": records,
                },
            )
        ]

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        return self._search(
            f"{clean}/*",
            kind="domain",
            target=clean,
        )

    def search_url(self, url: str) -> list[Finding]:
        clean = normalize_url(url)
        return self._search(
            clean,
            kind="url",
            target=clean,
        )


class CommonCrawlProvider(DomainProvider, URLProvider):
    name = "commoncrawl"
    collection_endpoint = "https://index.commoncrawl.org/collinfo.json"
    index_endpoint = "https://index.commoncrawl.org"

    def __init__(
        self,
        timeout: float = 15.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        limit: int = 100,
        max_crawls: int = 2,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.limit = max(1, min(limit, 500))
        self.max_crawls = max(1, min(max_crawls, 5))

    def _collections(self) -> list[str]:
        payload = get_json(
            self.collection_endpoint,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )
        if not isinstance(payload, list):
            raise ProviderError("commoncrawl returned an invalid collection list")

        collections: list[str] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            name = item.get("id") or item.get("name")
            if isinstance(name, str) and name:
                collections.append(name)
            if len(collections) >= self.max_crawls:
                break
        return collections

    def _search(self, pattern: str, *, kind: str, target: str) -> list[Finding]:
        collections = self._collections()
        records: list[dict[str, Any]] = []

        for collection in collections:
            query = urllib.parse.urlencode({
                "url": pattern,
                "output": "json",
                "filter": "status:200",
                "collapse": "urlkey",
                "limit": str(self.limit),
            })
            source_url = f"{self.index_endpoint}/{collection}-index?{query}"
            content = get_text(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
            )
            for record in _parse_commoncrawl_jsonl(content, self.limit):
                record["collection"] = collection
                records.append(record)
            if len(records) >= self.limit:
                records = records[: self.limit]
                break

        if not records:
            return []

        return [
            Finding.now(
                source=self.name,
                category="web-archive",
                identifier=f"{kind}:{target}".casefold(),
                title=f"Common Crawl captures — {target}",
                url=f"{self.index_endpoint}/",
                confidence="high",
                provenance={
                    "source_url": self.collection_endpoint,
                    "retrieval_method": "Common Crawl CDXJ index",
                    "provider": self.name,
                    "collections_checked": ",".join(collections),
                    "archive": "Common Crawl",
                },
                data={
                    "target": target,
                    "target_type": kind,
                    "capture_count": len(records),
                    "captures": records,
                },
            )
        ]

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        return self._search(
            f"*.{clean}/*",
            kind="domain",
            target=clean,
        )

    def search_url(self, url: str) -> list[Finding]:
        clean = normalize_url(url)
        return self._search(
            clean,
            kind="url",
            target=clean,
        )
