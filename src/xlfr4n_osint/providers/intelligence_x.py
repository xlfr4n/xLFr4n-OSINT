from __future__ import annotations

import ipaddress
import os
import time
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json, post_json
from xlfr4n_osint.identifiers import normalize_email, normalize_phone
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import (
    DomainProvider,
    EmailProvider,
    IPProvider,
    PhoneProvider,
    ProviderError,
    URLProvider,
)


class IntelligenceXProvider(
    DomainProvider,
    EmailProvider,
    PhoneProvider,
    IPProvider,
    URLProvider,
):
    name = "intelligence-x"
    base_url = "https://public.intelx.io"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
        buckets: tuple[str, ...] = (
            "leaks.public",
            "pastes",
            "web.public",
            "whois",
            "dns",
            "documents.public",
            "dumpster",
        ),
        max_results: int = 100,
        poll_interval: float = 0.5,
        max_polls: int = 12,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("XLFR4N_OSINT_INTELX_API_KEY")
        self.buckets = tuple(item for item in buckets if item)
        self.max_results = max(1, min(max_results, 1000))
        if poll_interval < 0:
            raise ValueError("poll_interval cannot be negative")
        self.poll_interval = poll_interval
        self.max_polls = max(1, max_polls)

    def _search(self, term: str, *, kind: str) -> list[Finding]:
        if not self.api_key:
            raise ProviderError("intelligence-x requires XLFR4N_OSINT_INTELX_API_KEY")

        params = {
            "term": term,
            "maxresults": str(self.max_results),
            "buckets": ",".join(self.buckets),
            "timeout": str(max(1, int(self.config.timeout))),
            "datefrom": "",
            "dateto": "",
            "sort": "4",
            "media": "0",
            "lookuplevel": "0",
            "terminate": "",
        }
        query = urllib.parse.urlencode(params)
        search_url = f"{self.base_url}/intelligent/search?{query}"

        started = post_json(
            search_url,
            {},
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers={"x-key": self.api_key},
        )
        if not isinstance(started, dict):
            raise ProviderError("intelligence-x search returned an unexpected response")

        search_id = started.get("id")
        if not isinstance(search_id, str) or not search_id:
            raise ProviderError("intelligence-x search did not return a search ID")

        records: list[dict[str, object]] = []
        result_url = f"{self.base_url}/intelligent/search/result"
        for attempt in range(self.max_polls):
            result_query = urllib.parse.urlencode({
                "id": search_id,
                "limit": self.max_results,
                "media": 0,
                "statistics": 1,
                "previewlines": 0,
            })
            payload = get_json(
                f"{result_url}?{result_query}",
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
                headers={"x-key": self.api_key},
            )
            if not isinstance(payload, dict):
                raise ProviderError("intelligence-x result returned an unexpected response")

            status = int(payload.get("status", 4))
            raw_records = payload.get("records")
            if isinstance(raw_records, list):
                records.extend(
                    item
                    for item in raw_records
                    if isinstance(item, dict)
                )

            if status in {0, 1, 2, 4}:
                if status == 2:
                    raise ProviderError("intelligence-x search ID not found")
                break

            if attempt + 1 < self.max_polls and self.poll_interval:
                time.sleep(self.poll_interval)

        sanitized: list[dict[str, object]] = []
        for record in records[: self.max_results]:
            sanitized.append({
                "name": record.get("name"),
                "date": record.get("date"),
                "bucket": record.get("bucket"),
                "media": record.get("media"),
                "content_type": record.get("contenttype") or record.get("contentType"),
                "size": record.get("size"),
                "system_id_present": bool(record.get("systemid") or record.get("systemId")),
            })

        source_url = f"{self.base_url}/intelligent/search"
        return [
            Finding.now(
                source=self.name,
                category="intelligence-x-exposure",
                identifier=f"{kind}:{term}".casefold(),
                title=f"Intelligence X exposure — {term}",
                url=source_url,
                confidence="medium",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "Intelligence X Search API metadata",
                    "provider": self.name,
                    "api_tier": "authenticated",
                    "raw_content_retained": "false",
                },
                data={
                    "target": term,
                    "target_type": kind,
                    "search_id_present": True,
                    "record_count": len(sanitized),
                    "records": sanitized,
                },
            )
        ]

    def search_email(self, email: str) -> list[Finding]:
        return self._search(normalize_email(email), kind="email")

    def search_phone(self, phone: str) -> list[Finding]:
        return self._search(normalize_phone(phone), kind="phone")

    def search_domain(self, domain: str) -> list[Finding]:
        return self._search(normalize_domain(domain), kind="domain")

    def search_url(self, url: str) -> list[Finding]:
        return self._search(url, kind="url")

    def search_ip(self, address: str) -> list[Finding]:
        try:
            clean = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc
        return self._search(clean, kind="ip")
