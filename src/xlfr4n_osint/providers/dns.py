from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


class DNSProvider(DomainProvider):
    name = "dns"
    endpoint = "https://cloudflare-dns.com/dns-query"
    record_types = ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT")

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def _query(self, domain: str, record_type: str) -> dict:
        query = urllib.parse.urlencode({
            "name": domain,
            "type": record_type,
        })
        url = f"{self.endpoint}?{query}"
        payload = get_json(
            url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            accept="application/dns-json",
        )
        if not isinstance(payload, dict):
            raise ProviderError("dns returned an unexpected response")
        return payload

    @staticmethod
    def _answers(payload: dict) -> list[dict[str, str | int]]:
        answer = payload.get("Answer")
        if not isinstance(answer, list):
            return []

        result: list[dict[str, str | int]] = []
        for item in answer:
            if not isinstance(item, dict) or "data" not in item:
                continue
            result.append({
                "name": str(item.get("name", "")),
                "type": int(item.get("type", 0)),
                "ttl": int(item.get("TTL", 0)),
                "data": str(item["data"]),
            })
        return result

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        records: dict[str, list[dict[str, str | int]]] = {}
        statuses: dict[str, int] = {}

        # Each record type is independent. Query them in parallel so a domain
        # scan is bounded by the slowest request/retry budget rather than the
        # sum of seven sequential DNS request budgets.
        with ThreadPoolExecutor(
            max_workers=len(self.record_types),
            thread_name_prefix="xlfr4n-dns",
        ) as executor:
            futures = {
                executor.submit(self._query, clean, record_type): record_type
                for record_type in self.record_types
            }
            ordered_payloads: dict[str, dict] = {}
            for future in as_completed(futures):
                record_type = futures[future]
                ordered_payloads[record_type] = future.result()

        for record_type in self.record_types:
            payload = ordered_payloads[record_type]
            statuses[record_type] = int(payload.get("Status", -1))
            records[record_type] = self._answers(payload)

        compact = {
            record_type: [item["data"] for item in values]
            for record_type, values in records.items()
            if values
        }
        if not compact:
            return []

        nameserver_data = compact.get("NS", [])
        return [
            Finding.now(
                source=self.name,
                category="dns-records",
                identifier=clean,
                title=f"DNS records — {clean}",
                url=f"https://{clean}",
                confidence="high",
                provenance={
                    "source_url": self.endpoint,
                    "retrieval_method": "Cloudflare DNS over HTTPS JSON API",
                    "provider": self.name,
                },
                data={
                    "records": compact,
                    "status_codes": statuses,
                    "record_count": sum(len(values) for values in records.values()),
                    "nameservers": nameserver_data,
                    "record_types_queried": list(self.record_types),
                    "parallel": True,
                },
            )
        ]
