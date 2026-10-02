from __future__ import annotations

import ipaddress
import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, IPProvider, ProviderError


class VirusTotalProvider(DomainProvider, IPProvider):
    name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("XLFR4N_OSINT_VIRUSTOTAL_API_KEY")

    def _lookup(self, target: str, *, target_type: str) -> list[Finding]:
        if not self.api_key:
            raise ProviderError(
                "virustotal requires XLFR4N_OSINT_VIRUSTOTAL_API_KEY"
            )

        encoded = urllib.parse.quote(target, safe="")
        source_url = f"{self.base_url}/{target_type}s/{encoded}"
        payload = get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers={"x-apikey": self.api_key},
        )
        if not isinstance(payload, dict):
            raise ProviderError("virustotal returned an unexpected response")

        data = payload.get("data")
        attributes = data.get("attributes", {}) if isinstance(data, dict) else {}
        if not isinstance(attributes, dict):
            attributes = {}

        stats = attributes.get("last_analysis_stats")
        if not isinstance(stats, dict):
            stats = {}

        return [
            Finding.now(
                source=self.name,
                category=f"virustotal-{target_type}",
                identifier=target,
                title=f"VirusTotal {target_type} — {target}",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "VirusTotal v3 API object lookup",
                    "provider": self.name,
                    "api_tier": "authenticated",
                },
                data={
                    "target": target,
                    "reputation": attributes.get("reputation"),
                    "analysis_stats": stats,
                    "last_analysis_date": attributes.get("last_analysis_date"),
                    "times_submitted": attributes.get("times_submitted"),
                    "whois": attributes.get("whois"),
                    "categories": attributes.get("categories"),
                },
            )
        ]

    def search_domain(self, domain: str) -> list[Finding]:
        return self._lookup(normalize_domain(domain), target_type="domain")

    def search_ip(self, address: str) -> list[Finding]:
        try:
            clean = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc
        return self._lookup(clean, target_type="ip")
