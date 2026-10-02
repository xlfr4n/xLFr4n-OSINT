from __future__ import annotations

import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


class SecurityTrailsProvider(DomainProvider):
    name = "securitytrails"
    base_url = "https://api.securitytrails.com/v1/domain"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("XLFR4N_OSINT_SECURITYTRAILS_API_KEY")

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        if not self.api_key:
            raise ProviderError(
                "securitytrails requires XLFR4N_OSINT_SECURITYTRAILS_API_KEY"
            )

        source_url = f"{self.base_url}/{urllib.parse.quote(clean, safe='')}"
        payload = get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers={"APIKEY": self.api_key},
        )
        if not isinstance(payload, dict):
            raise ProviderError("securitytrails returned an unexpected response")

        current_dns = payload.get("current_dns")
        dns_data = current_dns if isinstance(current_dns, dict) else {}

        return [
            Finding.now(
                source=self.name,
                category="securitytrails-domain",
                identifier=clean,
                title=f"SecurityTrails domain — {clean}",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "SecurityTrails REST domain API",
                    "provider": self.name,
                    "api_tier": "authenticated",
                },
                data={
                    "domain": clean,
                    "apex_domain": payload.get("apex_domain"),
                    "subdomain": payload.get("subdomain"),
                    "current_dns": dns_data,
                    "alexa_rank": payload.get("alexa_rank"),
                    "hostname": payload.get("hostname"),
                },
            )
        ]
