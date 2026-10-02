from __future__ import annotations

import ipaddress
import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import IPProvider, ProviderError


class ShodanProvider(IPProvider):
    name = "shodan"
    base_url = "https://api.shodan.io/shodan/host"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
        history: bool = False,
        minify: bool = True,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("XLFR4N_OSINT_SHODAN_API_KEY")
        self.history = history
        self.minify = minify

    def search_ip(self, address: str) -> list[Finding]:
        try:
            clean = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc

        if not self.api_key:
            raise ProviderError("shodan requires XLFR4N_OSINT_SHODAN_API_KEY")

        params = urllib.parse.urlencode({
            "key": self.api_key,
            "history": "true" if self.history else "false",
            "minify": "true" if self.minify else "false",
        })
        request_url = f"{self.base_url}/{clean}?{params}"
        provenance_url = f"{self.base_url}/{clean}"

        payload = get_json(
            request_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )
        if not isinstance(payload, dict):
            raise ProviderError("shodan returned an unexpected response")

        ports = payload.get("ports", [])
        return [
            Finding.now(
                source=self.name,
                category="shodan-host",
                identifier=clean,
                title=f"Shodan host — {clean}",
                url=provenance_url,
                confidence="high",
                provenance={
                    "source_url": provenance_url,
                    "retrieval_method": "Shodan REST host information API",
                    "provider": self.name,
                    "api_tier": "authenticated",
                },
                data={
                    "ip": clean,
                    "ports": ports if isinstance(ports, list) else [],
                    "hostnames": payload.get("hostnames", []),
                    "domains": payload.get("domains", []),
                    "org": payload.get("org"),
                    "isp": payload.get("isp"),
                    "asn": payload.get("asn"),
                    "country_name": payload.get("country_name"),
                    "city": payload.get("city"),
                    "os": payload.get("os"),
                    "last_update": payload.get("last_update"),
                    "history_requested": self.history,
                    "minified": self.minify,
                },
            )
        ]
