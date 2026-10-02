from __future__ import annotations

import ipaddress
import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import IPProvider, ProviderError


class CensysProvider(IPProvider):
    name = "censys"
    base_url = "https://api.platform.censys.io/v3/global/asset/host"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_token: str | None = None,
        organization_id: str | None = None,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_token = api_token or os.getenv("XLFR4N_OSINT_CENSYS_PAT")
        self.organization_id = organization_id or os.getenv(
            "XLFR4N_OSINT_CENSYS_ORGANIZATION_ID"
        )

    def search_ip(self, address: str) -> list[Finding]:
        try:
            clean = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc

        if not self.api_token:
            raise ProviderError("censys requires XLFR4N_OSINT_CENSYS_PAT")

        encoded = urllib.parse.quote(clean, safe="")
        source_url = f"{self.base_url}/{encoded}"
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }
        if self.organization_id:
            headers["X-Organization-ID"] = self.organization_id

        payload = get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers=headers,
        )
        if not isinstance(payload, dict):
            raise ProviderError("censys returned an unexpected response")

        host = payload.get("result", payload)
        if not isinstance(host, dict):
            raise ProviderError("censys host payload is not an object")

        location = host.get("location")
        location_data = location if isinstance(location, dict) else {}
        services = host.get("services")
        service_data = []
        if isinstance(services, list):
            for service in services[:100]:
                if not isinstance(service, dict):
                    continue
                service_data.append({
                    "port": service.get("port"),
                    "service_name": service.get("service_name"),
                    "extended_service_name": service.get("extended_service_name"),
                    "transport_protocol": service.get("transport_protocol"),
                })

        return [
            Finding.now(
                source=self.name,
                category="censys-host",
                identifier=clean,
                title=f"Censys host — {clean}",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "Censys Platform host lookup API",
                    "provider": self.name,
                    "api_tier": "authenticated",
                },
                data={
                    "ip": clean,
                    "location": {
                        "country": location_data.get("country"),
                        "country_code": location_data.get("country_code"),
                        "city": location_data.get("city"),
                        "continent": location_data.get("continent"),
                    },
                    "services": service_data,
                    "autonomous_system": host.get("autonomous_system"),
                    "last_updated_at": host.get("last_updated_at"),
                    "service_count": len(service_data),
                },
            )
        ]
