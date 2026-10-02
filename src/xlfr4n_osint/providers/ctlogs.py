from __future__ import annotations

import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


class CTLogsProvider(DomainProvider):
    name = "ctlogs"
    base_url = "https://api.ctlogs.dev/v1"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        encoded = urllib.parse.quote(clean, safe="")
        source_url = f"{self.base_url}/hosts/{encoded}"

        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
            )
        except ProviderError as exc:
            raise ProviderError(f"ctlogs {exc}") from exc

        if not isinstance(payload, dict):
            raise ProviderError("ctlogs returned an unexpected response")

        raw_hosts = payload.get("hosts")
        if not isinstance(raw_hosts, list):
            raise ProviderError("ctlogs returned no host collection")

        hosts: list[dict[str, object]] = []
        for item in raw_hosts:
            if not isinstance(item, dict) or not item.get("host"):
                continue
            hosts.append({
                "host": str(item["host"]),
                "certs": item.get("certs"),
                "first_seen": item.get("first_seen"),
                "last_seen": item.get("last_seen"),
                "last_not_after": item.get("last_not_after"),
                "dns": item.get("dns"),
                "a": item.get("a", []),
            })

        if not hosts:
            return []

        return [
            Finding.now(
                source=self.name,
                category="certificate-transparency",
                identifier=clean,
                title=f"Certificate Transparency — {clean}",
                url=f"https://{clean}",
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "ctlogs.dev public Certificate Transparency API",
                    "provider": self.name,
                },
                data={
                    "hosts": hosts,
                    "has_next": bool(payload.get("has_next", False)),
                    "host_count": len(hosts),
                },
            )
        ]
