from __future__ import annotations

import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


class CRTShProvider(DomainProvider):
    name = "crtsh"
    endpoint = "https://crt.sh/"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    @staticmethod
    def _normalize_hosts(payload: object, root: str) -> list[str]:
        if not isinstance(payload, list):
            raise ProviderError("crt.sh returned an unexpected response")

        values: set[str] = set()
        for item in payload:
            if not isinstance(item, dict):
                continue
            raw = item.get("name_value")
            if not raw:
                continue
            for value in str(raw).splitlines():
                candidate = value.strip().lstrip("*.")
                if not candidate:
                    continue
                try:
                    candidate = normalize_domain(candidate)
                except ValueError:
                    continue
                if candidate == root or candidate.endswith(f".{root}"):
                    values.add(candidate)
        return sorted(values)

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        query = urllib.parse.urlencode({
            "q": f"%.{clean}",
            "exclude": "expired",
            "deduplicate": "Y",
            "output": "json",
        })
        source_url = f"{self.endpoint}?{query}"

        payload = get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )
        hosts = self._normalize_hosts(payload, clean)
        if not hosts:
            return []

        return [
            Finding.now(
                source=self.name,
                category="certificate-hosts",
                identifier=clean,
                title=f"crt.sh certificate hosts — {clean}",
                url=f"https://{clean}",
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "crt.sh Certificate Transparency JSON",
                    "provider": self.name,
                },
                data={
                    "domain": clean,
                    "hosts": hosts,
                    "count": len(hosts),
                    "expired_certificates_excluded": True,
                },
            )
        ]
