from __future__ import annotations

import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.identifiers import normalize_email
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, EmailProvider, ProviderError


class HunterProvider(DomainProvider, EmailProvider):
    name = "hunter"
    base_url = "https://api.hunter.io/v2"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("XLFR4N_OSINT_HUNTER_API_KEY")

    def _get(self, path: str, params: dict[str, str]) -> object:
        if not self.api_key:
            raise ProviderError("hunter requires XLFR4N_OSINT_HUNTER_API_KEY")

        query = urllib.parse.urlencode(params)
        source_url = f"{self.base_url}/{path}?{query}"
        return get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers={"X-API-KEY": self.api_key},
        )

    def search_email(self, email: str) -> list[Finding]:
        clean = normalize_email(email)
        payload = self._get("email-verifier", {"email": clean})
        if not isinstance(payload, dict):
            raise ProviderError("hunter verifier returned an unexpected response")

        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        return [
            Finding.now(
                source=self.name,
                category="email-verification",
                identifier=clean.casefold(),
                title=f"Hunter verification — {clean}",
                url=f"{self.base_url}/email-verifier",
                confidence="medium",
                provenance={
                    "source_url": f"{self.base_url}/email-verifier?email={urllib.parse.quote(clean, safe='')}",
                    "retrieval_method": "Hunter Email Verifier API",
                    "provider": self.name,
                    "api_tier": "authenticated",
                },
                data={
                    "email": clean,
                    "status": data.get("status"),
                    "score": data.get("score"),
                    "result": data.get("result"),
                    "regexp": data.get("regexp"),
                    "gibberish": data.get("gibberish"),
                    "disposable": data.get("disposable"),
                    "webmail": data.get("webmail"),
                    "mx_records": data.get("mx_records"),
                    "smtp_server": data.get("smtp_server"),
                    "smtp_check": data.get("smtp_check"),
                },
            )
        ]

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        payload = self._get("domain-search", {"domain": clean})
        if not isinstance(payload, dict):
            raise ProviderError("hunter domain search returned an unexpected response")

        data = payload.get("data")
        data = data if isinstance(data, dict) else {}
        emails = data.get("emails")
        normalized = []
        if isinstance(emails, list):
            for item in emails[:100]:
                if isinstance(item, dict) and item.get("value"):
                    normalized.append({
                        "email": item.get("value"),
                        "type": item.get("type"),
                        "confidence": item.get("confidence"),
                        "sources": item.get("sources"),
                    })

        return [
            Finding.now(
                source=self.name,
                category="email-discovery",
                identifier=clean,
                title=f"Hunter email discovery — {clean}",
                url=f"{self.base_url}/domain-search",
                confidence="medium",
                provenance={
                    "source_url": f"{self.base_url}/domain-search?domain={urllib.parse.quote(clean, safe='')}",
                    "retrieval_method": "Hunter Domain Search API",
                    "provider": self.name,
                    "api_tier": "authenticated",
                },
                data={
                    "domain": clean,
                    "emails": normalized,
                    "count": len(normalized),
                },
            )
        ]
