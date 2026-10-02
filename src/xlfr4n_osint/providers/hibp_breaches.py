from __future__ import annotations

import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.identifiers import normalize_email
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import EmailProvider, ProviderError, ProviderNotFoundError


class HIBPBreachesProvider(EmailProvider):
    name = "hibp-breaches"
    endpoint = "https://haveibeenpwned.com/api/v3/breachedaccount"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("HIBP_API_KEY") or os.getenv(
            "XLFR4N_OSINT_HIBP_API_KEY"
        )

    def search_email(self, email: str) -> list[Finding]:
        clean = normalize_email(email)
        if not clean:
            return []
        if not self.api_key:
            raise ProviderError(
                "hibp-breaches requires HIBP_API_KEY or XLFR4N_OSINT_HIBP_API_KEY"
            )

        encoded = urllib.parse.quote(clean, safe="")
        source_url = f"{self.endpoint}/{encoded}"
        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
                headers={
                    "hibp-api-key": self.api_key,
                },
            )
        except ProviderNotFoundError:
            return []
        except ProviderError as exc:
            raise ProviderError(f"hibp-breaches {exc}") from exc

        if not isinstance(payload, list):
            raise ProviderError("hibp-breaches returned an unexpected response")

        findings: list[Finding] = []
        for breach in payload:
            if not isinstance(breach, dict):
                continue
            name = str(breach.get("Name") or breach.get("name") or "unknown-breach")
            findings.append(
                Finding.now(
                    source=self.name,
                    category="breach-exposure",
                    identifier=f"hibp:{name}".casefold(),
                    title=name,
                    url=source_url,
                    confidence="high",
                    provenance={
                        "source_url": source_url,
                        "retrieval_method": "HIBP BreachedAccount API",
                        "provider": self.name,
                    },
                    data={
                        "account": clean,
                        "name": name,
                        "title": breach.get("Title"),
                        "domain": breach.get("Domain"),
                        "breach_date": breach.get("BreachDate"),
                        "added_date": breach.get("AddedDate"),
                        "modified_date": breach.get("ModifiedDate"),
                        "pwn_count": breach.get("PwnCount"),
                        "data_classes": breach.get("DataClasses", []),
                        "verified": breach.get("IsVerified"),
                        "fabricated": breach.get("IsFabricated"),
                        "sensitive": breach.get("IsSensitive"),
                        "retired": breach.get("IsRetired"),
                        "spam_list": breach.get("IsSpamList"),
                    },
                )
            )
        return findings
