from __future__ import annotations

import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.identifiers import normalize_email, normalize_phone, normalize_username
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import (
    EmailProvider,
    PhoneProvider,
    ProviderError,
    UsernameProvider,
)


class LeakCheckProvider(
    UsernameProvider,
    EmailProvider,
    PhoneProvider,
):
    name = "leakcheck"
    endpoint = "https://leakcheck.io/api/public"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def _search(self, identifier: str, *, kind: str) -> list[Finding]:
        if kind == "email":
            value = normalize_email(identifier)
        elif kind == "phone":
            value = normalize_phone(identifier)
        else:
            value = normalize_username(identifier)
        if not value:
            return []

        query = urllib.parse.urlencode({"check": value})
        source_url = f"{self.endpoint}?{query}"
        payload = get_json(
            source_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )

        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise ProviderError("leakcheck returned an unexpected response")

        try:
            found = int(payload.get("found", 0))
        except (TypeError, ValueError) as exc:
            raise ProviderError("leakcheck returned an invalid finding count") from exc

        fields = payload.get("fields", [])
        sources = payload.get("sources", [])
        if not isinstance(fields, list) or not isinstance(sources, list):
            raise ProviderError("leakcheck returned invalid metadata collections")

        normalized_sources: list[dict[str, str | None]] = []
        for source in sources:
            if not isinstance(source, dict) or not source.get("name"):
                continue
            normalized_sources.append({
                "name": str(source["name"]),
                "date": str(source.get("date")) if source.get("date") else None,
            })

        return [
            Finding.now(
                source=self.name,
                category="breach-exposure",
                identifier=f"{kind}:{value}".casefold(),
                title=f"LeakCheck exposure — {value}",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "LeakCheck Public API",
                    "provider": self.name,
                },
                data={
                    "identifier_type": kind,
                    "found_sources": found,
                    "exposed_field_types": [
                        str(item) for item in fields if isinstance(item, str)
                    ],
                    "sources": normalized_sources,
                    "full_records_returned": False,
                    "password_values_returned": False,
                },
            )
        ]

    def search_username(self, username: str) -> list[Finding]:
        return self._search(username, kind="username")

    def search_email(self, email: str) -> list[Finding]:
        return self._search(email, kind="email")

    def search_phone(self, phone: str) -> list[Finding]:
        return self._search(phone, kind="phone")
