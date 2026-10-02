from __future__ import annotations

import os
from typing import Any

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import post_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


_SENSITIVE_KEYS = {
    "password",
    "passwords",
    "credential",
    "credentials",
    "cookie",
    "cookies",
    "token",
    "tokens",
    "secret",
    "secrets",
    "session",
    "sessions",
}


def _sanitize(value: Any, *, depth: int = 0) -> Any:
    if depth > 10:
        return "[max-depth]"

    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).casefold()
            if any(marker in normalized_key for marker in _SENSITIVE_KEYS):
                result[str(key)] = "[redacted]"
            else:
                result[str(key)] = _sanitize(item, depth=depth + 1)
        return result

    if isinstance(value, list):
        return [_sanitize(item, depth=depth + 1) for item in value[:500]]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def _summary(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"response_type": type(payload).__name__}

    sanitized = _sanitize(payload)
    if not isinstance(sanitized, dict):
        return {"response": sanitized}

    summary: dict[str, Any] = {}
    for key in (
        "status",
        "message",
        "total",
        "count",
        "compromised",
        "first_seen",
        "last_seen",
        "stealer",
        "stealers",
        "domains",
        "employees",
    ):
        if key in sanitized:
            summary[key] = sanitized[key]

    for key, value in sanitized.items():
        if key not in summary and key.casefold() in {
            "data",
            "results",
            "records",
            "overview",
            "statistics",
        }:
            summary[key] = value

    return summary


class HudsonRockProvider(DomainProvider):
    name = "hudsonrock"
    endpoint = "https://api.hudsonrock.com/json/v3/search-by-domain"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        api_key: str | None = None,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.api_key = api_key or os.getenv("XLFR4N_OSINT_HUDSONROCK_API_KEY")

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        if not self.api_key:
            raise ProviderError(
                "hudsonrock requires XLFR4N_OSINT_HUDSONROCK_API_KEY"
            )

        payload = post_json(
            self.endpoint,
            {"domains": [clean]},
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
            headers={"api-key": self.api_key},
        )

        return [
            Finding.now(
                source=self.name,
                category="infostealer-exposure",
                identifier=clean,
                title=f"Hudson Rock domain intelligence — {clean}",
                url=self.endpoint,
                confidence="medium",
                provenance={
                    "source_url": self.endpoint,
                    "retrieval_method": "Hudson Rock Cavalier domain search API",
                    "provider": self.name,
                    "api_tier": "authenticated",
                },
                data={
                    "domain": clean,
                    "response": _summary(payload),
                    "credential_values_retained": False,
                    "sensitive_fields_redacted": True,
                },
            )
        ]
