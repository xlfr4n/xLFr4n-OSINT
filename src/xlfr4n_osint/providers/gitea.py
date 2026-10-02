from __future__ import annotations

import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import ProviderError, UsernameProvider


class GiteaProvider(UsernameProvider):
    name = "gitea"
    api_base = "https://gitea.com/api/v1"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def search_username(self, username: str) -> list[Finding]:
        clean = username.strip().lstrip("@")
        if not clean:
            return []

        encoded = urllib.parse.quote(clean, safe="")
        source_url = f"{self.api_base}/users/{encoded}"

        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
            )
        except ProviderError as exc:
            if str(exc) == "HTTP 404":
                return []
            raise ProviderError(f"gitea {exc}") from exc

        identifier = str(payload.get("login") or clean)
        html_url = str(payload.get("html_url") or f"https://gitea.com/{identifier}")

        return [
            Finding.now(
                source=self.name,
                category="public-profile",
                identifier=identifier,
                title=str(payload.get("full_name") or identifier),
                url=html_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "Gitea REST API public user endpoint",
                    "provider": self.name,
                },
                data={
                    "login": payload.get("login"),
                    "full_name": payload.get("full_name"),
                    "description": payload.get("description"),
                    "website": payload.get("website"),
                    "location": payload.get("location"),
                    "followers_count": payload.get("followers_count"),
                    "following_count": payload.get("following_count"),
                    "created": payload.get("created"),
                    "type": payload.get("type"),
                    "visibility": payload.get("visibility"),
                },
            )
        ]
