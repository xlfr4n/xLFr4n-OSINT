from __future__ import annotations

import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import Provider, ProviderError


class GitLabProvider(Provider):
    name = "gitlab"
    api_base = "https://gitlab.com/api/v4"

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

        query = urllib.parse.urlencode({"username": clean})
        source_url = f"{self.api_base}/users?{query}"

        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
            )
        except ProviderError as exc:
            raise ProviderError(f"gitlab {exc}") from exc

        if not isinstance(payload, list):
            raise ProviderError("gitlab returned an unexpected response")

        matches = [
            item for item in payload
            if str(item.get("username", "")).casefold() == clean.casefold()
        ]
        if not matches:
            return []

        user = matches[0]
        identifier = str(user.get("username") or clean)
        html_url = str(user.get("web_url") or f"https://gitlab.com/{identifier}")

        return [
            Finding.now(
                source=self.name,
                category="public-profile",
                identifier=identifier,
                title=str(user.get("name") or identifier),
                url=html_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "GitLab REST API public users endpoint",
                    "provider": self.name,
                },
                data={
                    "username": user.get("username"),
                    "name": user.get("name"),
                    "state": user.get("state"),
                    "avatar_url": user.get("avatar_url"),
                    "web_url": user.get("web_url"),
                    "created_at": user.get("created_at"),
                    "bio": user.get("bio"),
                    "location": user.get("location"),
                    "public_email": None,
                },
            )
        ]
