from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import Provider, ProviderError


class GitHubProvider(Provider):
    name = "github"

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def search_username(self, username: str) -> list[Finding]:
        clean = username.strip().lstrip("@")
        if not clean:
            return []

        encoded = urllib.parse.quote(clean, safe="")
        request = urllib.request.Request(
            f"https://api.github.com/users/{encoded}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "xLFr4n-OSINT/0.1.0",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return []
            raise ProviderError(f"github HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ProviderError(f"github network error: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ProviderError("github returned invalid JSON") from exc

        html_url = str(payload.get("html_url") or f"https://github.com/{clean}")
        public_repos = payload.get("public_repos")
        followers = payload.get("followers")

        return [
            Finding.now(
                source=self.name,
                category="public-profile",
                identifier=str(payload.get("login") or clean),
                title=str(payload.get("name") or payload.get("login") or clean),
                url=html_url,
                confidence="high",
                data={
                    "login": payload.get("login"),
                    "name": payload.get("name"),
                    "bio": payload.get("bio"),
                    "company": payload.get("company"),
                    "location": payload.get("location"),
                    "blog": payload.get("blog"),
                    "public_repos": public_repos,
                    "followers": followers,
                    "following": payload.get("following"),
                    "created_at": payload.get("created_at"),
                    "updated_at": payload.get("updated_at"),
                },
            )
        ]
