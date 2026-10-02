from __future__ import annotations

import urllib.error
import urllib.request

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


class HTTPProvider(DomainProvider):
    name = "http"
    port = 443

    _interesting_headers = (
        "server",
        "content-type",
        "content-length",
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "location",
    )

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        url = f"https://{clean}/"
        request = urllib.request.Request(
            url,
            headers={"User-Agent": self.config.user_agent},
            method="HEAD",
        )

        response: object
        try:
            response = urllib.request.urlopen(
                request,
                timeout=self.config.timeout,
            )
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ProviderError(f"http network error: {exc}") from exc

        try:
            status = int(response.getcode())
            final_url = str(response.geturl())
            headers = {
                key.lower(): str(response.headers.get(key))
                for key in self._interesting_headers
                if response.headers.get(key) is not None
            }
        finally:
            response.close()

        return [
            Finding.now(
                source=self.name,
                category="http-metadata",
                identifier=clean,
                title=f"HTTP metadata — {clean}",
                url=final_url,
                confidence="high",
                provenance={
                    "source_url": url,
                    "retrieval_method": "HTTPS HEAD request",
                    "provider": self.name,
                },
                data={
                    "status": status,
                    "final_url": final_url,
                    "https": final_url.lower().startswith("https://"),
                    "headers": headers,
                },
            )
        ]
