from __future__ import annotations

import os
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.identifiers import normalize_email
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import EmailProvider, ProviderError, ProviderNotFoundError


class _HIBPEmailProvider(EmailProvider):
    api_name: str = "hibp"
    endpoint: str = ""
    retrieval_method: str = ""

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

    def _request(self, email: str) -> tuple[str, object]:
        clean = normalize_email(email)
        if not clean:
            return "", []
        if not self.api_key:
            raise ProviderError(
                "HIBP provider requires HIBP_API_KEY or XLFR4N_OSINT_HIBP_API_KEY"
            )
        encoded = urllib.parse.quote(clean, safe="")
        source_url = f"{self.endpoint}/{encoded}"
        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
                headers={"hibp-api-key": self.api_key},
            )
        except ProviderNotFoundError:
            return source_url, []
        except ProviderError as exc:
            raise ProviderError(f"{self.name} {exc}") from exc
        return source_url, payload


class HIBPPastesProvider(_HIBPEmailProvider):
    name = "hibp-pastes"
    endpoint = "https://haveibeenpwned.com/api/v3/pasteaccount"
    retrieval_method = "HIBP PasteAccount API"

    def search_email(self, email: str) -> list[Finding]:
        source_url, payload = self._request(email)
        if not source_url:
            return []
        if not isinstance(payload, list):
            raise ProviderError("hibp-pastes returned an unexpected response")

        findings: list[Finding] = []
        clean = normalize_email(email)
        for paste in payload:
            if not isinstance(paste, dict):
                continue
            source = str(paste.get("Source") or paste.get("source") or "unknown")
            paste_id = str(paste.get("Id") or paste.get("id") or "")
            identifier = f"paste:{source}:{paste_id or clean}".casefold()
            findings.append(
                Finding.now(
                    source=self.name,
                    category="paste-exposure",
                    identifier=identifier,
                    title=f"HIBP paste exposure — {source}",
                    url=source_url,
                    confidence="high",
                    provenance={
                        "source_url": source_url,
                        "retrieval_method": self.retrieval_method,
                        "provider": self.name,
                        "upstream_attribution": "Have I Been Pwned",
                    },
                    data={
                        "identifier_type": "email",
                        "email": clean,
                        "source": source,
                        "paste_id": paste_id or None,
                        "title": paste.get("Title"),
                        "date": paste.get("Date"),
                        "email_count": paste.get("EmailCount"),
                        "raw_content_retained": False,
                    },
                )
            )
        return findings


class HIBPStealerLogsProvider(_HIBPEmailProvider):
    name = "hibp-stealerlogs"
    endpoint = "https://haveibeenpwned.com/api/v3/stealerlogsbyemail"
    retrieval_method = "HIBP StealerLogsByEmail API"

    def search_email(self, email: str) -> list[Finding]:
        source_url, payload = self._request(email)
        if not source_url:
            return []
        if not isinstance(payload, list):
            raise ProviderError("hibp-stealerlogs returned an unexpected response")

        clean = normalize_email(email)
        findings: list[Finding] = []
        for domain in payload:
            if not isinstance(domain, str) or not domain.strip():
                continue
            domain = domain.strip().lower()
            findings.append(
                Finding.now(
                    source=self.name,
                    category="stealer-log-exposure",
                    identifier=f"{clean}:{domain}".casefold(),
                    title=f"HIBP stealer-log domain — {domain}",
                    url=source_url,
                    confidence="high",
                    provenance={
                        "source_url": source_url,
                        "retrieval_method": self.retrieval_method,
                        "provider": self.name,
                        "upstream_attribution": "Have I Been Pwned",
                    },
                    data={
                        "identifier_type": "email",
                        "email": clean,
                        "website_domain": domain,
                        "credential_values_retained": False,
                    },
                )
            )
        return findings
