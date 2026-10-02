from __future__ import annotations

import os
import urllib.parse
from typing import Any

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.providers.base import DomainProvider, ProviderError, ProviderNotFoundError


class _HIBPDomainProvider(DomainProvider):
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

    def _request(self, domain: str, endpoint: str) -> tuple[str, object]:
        clean = normalize_domain(domain)
        if not self.api_key:
            raise ProviderError(
                "HIBP provider requires HIBP_API_KEY or XLFR4N_OSINT_HIBP_API_KEY"
            )

        source_url = (
            "https://haveibeenpwned.com/api/v3/"
            + endpoint
            + "/"
            + urllib.parse.quote(clean, safe="")
        )
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


def _add_findings(
    *,
    provider: str,
    category: str,
    domain: str,
    source_url: str,
    rows: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        alias = str(row.get("alias") or "")
        breaches = row.get("breaches")
        breach_names = [
            str(item)
            for item in breaches
            if isinstance(item, str)
        ] if isinstance(breaches, list) else []
        identifier = f"{domain}:{alias}:{','.join(breach_names)}".casefold()
        findings.append(
            Finding.now(
                source=provider,
                category=category,
                identifier=identifier,
                title=(
                    f"HIBP domain exposure — "
                    f"{alias}@{domain}" if alias else f"HIBP domain exposure — {domain}"
                ),
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "HIBP domain exposure API",
                    "provider": provider,
                    "api_tier": "authenticated",
                    "domain_control_required": "true",
                },
                data={
                    "domain": domain,
                    "alias": alias or None,
                    "breaches": breach_names,
                    "full_email_retained": False,
                },
            )
        )
    return findings


class HIBPDomainBreachesProvider(_HIBPDomainProvider):
    name = "hibp-domain-breaches"

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        source_url, payload = self._request(clean, "breachedDomain")
        if not isinstance(payload, dict):
            raise ProviderError("hibp-domain-breaches returned an unexpected response")

        rows = []
        for alias, breaches in payload.items():
            if not isinstance(alias, str):
                continue
            rows.append({
                "alias": alias,
                "breaches": breaches,
            })

        return _add_findings(
            provider=self.name,
            category="domain-breach-exposure",
            domain=clean,
            source_url=source_url,
            rows=rows,
        )


class HIBPStealerLogDomainProvider(_HIBPDomainProvider):
    name = "hibp-stealerlogs-domain"

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        source_url, payload = self._request(clean, "stealerLogsByWebsiteDomain")
        if not isinstance(payload, list):
            raise ProviderError(
                "hibp-stealerlogs-domain returned an unexpected response"
            )

        rows = []
        for email in payload:
            if not isinstance(email, str) or "@" not in email:
                continue
            alias, email_domain = email.rsplit("@", 1)
            rows.append({
                "alias": alias,
                "email_domain": email_domain,
            })

        findings: list[Finding] = []
        for row in rows:
            alias = str(row.get("alias") or "")
            email_domain = str(row.get("email_domain") or "")
            findings.append(
                Finding.now(
                    source=self.name,
                    category="stealer-log-domain-exposure",
                    identifier=f"{clean}:{alias}@{email_domain}".casefold(),
                    title=f"HIBP stealer-log exposure — {clean}",
                    url=source_url,
                    confidence="high",
                    provenance={
                        "source_url": source_url,
                        "retrieval_method": "HIBP stealer log website-domain API",
                        "provider": self.name,
                        "api_tier": "authenticated",
                        "domain_control_required": "true",
                    },
                    data={
                        "website_domain": clean,
                        "email_alias": alias or None,
                        "email_domain": email_domain or None,
                        "full_email_retained": False,
                    },
                )
            )
        return findings
