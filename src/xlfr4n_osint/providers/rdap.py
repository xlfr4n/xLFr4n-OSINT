from __future__ import annotations

import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


class RDAPProvider(DomainProvider):
    name = "rdap"
    bootstrap_url = "https://data.iana.org/rdap/dns.json"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self._services: dict[str, tuple[str, ...]] | None = None

    def _load_services(self) -> dict[str, tuple[str, ...]]:
        if self._services is not None:
            return self._services

        payload = get_json(
            self.bootstrap_url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )
        services = payload.get("services") if isinstance(payload, dict) else None
        if not isinstance(services, list):
            raise ProviderError("rdap bootstrap returned an unexpected response")

        resolved: dict[str, tuple[str, ...]] = {}
        for item in services:
            if not isinstance(item, list) or len(item) != 2:
                continue
            tlds, urls = item
            if not isinstance(tlds, list) or not isinstance(urls, list):
                continue
            valid_urls = tuple(
                str(url).rstrip("/")
                for url in urls
                if str(url).startswith("http")
            )
            for tld in tlds:
                key = str(tld).lstrip(".").lower()
                if key and valid_urls:
                    resolved[key] = valid_urls

        self._services = resolved
        return resolved

    def _find_base_url(self, domain: str) -> str:
        tld = domain.rsplit(".", 1)[-1]
        urls = self._load_services().get(tld)
        if not urls:
            raise ProviderError(f"no RDAP bootstrap service for .{tld}")
        return urls[0]

    @staticmethod
    def _event_map(payload: dict) -> dict[str, str]:
        events = payload.get("events")
        if not isinstance(events, list):
            return {}
        result: dict[str, str] = {}
        for event in events:
            if not isinstance(event, dict):
                continue
            action = event.get("eventAction")
            date = event.get("eventDate")
            if action and date:
                result[str(action)] = str(date)
        return result

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        base_url = self._find_base_url(clean)
        encoded = urllib.parse.quote(clean, safe="")
        source_url = f"{base_url}/domain/{encoded}"

        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
            )
        except ProviderError as exc:
            if str(exc) == "HTTP 404":
                return []
            raise ProviderError(f"rdap {exc}") from exc

        if not isinstance(payload, dict) or payload.get("objectClassName") != "domain":
            raise ProviderError("rdap returned an unexpected domain object")

        events = self._event_map(payload)
        nameservers = []
        raw_nameservers = payload.get("nameservers")
        if isinstance(raw_nameservers, list):
            for server in raw_nameservers:
                if isinstance(server, dict) and server.get("ldhName"):
                    nameservers.append(str(server["ldhName"]).lower())

        registrar_handles = []
        entities = payload.get("entities")
        if isinstance(entities, list):
            for entity in entities:
                if not isinstance(entity, dict):
                    continue
                roles = entity.get("roles")
                handle = entity.get("handle")
                if isinstance(roles, list) and "registrar" in roles and handle:
                    registrar_handles.append(str(handle))

        return [
            Finding.now(
                source=self.name,
                category="domain-registration",
                identifier=str(payload.get("ldhName") or clean),
                title=str(payload.get("ldhName") or clean),
                url=f"https://{clean}",
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "bootstrap_url": self.bootstrap_url,
                    "retrieval_method": "IANA RDAP bootstrap + authoritative RDAP endpoint",
                    "provider": self.name,
                },
                data={
                    "domain": payload.get("ldhName") or clean,
                    "unicode_domain": payload.get("unicodeName"),
                    "status": payload.get("status", []),
                    "nameservers": nameservers,
                    "registrar_handles": registrar_handles,
                    "registration_date": events.get("registration"),
                    "expiration_date": events.get("expiration"),
                    "last_changed": events.get("last changed"),
                },
            )
        ]
