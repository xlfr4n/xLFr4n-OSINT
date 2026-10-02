from __future__ import annotations

import ipaddress
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.http import get_json
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import ASNProvider, IPProvider, ProviderError, ProviderNotFoundError


class RDAPNumberProvider(IPProvider, ASNProvider):
    name = "rdap-number"
    ip4_bootstrap_url = "https://data.iana.org/rdap/ipv4.json"
    ip6_bootstrap_url = "https://data.iana.org/rdap/ipv6.json"
    asn_bootstrap_url = "https://data.iana.org/rdap/asn.json"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self._ip_services: list[tuple[list[str], tuple[str, ...]]] | None = None
        self._asn_services: list[tuple[list[str], tuple[str, ...]]] | None = None

    def _load_bootstrap(
        self,
        url: str,
        *,
        cache_attr: str,
    ) -> list[tuple[list[str], tuple[str, ...]]]:
        cached = getattr(self, cache_attr)
        if cached is not None:
            return cached

        payload = get_json(
            url,
            timeout=self.config.timeout,
            user_agent=self.config.user_agent,
        )
        services = payload.get("services") if isinstance(payload, dict) else None
        if not isinstance(services, list):
            raise ProviderError("rdap number bootstrap returned an unexpected response")

        resolved: list[tuple[list[str], tuple[str, ...]]] = []
        for item in services:
            if not isinstance(item, list) or len(item) != 2:
                continue
            ranges, urls = item
            if not isinstance(ranges, list) or not isinstance(urls, list):
                continue
            valid_urls = tuple(
                str(value).rstrip("/")
                for value in urls
                if str(value).startswith("http")
            )
            if valid_urls:
                resolved.append(([str(value) for value in ranges], valid_urls))

        setattr(self, cache_attr, resolved)
        return resolved

    def _ip_base(self, value: str) -> tuple[str, str]:
        address = ipaddress.ip_address(value.strip())
        bootstrap = self.ip4_bootstrap_url if address.version == 4 else self.ip6_bootstrap_url
        services = self._load_bootstrap(bootstrap, cache_attr="_ip_services")

        for ranges, urls in services:
            for prefix in ranges:
                try:
                    if address in ipaddress.ip_network(prefix, strict=False):
                        return bootstrap, urls[0]
                except ValueError:
                    continue

        raise ProviderError(f"no RDAP bootstrap service for {address}")

    def _asn_base(self, asn: int) -> tuple[str, str]:
        if asn < 0 or asn > 4294967295:
            raise ValueError("ASN must be between 0 and 4294967295")
        services = self._load_bootstrap(self.asn_bootstrap_url, cache_attr="_asn_services")

        for ranges, urls in services:
            for raw_range in ranges:
                value = raw_range.strip().lower().removeprefix("as")
                try:
                    if "-" in value:
                        start_raw, end_raw = value.split("-", 1)
                        start = int(start_raw)
                        end = int(end_raw)
                    else:
                        start = end = int(value)
                except ValueError:
                    continue
                if start <= asn <= end:
                    return self.asn_bootstrap_url, urls[0]

        raise ProviderError(f"no RDAP bootstrap service for AS{asn}")

    @staticmethod
    def _events(payload: dict) -> dict[str, str]:
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

    def search_ip(self, address: str) -> list[Finding]:
        try:
            normalized = str(ipaddress.ip_address(address.strip()))
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc

        bootstrap_url, base_url = self._ip_base(normalized)
        source_url = f"{base_url}/ip/{urllib.parse.quote(normalized, safe='')}"
        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
            )
        except ProviderNotFoundError:
            return []
        except ProviderError as exc:
            raise ProviderError(f"rdap-number {exc}") from exc

        if not isinstance(payload, dict):
            raise ProviderError("rdap IP response is not an object")

        events = self._events(payload)
        return [
            Finding.now(
                source=self.name,
                category="ip-registration",
                identifier=normalized,
                title=f"IP registration — {normalized}",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "bootstrap_url": bootstrap_url,
                    "retrieval_method": "IANA RDAP bootstrap + authoritative RDAP endpoint",
                    "provider": self.name,
                },
                data={
                    "ip": normalized,
                    "ip_version": payload.get("ipVersion"),
                    "handle": payload.get("handle"),
                    "name": payload.get("name"),
                    "type": payload.get("type"),
                    "country": payload.get("country"),
                    "start_address": payload.get("startAddress"),
                    "end_address": payload.get("endAddress"),
                    "status": payload.get("status", []),
                    "registration_date": events.get("registration"),
                    "last_changed": events.get("last changed"),
                },
            )
        ]

    def search_asn(self, asn: str) -> list[Finding]:
        value = asn.strip().lower().removeprefix("as")
        try:
            number = int(value)
        except ValueError as exc:
            raise ValueError("ASN must be numeric") from exc

        bootstrap_url, base_url = self._asn_base(number)
        source_url = f"{base_url}/autnum/{number}"
        try:
            payload = get_json(
                source_url,
                timeout=self.config.timeout,
                user_agent=self.config.user_agent,
            )
        except ProviderNotFoundError:
            return []
        except ProviderError as exc:
            raise ProviderError(f"rdap-number {exc}") from exc

        if not isinstance(payload, dict):
            raise ProviderError("rdap ASN response is not an object")

        events = self._events(payload)
        return [
            Finding.now(
                source=self.name,
                category="asn-registration",
                identifier=f"AS{number}",
                title=f"AS{number} — {payload.get('name') or payload.get('handle') or 'RDAP record'}",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "bootstrap_url": bootstrap_url,
                    "retrieval_method": "IANA RDAP bootstrap + authoritative RDAP endpoint",
                    "provider": self.name,
                },
                data={
                    "asn": number,
                    "handle": payload.get("handle"),
                    "name": payload.get("name"),
                    "start_autnum": payload.get("startAutnum"),
                    "end_autnum": payload.get("endAutnum"),
                    "country": payload.get("country"),
                    "status": payload.get("status", []),
                    "registration_date": events.get("registration"),
                    "last_changed": events.get("last changed"),
                },
            )
        ]