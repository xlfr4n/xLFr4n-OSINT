from __future__ import annotations

import json
import os

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import (
    ASNProvider,
    DomainProvider,
    EmailProvider,
    IPProvider,
    PersonProvider,
    PhoneProvider,
    ProviderError,
    UsernameProvider,
)
from xlfr4n_osint.tooling import run_external_command


def _parse_spiderfoot_json(content: str) -> list[dict[str, object]]:
    text = content.strip()
    if not text:
        return []

    candidates = [text]
    start = text.find("[")
    end = text.rfind("]")
    if start >= 0 and end > start:
        candidates.append(text[start : end + 1])

    payload = None
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
            break
        except json.JSONDecodeError:
            continue

    if not isinstance(payload, list):
        raise ProviderError("spiderfoot returned no JSON event list")

    events: list[dict[str, object]] = []
    for item in payload:
        if isinstance(item, dict):
            events.append(item)
    return events


class SpiderFootProvider(
    UsernameProvider,
    PersonProvider,
    EmailProvider,
    PhoneProvider,
    DomainProvider,
    IPProvider,
    ASNProvider,
):
    name = "spiderfoot"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.command = os.getenv("XLFR4N_OSINT_SPIDERFOOT_COMMAND", "spiderfoot")

    def _search(self, target: str) -> list[Finding]:
        clean = target.strip()
        if not clean:
            return []

        command = [
            self.command,
            "-s",
            clean,
            "-u",
            "passive",
            "-o",
            "json",
        ]
        result = run_external_command(
            command,
            timeout=max(120.0, self.config.timeout * 90.0),
        )
        if result.returncode != 0:
            raise ProviderError(
                f"spiderfoot exited with code {result.returncode}: "
                f"{result.stderr.strip()[:500]}"
            )

        events = _parse_spiderfoot_json(result.stdout)
        if not events:
            return []

        findings: list[Finding] = []
        for event in events:
            event_type = str(
                event.get("type")
                or event.get("eventType")
                or "UNKNOWN"
            )
            data = str(event.get("data") or "").strip()
            if not data:
                continue

            source_data = str(event.get("source") or "")
            # SpiderFoot emits the initial target as an event in some passive
            # runs. That is not independent intelligence and should not become
            # a finding by itself.
            if (
                data.casefold() == clean.casefold()
                and (
                    not source_data
                    or source_data.casefold() == clean.casefold()
                )
            ):
                continue

            module = str(event.get("module") or "")
            source_data = str(event.get("source") or "")
            source_url = (
                source_data
                if source_data.startswith(("http://", "https://"))
                else f"tool://spiderfoot/{clean}"
            )
            url = data if data.startswith(("http://", "https://")) else source_url

            findings.append(
                Finding.now(
                    source=self.name,
                    category=f"spiderfoot:{event_type.casefold()}",
                    identifier=f"{event_type}:{data}".casefold(),
                    title=f"SpiderFoot {event_type}",
                    url=url,
                    confidence="medium",
                    provenance={
                        "source_url": source_url,
                        "retrieval_method": "external SpiderFoot passive CLI",
                        "provider": self.name,
                        "scope": "passive",
                    },
                    data={
                        "target": clean,
                        "event_type": event_type,
                        "data": data,
                        "module": module,
                        "source": source_data,
                    },
                )
            )

        return findings

    def search_username(self, username: str) -> list[Finding]:
        return self._search(username)

    def search_email(self, email: str) -> list[Finding]:
        return self._search(email)

    def search_phone(self, phone: str) -> list[Finding]:
        return self._search(phone)

    def search_domain(self, domain: str) -> list[Finding]:
        return self._search(domain)

    def search_ip(self, address: str) -> list[Finding]:
        return self._search(address)

    def search_asn(self, asn: str) -> list[Finding]:
        return self._search(asn)

    def search_person(self, name: str) -> list[Finding]:
        return self._search(name)
