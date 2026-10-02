from __future__ import annotations

import json
import tempfile
from pathlib import Path

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError
from xlfr4n_osint.tooling import run_external_command


def _normalize_subdomain(value: str, root: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    if not candidate:
        return None
    try:
        candidate = normalize_domain(candidate)
    except ValueError:
        return None
    if candidate != root and not candidate.endswith(f".{root}"):
        return None
    return candidate


def _parse_subfinder_jsonl(content: str, root: str) -> list[str]:
    values: set[str] = set()
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            candidate = line.strip()
        else:
            if isinstance(item, dict):
                candidate = str(item.get("host") or item.get("name") or "")
            else:
                candidate = ""
        normalized = _normalize_subdomain(candidate, root)
        if normalized:
            values.add(normalized)
    return sorted(values)


def _parse_amass_jsonl(content: str, root: str) -> list[str]:
    values: set[str] = set()
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        candidates = [
            item.get("name"),
            item.get("domain"),
            item.get("host"),
        ]
        for candidate in candidates:
            if candidate:
                normalized = _normalize_subdomain(str(candidate), root)
                if normalized:
                    values.add(normalized)
    return sorted(values)


class SubfinderProvider(DomainProvider):
    name = "subfinder"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)
        command = [
            "subfinder",
            "-d",
            clean,
            "-silent",
            "-oJ",
            "-timeout",
            str(max(1, int(self.config.timeout))),
        ]
        result = run_external_command(
            command,
            timeout=max(60.0, self.config.timeout * 30.0),
        )
        if result.returncode != 0:
            raise ProviderError(
                f"subfinder exited with code {result.returncode}: "
                f"{result.stderr.strip()[:500]}"
            )

        values = _parse_subfinder_jsonl(result.stdout, clean)
        if not values:
            return []

        source_url = f"tool://subfinder/{clean}"
        return [
            Finding.now(
                source=self.name,
                category="subdomains",
                identifier=clean,
                title=f"Subfinder subdomains — {clean}",
                url=f"https://{clean}",
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "external Subfinder passive enumeration",
                    "provider": self.name,
                    "scope": "passive",
                },
                data={
                    "domain": clean,
                    "subdomains": values,
                    "count": len(values),
                },
            )
        ]


class AmassProvider(DomainProvider):
    name = "amass"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)

        with tempfile.TemporaryDirectory(prefix="xlfr4n-amass-") as tmp:
            output = Path(tmp) / "amass.json"
            command = [
                "amass",
                "enum",
                "-passive",
                "-d",
                clean,
                "-json",
                str(output),
            ]
            result = run_external_command(
                command,
                timeout=max(60.0, self.config.timeout * 60.0),
                cwd=tmp,
            )
            if result.returncode != 0:
                raise ProviderError(
                    f"amass exited with code {result.returncode}: "
                    f"{result.stderr.strip()[:500]}"
                )
            if not output.exists():
                raise ProviderError("amass produced no JSON report")

            values = _parse_amass_jsonl(
                output.read_text(encoding="utf-8", errors="replace"),
                clean,
            )

        if not values:
            return []

        source_url = f"tool://amass/passive/{clean}"
        return [
            Finding.now(
                source=self.name,
                category="subdomains",
                identifier=clean,
                title=f"Amass passive subdomains — {clean}",
                url=f"https://{clean}",
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "external Amass passive enumeration",
                    "provider": self.name,
                    "scope": "passive",
                },
                data={
                    "domain": clean,
                    "subdomains": values,
                    "count": len(values),
                    "mode": "passive",
                },
            )
        ]
