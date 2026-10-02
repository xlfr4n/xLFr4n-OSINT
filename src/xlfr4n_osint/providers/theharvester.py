from __future__ import annotations

import json
import tempfile
from pathlib import Path

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError
from xlfr4n_osint.tooling import run_external_command


class TheHarvesterProvider(DomainProvider):
    name = "theharvester"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        sources: tuple[str, ...] = ("crtsh", "certspotter", "commoncrawl"),
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.sources = tuple(item.strip() for item in sources if item.strip())
        if not self.sources:
            raise ValueError("theHarvester requires at least one source")

    @staticmethod
    def _parse_jsonl(content: str, root: str) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        for line in content.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or item.get("type") == "summary":
                continue

            value = str(item.get("value") or "").strip()
            if not value:
                continue

            normalized = None
            try:
                normalized = normalize_domain(value)
            except ValueError:
                pass

            if normalized is not None and (
                normalized == root or normalized.endswith(f".{root}")
            ):
                findings.append({
                    "type": str(item.get("type")),
                    "value": normalized,
                    "sources": item.get("sources", []),
                    "actions": item.get("actions", []),
                })
                continue

            if str(item.get("type", "")).lower() in {"hostname", "domain"}:
                continue

            findings.append({
                "type": str(item.get("type")),
                "value": value,
                "sources": item.get("sources", []),
                "actions": item.get("actions", []),
            })
        return findings

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)

        with tempfile.TemporaryDirectory(prefix="xlfr4n-theharvester-") as tmp:
            basename = str(Path(tmp) / "report")
            command = [
                "theHarvester",
                "-d",
                clean,
                "-b",
                ",".join(self.sources),
                "-f",
                basename,
            ]
            result = run_external_command(
                command,
                timeout=max(120.0, self.config.timeout * 60.0),
                cwd=tmp,
            )
            if result.returncode != 0:
                raise ProviderError(
                    f"theHarvester exited with code {result.returncode}: "
                    f"{result.stderr.strip()[:500]}"
                )

            report_path = Path(f"{basename}.jsonl")
            if not report_path.exists():
                raise ProviderError("theHarvester produced no JSONL report")

            items = self._parse_jsonl(
                report_path.read_text(encoding="utf-8", errors="replace"),
                clean,
            )

        if not items:
            return []

        return [
            Finding.now(
                source=self.name,
                category="theharvester-results",
                identifier=clean,
                title=f"theHarvester passive results — {clean}",
                url=f"https://{clean}",
                confidence="medium",
                provenance={
                    "source_url": f"tool://theharvester/{clean}",
                    "retrieval_method": "external theHarvester P0 passive discovery",
                    "provider": self.name,
                    "sources": ",".join(self.sources),
                    "scope": "passive",
                },
                data={
                    "domain": clean,
                    "sources": list(self.sources),
                    "results": items,
                    "count": len(items),
                },
            )
        ]
