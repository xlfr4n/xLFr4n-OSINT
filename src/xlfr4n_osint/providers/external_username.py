from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import EmailProvider, ProviderError, UsernameProvider
from xlfr4n_osint.tooling import run_external_command



def _parse_maigret_ndjson(content: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for line in content.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and str(item.get("status")) == "Claimed":
            records.append(item)
    return records


def _parse_sherlock_csv(path: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    with path.open(
        "r",
        newline="",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        for row in csv.DictReader(handle):
            if str(row.get("exists", "")).casefold() in {"claimed", "true", "found"}:
                records.append({key: str(value) for key, value in row.items()})
    return records


def _tool_provenance(tool: str, command: list[str]) -> dict[str, str]:
    return {
        "provider": tool,
        "retrieval_method": f"external {tool} CLI",
        "command": " ".join(command),
    }


class MaigretProvider(UsernameProvider):
    name = "maigret"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
        all_sites: bool = False,
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)
        self.all_sites = all_sites

    def search_username(self, username: str) -> list[Finding]:
        clean = username.strip().lstrip("@")
        if not clean:
            return []

        with tempfile.TemporaryDirectory(prefix="xlfr4n-maigret-") as tmp:
            command = [
                "maigret",
                clean,
                "--json",
                "ndjson",
                "--no-color",
                "--no-progressbar",
                "--folderoutput",
                ".",
            ]
            if self.all_sites:
                command.append("--all-sites")

            result = run_external_command(
                command,
                timeout=max(60.0, self.config.timeout * 60.0),
                cwd=tmp,
            )
            if result.returncode != 0:
                raise ProviderError(
                    f"maigret exited with code {result.returncode}: "
                    f"{result.stderr.strip()[:500]}"
                )

            reports = sorted(Path(tmp).glob("report_*_ndjson.json"))
            if not reports:
                raise ProviderError("maigret produced no NDJSON report")

            findings: list[Finding] = []
            for report_path in reports:
                for item in _parse_maigret_ndjson(
                    report_path.read_text(encoding="utf-8", errors="replace")
                ):
                    site = str(item.get("site_name") or "unknown-site")
                    url = str(item.get("url") or item.get("url_user") or "")
                    if not url:
                        continue
                    findings.append(
                        Finding.now(
                            source=self.name,
                            category="username-account",
                            identifier=f"{site}:{clean}".casefold(),
                            title=site,
                            url=url,
                            confidence="high",
                            provenance=_tool_provenance(self.name, command),
                            data={
                                "username": clean,
                                "site": site,
                                "status": item.get("status"),
                                "ids": item.get("ids", {}),
                                "tags": item.get("tags", []),
                                "keywords": item.get("keywords", []),
                            },
                        )
                    )

            return findings


class SherlockProvider(UsernameProvider):
    name = "sherlock"

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

        with tempfile.TemporaryDirectory(prefix="xlfr4n-sherlock-") as tmp:
            command = [
                "sherlock",
                clean,
                "--csv",
                "--folderoutput",
                ".",
                "--no-color",
                "--timeout",
                str(max(1, int(self.config.timeout))),
            ]
            result = run_external_command(
                command,
                timeout=max(60.0, self.config.timeout * 60.0),
                cwd=tmp,
            )
            if result.returncode != 0:
                raise ProviderError(
                    f"sherlock exited with code {result.returncode}: "
                    f"{result.stderr.strip()[:500]}"
                )

            reports = sorted(Path(tmp).glob(f"{clean}.csv"))
            if not reports:
                raise ProviderError("sherlock produced no CSV report")

            findings: list[Finding] = []
            for row in _parse_sherlock_csv(reports[0]):
                exists = str(row.get("exists", ""))
                platform = str(row.get("name") or "unknown-site")
                url = str(row.get("url_user") or "")
                if not url:
                    continue
                findings.append(
                    Finding.now(
                        source=self.name,
                        category="username-account",
                        identifier=f"{platform}:{clean}".casefold(),
                        title=platform,
                        url=url,
                        confidence="high",
                        provenance=_tool_provenance(self.name, command),
                        data={
                            "username": clean,
                            "platform": platform,
                            "status": exists,
                            "http_status": row.get("http_status"),
                            "response_time_s": row.get("response_time_s"),
                        },
                    )
                )

            return findings


class HoleheProvider(EmailProvider):
    name = "holehe"

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    @staticmethod
    def _parse_csv(path: Path) -> list[dict[str, str]]:
        with path.open(
            "r",
            newline="",
            encoding="utf-8",
            errors="replace",
        ) as handle:
            return [
                {key: str(value) for key, value in row.items()}
                for row in __import__("csv").DictReader(handle)
            ]

    def search_email(self, email: str) -> list[Finding]:
        clean = email.strip()
        if not clean:
            return []

        with tempfile.TemporaryDirectory(prefix="xlfr4n-holehe-") as tmp:
            output = Path(tmp) / "holehe.csv"
            command = [
                "holehe",
                clean,
                "--no-color",
                "--no-clear",
                "--only-used",
                "--csv",
                "-o",
                str(output),
                "-t",
                str(max(1, int(self.config.timeout))),
            ]
            result = run_external_command(
                command,
                timeout=max(60.0, self.config.timeout * 10.0),
                cwd=tmp,
            )
            if result.returncode != 0:
                raise ProviderError(
                    f"holehe exited with code {result.returncode}: "
                    f"{result.stderr.strip()[:500]}"
                )
            if not output.exists():
                raise ProviderError("holehe produced no CSV report")

            findings: list[Finding] = []
            for row in self._parse_csv(output):
                exists = row.get("exists", "").casefold()
                if exists not in {"true", "yes", "claimed"}:
                    continue
                service = row.get("name") or row.get("domain") or "unknown-service"
                findings.append(
                    Finding.now(
                        source=self.name,
                        category="email-account-presence",
                        identifier=f"{service}:{clean}".casefold(),
                        title=str(service),
                        url=str(row.get("domain") or ""),
                        confidence="medium",
                        provenance=_tool_provenance(self.name, command),
                        data={
                            "email": clean,
                            "service": service,
                            "exists": row.get("exists"),
                            "rate_limit": row.get("rateLimit"),
                            "recovery_email": None,
                            "recovery_phone": None,
                        },
                    )
                )

            return findings
