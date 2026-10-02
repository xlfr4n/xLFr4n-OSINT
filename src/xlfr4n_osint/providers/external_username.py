from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.identifiers import normalize_email, normalize_phone, normalize_username
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



def _parse_holehe_csv(path: Path) -> list[dict[str, str]]:
    """Parse legacy Holehe CSV exports for backward compatibility."""
    with path.open(
        "r",
        newline="",
        encoding="utf-8",
        errors="replace",
    ) as handle:
        rows: list[dict[str, str]] = []
        for row in csv.DictReader(handle):
            if str(row.get("exists", "")).casefold() in {"true", "yes", "claimed"}:
                rows.append({key: str(value) for key, value in row.items()})
        return rows



def _parse_holehe_output(content: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith("[+] "):
            continue
        domain = stripped[4:].strip().split(maxsplit=1)[0].rstrip(",")
        if not domain or "." not in domain:
            continue
        rows.append(
            {
                "domain": domain,
                "exists": "true",
                "rateLimit": "false",
            }
        )
    return rows


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
        clean = normalize_username(username)
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
                url = str(row.get("url_user") or "").strip()
                url_main = str(row.get("url_main") or "").strip()
                if not url:
                    continue
                # A site homepage is not an account/profile finding. Sherlock
                # can legitimately return a claimed status for generic URLs.
                if url_main and url.rstrip("/") == url_main.rstrip("/"):
                    continue
                findings.append(
                    Finding.now(
                        source=self.name,
                        category="username-account",
                        identifier=f"{platform}:{clean}".casefold(),
                        title=platform,
                        url=url,
                        confidence="medium",
                        provenance=_tool_provenance(self.name, command),
                        data={
                            "username": clean,
                            "platform": platform,
                            "status": exists,
                            "http_status": row.get("http_status"),
                            "response_time_s": row.get("response_time_s"),
                            "url_main": url_main or None,
                            "verification": "tool-asserted",
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


    def search_email(self, email: str) -> list[Finding]:
        clean = normalize_email(email)
        if not clean:
            return []

        command = [
            "holehe",
            clean,
            "--no-color",
            "--no-clear",
            "--only-used",
            "-T",
            str(max(1, int(self.config.timeout))),
        ]
        result = run_external_command(
            command,
            timeout=max(60.0, self.config.timeout * 10.0),
        )
        if result.returncode != 0:
            raise ProviderError(
                f"holehe exited with code {result.returncode}: "
                f"{result.stderr.strip()[:500]}"
            )

        rows = _parse_holehe_output(result.stdout)
        findings: list[Finding] = []
        for row in rows:
            service = row.get("domain") or "unknown-service"
            findings.append(
                Finding.now(
                    source=self.name,
                    category="email-account-presence",
                    identifier=f"{service}:{clean}".casefold(),
                    title=str(service),
                    url=f"https://{service}",
                    confidence="medium",
                    provenance=_tool_provenance(self.name, command),
                    data={
                        "email": clean,
                        "service": service,
                        "exists": True,
                        "rate_limit": False,
                        "recovery_email": None,
                        "recovery_phone": None,
                        "verification": "tool-asserted",
                    },
                )
            )

        return findings
