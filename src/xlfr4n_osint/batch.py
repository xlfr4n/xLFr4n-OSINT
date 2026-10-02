from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from xlfr4n_osint.execution import execute_providers
from xlfr4n_osint.models import ScanReport
from xlfr4n_osint.registry import ProviderRegistry


@dataclass(frozen=True, slots=True)
class BatchItem:
    type: str
    value: str
    sources: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "BatchItem":
        item_type = str(payload.get("type", "")).strip().lower()
        value = str(payload.get("value", "")).strip()
        if item_type not in {"username", "domain", "email", "phone", "password", "ip", "asn", "url", "person", "hash", "file"}:
            raise ValueError(f"unsupported batch item type: {item_type}")
        if not value:
            raise ValueError("batch item value cannot be empty")

        raw_sources = payload.get("sources", [])
        if raw_sources is None:
            raw_sources = []
        if not isinstance(raw_sources, list) or not all(isinstance(x, str) for x in raw_sources):
            raise ValueError("batch item sources must be a string list")

        return cls(
            type=item_type,
            value=value,
            sources=tuple(x.strip() for x in raw_sources if x.strip()),
        )


def load_jsonl(path: str | Path) -> list[BatchItem]:
    items: list[BatchItem] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"line {line_number} must be a JSON object")
            try:
                items.append(BatchItem.from_dict(payload))
            except ValueError as exc:
                raise ValueError(f"line {line_number}: {exc}") from exc
    return items


def _method_for(item_type: str) -> str:
    return {
        "username": "search_username",
        "domain": "search_domain",
        "email": "search_email",
        "phone": "search_phone",
        "password": "check_password",
        "ip": "search_ip",
        "asn": "search_asn",
        "url": "search_url",
        "person": "search_person",
        "hash": "search_hash",
        "file": "inspect_file",
    }[item_type]


def run_item(
    item: BatchItem,
    registry: ProviderRegistry,
    *,
    timeout: float,
    user_agent: str,
    all_sources: bool = False,
    provider_workers: int = 6,
) -> ScanReport:
    report = ScanReport(
        query="<redacted-password>" if item.type == "password" else item.value
    )
    capability = item.type

    try:
        providers = registry.build(
            list(item.sources) if item.sources else None,
            capability=capability,
            all_sources=all_sources,
            timeout=timeout,
            user_agent=user_agent,
        )
    except (ValueError, TypeError) as exc:
        report.errors.append({
            "source": "registry",
            "error": str(exc),
            "type": type(exc).__name__,
        })
        return report

    findings, errors, executions = execute_providers(
        providers,
        method_name=_method_for(item.type),
        value=item.value,
        max_workers=provider_workers,
    )
    report.findings.extend(findings)
    report.errors.extend(errors)
    report.provider_runs.extend(
        execution.to_dict() for execution in executions
    )
    return report


def run_batch(
    items: list[BatchItem],
    registry: ProviderRegistry,
    *,
    timeout: float,
    user_agent: str,
    max_workers: int = 1,
    all_sources: bool = False,
    provider_workers: int = 6,
) -> list[ScanReport]:
    if max_workers < 1:
        raise ValueError("max_workers must be at least 1")
    if provider_workers < 1:
        raise ValueError("provider_workers must be at least 1")

    if max_workers == 1:
        return [
            run_item(
                item,
                registry,
                timeout=timeout,
                user_agent=user_agent,
                all_sources=all_sources,
                provider_workers=provider_workers,
            )
            for item in items
        ]

    reports: list[ScanReport | None] = [None] * len(items)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                run_item,
                item,
                registry,
                timeout=timeout,
                user_agent=user_agent,
                all_sources=all_sources,
                provider_workers=provider_workers,
            ): index
            for index, item in enumerate(items)
        }
        for future in as_completed(future_map):
            reports[future_map[future]] = future.result()

    return [report for report in reports if report is not None]
