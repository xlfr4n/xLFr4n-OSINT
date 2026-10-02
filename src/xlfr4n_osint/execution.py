from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from time import monotonic
from typing import Any, Callable

from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import Provider
from xlfr4n_osint.source_status import inspect_provider


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _status_for_error(exc: BaseException) -> str:
    marker = f"{type(exc).__name__} {exc}".casefold()
    return "timeout" if isinstance(exc, TimeoutError) or "timeout" in marker or "timed out" in marker else "error"


@dataclass(slots=True)
class ProviderExecution:
    provider: str
    status: str
    started_at: str
    finished_at: str
    duration_seconds: float
    finding_count: int = 0
    error: str | None = None
    error_type: str | None = None
    skip_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "provider": self.provider,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "finding_count": self.finding_count,
        }
        if self.error:
            payload["error"] = self.error
            payload["error_type"] = self.error_type or "Exception"
        if self.skip_reason:
            payload["skip_reason"] = self.skip_reason
        return payload


def execute_providers(
    providers: list[Provider],
    *,
    method_name: str,
    value: str,
    max_workers: int = 6,
) -> tuple[list[Finding], list[dict[str, str]], list[ProviderExecution]]:
    if max_workers < 1:
        raise ValueError("max_workers must be at least 1")
    if not providers:
        return [], [], []

    worker_count = min(max_workers, len(providers))

    def invoke(provider: Provider) -> tuple[ProviderExecution, list[Finding], dict[str, str] | None]:
        started_at = _now()
        started = monotonic()
        readiness = inspect_provider(provider.name)
        if readiness.get("status") != "ready":
            reason = str(readiness.get("status") or "unavailable")
            requirement = str(readiness.get("requirement") or "")
            detail = reason + (": " + requirement if requirement else "")
            return (
                ProviderExecution(
                    provider=provider.name,
                    status="skipped",
                    started_at=started_at,
                    finished_at=_now(),
                    duration_seconds=0.0,
                    skip_reason=detail,
                ),
                [],
                None,
            )
        try:
            method: Callable[[str], list[Finding]] = getattr(provider, method_name)
            findings = method(value)
            safe_findings = list(findings or [])
            finished_at = _now()
            duration = monotonic() - started
            status = "findings" if safe_findings else "no-findings"
            return (
                ProviderExecution(
                    provider=provider.name,
                    status=status,
                    started_at=started_at,
                    finished_at=finished_at,
                    duration_seconds=duration,
                    finding_count=len(safe_findings),
                ),
                safe_findings,
                None,
            )
        except Exception as exc:
            finished_at = _now()
            duration = monotonic() - started
            error = {
                "source": provider.name,
                "error": str(exc),
                "type": type(exc).__name__,
            }
            return (
                ProviderExecution(
                    provider=provider.name,
                    status=_status_for_error(exc),
                    started_at=started_at,
                    finished_at=finished_at,
                    duration_seconds=duration,
                    error=str(exc),
                    error_type=type(exc).__name__,
                ),
                [],
                error,
            )

    futures = {}
    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="xlfr4n-osint-provider",
    ) as executor:
        for index, provider in enumerate(providers):
            futures[executor.submit(invoke, provider)] = index

        ordered: list[tuple[int, ProviderExecution, list[Finding], dict[str, str] | None]] = []
        for future in as_completed(futures):
            execution, findings, error = future.result()
            ordered.append((futures[future], execution, findings, error))

    ordered.sort(key=lambda item: item[0])

    all_findings: list[Finding] = []
    errors: list[dict[str, str]] = []
    executions: list[ProviderExecution] = []
    for _, execution, findings, error in ordered:
        executions.append(execution)
        all_findings.extend(findings)
        if error is not None:
            errors.append(error)

    return all_findings, errors, executions
