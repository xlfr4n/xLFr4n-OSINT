from __future__ import annotations

import json
import platform
from typing import Any

from xlfr4n_osint.source_status import inspect_registry, provider_is_ready


def build_doctor_report(registry: Any) -> dict[str, Any]:
    providers = inspect_registry(registry)
    ready = sum(provider_is_ready(item) for item in providers)
    return {
        "schema_version": "1.0",
        "name": "xLFr4n-OSINT",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "provider_count": len(providers),
        "ready_count": ready,
        "providers": providers,
    }


def render_doctor(report: dict[str, Any]) -> str:
    lines = [
        "⚡ xLFr4n // OSINT doctor",
        f"Python: {report['python']}",
        f"Providers ready: {report['ready_count']}/{report['provider_count']}",
        "",
    ]
    for item in report["providers"]:
        status = str(item["status"]).upper()
        detail = item.get("requirement") or ""
        caps = ", ".join(item.get("capabilities", []))
        lines.append(
            f"[{status:<19}] {item['name']:<18} {item['mode']:<7} "
            f"{caps:<28} {detail}"
        )
    return "\n".join(lines)


def run_doctor(registry: Any, *, as_json: bool = False) -> int:
    report = build_doctor_report(registry)
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_doctor(report))
    return 0 if report["ready_count"] == report["provider_count"] else 1
