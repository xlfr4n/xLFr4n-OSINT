from __future__ import annotations

import os
import shutil
from typing import Any

COMMAND_REQUIREMENTS: dict[str, str] = {
    "maigret": "maigret",
    "sherlock": "sherlock",
    "holehe": "holehe",
    "subfinder": "subfinder",
    "amass": "amass",
    "theharvester": "theHarvester",
    "spiderfoot": os.getenv("XLFR4N_OSINT_SPIDERFOOT_COMMAND", "spiderfoot"),
    "exiftool": "exiftool",
}

CREDENTIAL_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "hibp-breaches": ("HIBP_API_KEY", "XLFR4N_OSINT_HIBP_API_KEY"),
    "hibp-pastes": ("HIBP_API_KEY", "XLFR4N_OSINT_HIBP_API_KEY"),
    "hibp-stealerlogs": ("HIBP_API_KEY", "XLFR4N_OSINT_HIBP_API_KEY"),
    "hibp-domain-breaches": ("HIBP_API_KEY", "XLFR4N_OSINT_HIBP_API_KEY"),
    "hibp-stealerlogs-domain": ("HIBP_API_KEY", "XLFR4N_OSINT_HIBP_API_KEY"),
    "censys": (
        "XLFR4N_OSINT_CENSYS_PAT",
        "XLFR4N_OSINT_CENSYS_ORGANIZATION_ID",
    ),
    "shodan": ("XLFR4N_OSINT_SHODAN_API_KEY",),
    "securitytrails": ("XLFR4N_OSINT_SECURITYTRAILS_API_KEY",),
    "virustotal": ("XLFR4N_OSINT_VIRUSTOTAL_API_KEY",),
    "hunter": ("XLFR4N_OSINT_HUNTER_API_KEY",),
    "urlscan": ("URLSCAN_API_KEY",),
    "hudsonrock": ("XLFR4N_OSINT_HUDSONROCK_API_KEY",),
    "intelligence-x": ("XLFR4N_OSINT_INTELX_API_KEY",),
}

PUBLIC_OPT_IN = {"crtsh", "leakcheck", "wayback", "commoncrawl"}


def _first_set(names: tuple[str, ...]) -> str | None:
    for name in names:
        if os.getenv(name):
            return name
    return None


def inspect_provider(name: str, *, default_enabled: bool = False) -> dict[str, Any]:
    key = name.strip().lower()
    mode = "default" if default_enabled else "opt-in"
    result: dict[str, Any] = {
        "name": key,
        "mode": mode,
        "status": "ready",
        "requirement": None,
        "configured_by": None,
    }

    command = COMMAND_REQUIREMENTS.get(key)
    if command:
        result["requirement"] = f"executable: {command}"
        if shutil.which(command) is None:
            result["status"] = "missing-dependency"
        return result

    env_names = CREDENTIAL_REQUIREMENTS.get(key)
    if env_names:
        result["requirement"] = "credential: " + " or ".join(env_names)
        configured = _first_set(env_names)
        if configured is None:
            result["status"] = "missing-credentials"
        else:
            selected = [configured]
            for env_name in env_names:
                if env_name != configured and os.getenv(env_name):
                    selected.append(env_name)
            result["configured_by"] = ", ".join(selected)
        return result

    if key in PUBLIC_OPT_IN:
        result["requirement"] = "public endpoint"
        return result

    result["requirement"] = "native provider"
    return result


def inspect_registry(registry: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for name in registry.names():
        item = {
            "name": name,
            "capabilities": list(registry.capabilities(name)),
            "default_enabled": registry.is_default_enabled(name),
        }
        item.update(
            inspect_provider(
                name,
                default_enabled=bool(item["default_enabled"]),
            )
        )
        output.append(item)
    return output


def provider_is_ready(item: dict[str, Any]) -> bool:
    return item.get("status") == "ready"
