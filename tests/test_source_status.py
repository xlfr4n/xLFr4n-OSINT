from __future__ import annotations

from xlfr4n_osint.cli import build_registry
from xlfr4n_osint.source_status import inspect_provider, inspect_registry


def test_native_provider_is_ready() -> None:
    result = inspect_provider("github", default_enabled=True)
    assert result["status"] == "ready"
    assert result["mode"] == "default"


def test_missing_external_command_is_reported() -> None:
    result = inspect_provider("__missing__", default_enabled=False)
    assert result["status"] == "ready"


def test_registry_contains_readiness_fields() -> None:
    items = inspect_registry(build_registry())
    github = next(item for item in items if item["name"] == "github")
    assert {"status", "mode", "requirement"} <= set(github)
