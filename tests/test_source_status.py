from __future__ import annotations

from xlfr4n_osint.cli import build_registry
from xlfr4n_osint.source_status import inspect_provider, inspect_registry


def test_native_provider_is_ready() -> None:
    result = inspect_provider("github", default_enabled=True)
    assert result["status"] == "ready"
    assert result["mode"] == "default"


def test_missing_external_command_is_reported(monkeypatch) -> None:
    monkeypatch.setattr("xlfr4n_osint.source_status.shutil.which", lambda _: None)
    result = inspect_provider("maigret", default_enabled=False)
    assert result["status"] == "missing-dependency"


def test_authenticated_provider_requires_credentials(
    monkeypatch,
) -> None:
    monkeypatch.delenv("XLFR4N_OSINT_SHODAN_API_KEY", raising=False)
    result = inspect_provider("shodan", default_enabled=False)
    assert result["status"] == "missing-credentials"


def test_registry_contains_readiness_fields() -> None:
    items = inspect_registry(build_registry())
    github = next(item for item in items if item["name"] == "github")
    assert {"status", "mode", "requirement"} <= set(github)


def test_spiderfoot_uses_kali_binary_by_default(monkeypatch) -> None:
    monkeypatch.delenv("XLFR4N_OSINT_SPIDERFOOT_COMMAND", raising=False)
    result = inspect_provider("spiderfoot", default_enabled=False)
    assert result["requirement"] == "executable: spiderfoot"
