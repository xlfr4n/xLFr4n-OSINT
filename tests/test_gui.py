from __future__ import annotations

import json
from pathlib import Path

from xlfr4n_osint.gui import InvestigationService, _redact_secret
from xlfr4n_osint.models import Finding
from xlfr4n_osint.registry import ProviderRegistry


class FakeUsernameProvider:
    name = "fake"

    def __init__(self, **_: object) -> None:
        pass

    def search_username(self, username: str) -> list[Finding]:
        return [
            Finding.now(
                source=self.name,
                category="account",
                identifier=username,
                title="Fake profile",
                url="https://example.test/" + username,
                confidence="high",
            )
        ]


def test_redact_secret_recurses() -> None:
    payload = {"a": "secret", "nested": ["xxsecret", {"v": "secret"}]}
    assert _redact_secret(payload, "secret") == {
        "a": "<redacted-password>",
        "nested": ["xx<redacted-password>", {"v": "<redacted-password>"}],
    }


def test_source_snapshot_filters_capability() -> None:
    registry = ProviderRegistry()
    registry.register("fake", FakeUsernameProvider, capabilities={"username"})
    service = InvestigationService(registry, timeout=5)
    assert service.source_snapshot("username")[0]["name"] == "fake"
    assert service.source_snapshot("domain") == []


def test_scan_writes_local_report(tmp_path: Path, monkeypatch) -> None:
    registry = ProviderRegistry()
    registry.register("fake", FakeUsernameProvider, capabilities={"username"})
    monkeypatch.setenv("XLFR4N_OSINT_REPORT_DIR", str(tmp_path))
    service = InvestigationService(registry, timeout=5)
    report = service.scan(
        {"type": "username", "value": "demo", "sources": ["fake"]}
    )

    assert report["query"] == "demo"
    assert report["summary"]["finding_count"] == 1
    assert Path(tmp_path, report["scan_id"] + ".json").exists()

    loaded = json.loads(
        Path(tmp_path, report["scan_id"] + ".json").read_text()
    )
    assert loaded["findings"][0]["title"] == "Fake profile"


def test_password_scan_never_keeps_query(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class FakePasswordProvider:
        name = "fake-password"

        def __init__(self, **_: object) -> None:
            pass

        def check_password(self, password: str) -> list[Finding]:
            return [
                Finding.now(
                    source=self.name,
                    category="password-exposure",
                    identifier="prevalence",
                    title="Password prevalence",
                    url="https://example.test/passwords",
                    data={"note": f"tested={password}"},
                )
            ]

    registry = ProviderRegistry()
    registry.register(
        "fake-password",
        FakePasswordProvider,
        capabilities={"password"},
    )
    monkeypatch.setenv("XLFR4N_OSINT_REPORT_DIR", str(tmp_path))
    service = InvestigationService(registry, timeout=5)

    report = service.scan(
        {
            "type": "password",
            "value": "secret-pass",
            "sources": ["fake-password"],
        }
    )

    assert report["query"] == "<redacted-password>"
    assert "secret-pass" not in json.dumps(report)

    saved = Path(tmp_path, report["scan_id"] + ".json").read_text()
    assert "secret-pass" not in saved


def test_markdown_export_rebuilds_report(tmp_path: Path, monkeypatch) -> None:
    registry = ProviderRegistry()
    registry.register("fake", FakeUsernameProvider, capabilities={"username"})
    monkeypatch.setenv("XLFR4N_OSINT_REPORT_DIR", str(tmp_path))
    service = InvestigationService(registry, timeout=5)

    report = service.scan(
        {"type": "username", "value": "demo", "sources": ["fake"]}
    )
    markdown = service.get_markdown(report["scan_id"])

    assert "# Investigation Report" in markdown
    assert "fake" in markdown
    assert "demo" in markdown


def test_gui_assets_are_packaged() -> None:
    html, html_type = InvestigationService.asset("index.html")
    css, css_type = InvestigationService.asset("styles.css")
    js, js_type = InvestigationService.asset("app.js")
    icon, icon_type = InvestigationService.asset("favicon.svg")

    assert b"<title>xLFr4n // OSINT Console</title>" in html
    assert css_type == "text/css"
    assert b"async function runScan" in js
    assert js_type in {"text/javascript", "application/javascript"}
    assert b"<svg" in icon
    assert icon_type == "image/svg+xml"
    assert html_type == "text/html"


def test_gui_rejects_remote_binding_by_default() -> None:
    import pytest
    from xlfr4n_osint.gui import run_gui

    with pytest.raises(ValueError, match="refusing non-loopback"):
        run_gui(host="0.0.0.0", port=0, open_browser=False)
