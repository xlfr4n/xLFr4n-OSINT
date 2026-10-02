from __future__ import annotations

from pathlib import Path

import pytest

from xlfr4n_osint.config import ScanConfig


def test_config_defaults_are_stable() -> None:
    config = ScanConfig.from_file(Path("/tmp/xlfr4n-osint-no-config.toml"))

    assert config.timeout == 10.0
    assert config.user_agent == "xLFr4n-OSINT/0.1.0"


def test_config_reads_toml_file(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[scan]\ntimeout = 4.5\nuser_agent = "xLFr4n-Test/1.0"\n',
        encoding="utf-8",
    )

    config = ScanConfig.from_file(path)

    assert config.timeout == 4.5
    assert config.user_agent == "xLFr4n-Test/1.0"


def test_config_rejects_invalid_scan_table(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('scan = "invalid"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="scan"):
        ScanConfig.from_file(path)


def test_config_environment_overrides_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        '[scan]\ntimeout = 8\nuser_agent = "file-agent"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("XLFR4N_OSINT_TIMEOUT", "2.25")
    monkeypatch.setenv("XLFR4N_OSINT_USER_AGENT", "env-agent")

    config = ScanConfig.from_file(path)

    assert config.timeout == 2.25
    assert config.user_agent == "env-agent"
