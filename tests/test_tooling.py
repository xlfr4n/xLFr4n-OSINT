from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from xlfr4n_osint.tooling import (
    ExternalToolNotFoundError,
    ExternalToolTimeoutError,
    run_external_command,
)


def test_external_command_rejects_missing_binary() -> None:
    with patch("xlfr4n_osint.tooling.shutil.which", return_value=None):
        with pytest.raises(ExternalToolNotFoundError):
            run_external_command(["missing-tool"], timeout=1)


def test_external_command_wraps_timeout() -> None:
    with (
        patch("xlfr4n_osint.tooling.shutil.which", return_value="/bin/tool"),
        patch(
            "xlfr4n_osint.tooling.subprocess.run",
            side_effect=subprocess.TimeoutExpired(["tool"], 1),
        ),
    ):
        with pytest.raises(ExternalToolTimeoutError):
            run_external_command(["tool"], timeout=1)
