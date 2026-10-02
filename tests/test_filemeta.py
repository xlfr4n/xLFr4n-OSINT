from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import patch

from xlfr4n_osint.filemeta import ExifToolProvider


def test_exiftool_file_provider_hashes_local_file(tmp_path: Path) -> None:
    target = tmp_path / "example.txt"
    target.write_text("hello", encoding="utf-8")
    sha256 = hashlib.sha256(b"hello").hexdigest()

    with patch(
        "xlfr4n_osint.filemeta.run_external_command",
        return_value=type(
            "Result",
            (),
            {"returncode": 0, "stdout": '[{"FileName":"example.txt","FileSize":5}]', "stderr": ""},
        )(),
    ):
        finding = ExifToolProvider().inspect_file(str(target))[0]

    assert finding.data["hashes"]["sha256"] == sha256
    assert finding.data["size_bytes"] == 5
    assert finding.data["metadata"]["FileName"] == "example.txt"
