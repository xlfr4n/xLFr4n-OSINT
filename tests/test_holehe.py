from __future__ import annotations

from pathlib import Path

from xlfr4n_osint.providers.external_username import _parse_holehe_csv


def test_parse_holehe_csv_keeps_registered_accounts(tmp_path: Path) -> None:
    path = tmp_path / "holehe.csv"
    path.write_text(
        "name,domain,exists,rateLimit,emailrecovery,phoneNumber\n"
        "Example,example.com,true,false,,,\n"
        "Other,other.example,false,false,,,\n",
        encoding="utf-8",
    )

    rows = _parse_holehe_csv(path)

    assert len(rows) == 1
    assert rows[0]["name"] == "Example"
