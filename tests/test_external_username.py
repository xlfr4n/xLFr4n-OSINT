from __future__ import annotations

from pathlib import Path

from xlfr4n_osint.providers.external_username import (
    _parse_maigret_ndjson,
    _parse_sherlock_csv,
)


def test_parse_maigret_ndjson_keeps_claimed_results() -> None:
    raw = (
        '{"status":"Claimed","site_name":"Example","url":"https://example.com/u"}\n'
        '{"status":"Available","site_name":"Other","url":"https://other.example"}\n'
        'not-json\n'
    )

    records = _parse_maigret_ndjson(raw)

    assert len(records) == 1
    assert records[0]["site_name"] == "Example"


def test_parse_sherlock_csv_keeps_found_results(tmp_path: Path) -> None:
    path = tmp_path / "xLFr4n.csv"
    path.write_text(
        "username,name,url_main,url_user,exists,http_status,response_time_s\n"
        "xLFr4n,Example,https://example.com,https://example.com/u,Claimed,200,0.2\n"
        "xLFr4n,Other,https://other.example,https://other.example/u,Available,404,0.1\n",
        encoding="utf-8",
    )

    records = _parse_sherlock_csv(path)

    assert len(records) == 1
    assert records[0]["name"] == "Example"
