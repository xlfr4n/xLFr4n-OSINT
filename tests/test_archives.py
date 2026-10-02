from __future__ import annotations

from xlfr4n_osint.providers.archives import (
    CommonCrawlProvider,
    WaybackProvider,
    _compact_wayback,
    _parse_commoncrawl_jsonl,
)


def test_wayback_compacts_cdx_table() -> None:
    payload = [
        ["timestamp", "original", "statuscode", "mimetype", "digest"],
        ["20260101000000", "https://example.com/", "200", "text/html", "A"],
        ["20260201000000", "https://example.com/", "200", "text/html", "B"],
    ]

    records = _compact_wayback(payload, 10)

    assert len(records) == 2
    assert records[0]["timestamp"] == "20260101000000"
    assert records[1]["digest"] == "B"


def test_commoncrawl_parser_keeps_archive_metadata_only() -> None:
    raw = (
        '{"url":"https://example.com/","timestamp":"20260101",'
        '"status":"200","mime":"text/html","mime-detected":"text/html",'
        '"digest":"ABC","length":"123","filename":"crawl.warc.gz"}\n'
        '{"url":"https://example.com/","status":"404"}\n'
        'not-json\n'
    )

    records = _parse_commoncrawl_jsonl(raw, 10)

    assert len(records) == 2
    assert records[0]["digest"] == "ABC"
    assert records[1]["status"] == "404"


def test_archive_provider_names_are_stable() -> None:
    assert WaybackProvider.name == "wayback"
    assert CommonCrawlProvider.name == "commoncrawl"
