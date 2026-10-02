from __future__ import annotations

from xlfr4n_osint.providers.external_domain import (
    _parse_amass_jsonl,
    _parse_subfinder_jsonl,
)


def test_parse_subfinder_jsonl_filters_to_root_domain() -> None:
    raw = (
        '{"host":"www.example.com"}\n'
        '{"host":"api.example.com"}\n'
        '{"host":"example.org"}\n'
        "not-json-host.example.com\n"
    )

    values = _parse_subfinder_jsonl(raw, "example.com")

    assert values == ["api.example.com", "not-json-host.example.com", "www.example.com"]


def test_parse_amass_jsonl_deduplicates_and_filters_to_root() -> None:
    raw = (
        '{"name":"www.example.com","domain":"example.com"}\n'
        '{"name":"api.example.com"}\n'
        '{"name":"other.example.org"}\n'
    )

    values = _parse_amass_jsonl(raw, "example.com")

    assert values == ["api.example.com", "www.example.com"]
