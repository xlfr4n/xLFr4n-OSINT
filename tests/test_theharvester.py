from __future__ import annotations

import json

from xlfr4n_osint.providers.theharvester import TheHarvesterProvider


def test_theharvester_jsonl_parser_normalizes_in_scope_hosts() -> None:
    raw = "\n".join([
        json.dumps({
            "type": "hostname",
            "value": "api.example.com",
            "sources": ["crtsh"],
        }),
        json.dumps({
            "type": "hostname",
            "value": "other.example.org",
            "sources": ["crtsh"],
        }),
        json.dumps({
            "type": "email",
            "value": "user@example.com",
            "sources": ["hunter"],
        }),
        json.dumps({"type": "summary", "result_count": 3}),
    ])

    values = TheHarvesterProvider._parse_jsonl(raw, "example.com")

    assert values == [
        {
            "type": "hostname",
            "value": "api.example.com",
            "sources": ["crtsh"],
            "actions": [],
        },
        {
            "type": "email",
            "value": "user@example.com",
            "sources": ["hunter"],
            "actions": [],
        },
    ]
