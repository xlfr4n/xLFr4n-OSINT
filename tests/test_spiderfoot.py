from __future__ import annotations

import json

from xlfr4n_osint.providers.spiderfoot import _parse_spiderfoot_json


def test_parse_spiderfoot_json_accepts_plain_array() -> None:
    raw = json.dumps([
        {
            "type": "DOMAIN_NAME",
            "data": "example.com",
            "module": "sfp_dnsresolve",
            "source": "https://example.com",
        }
    ])

    events = _parse_spiderfoot_json(raw)

    assert len(events) == 1
    assert events[0]["type"] == "DOMAIN_NAME"


def test_parse_spiderfoot_json_ignores_log_prefix() -> None:
    raw = (
        "log line before JSON\n"
        '[{"type":"EMAILADDR","data":"user@example.com","module":"sfp_hunter"}]\n'
        "trailing log"
    )

    events = _parse_spiderfoot_json(raw)

    assert len(events) == 1
    assert events[0]["data"] == "user@example.com"
