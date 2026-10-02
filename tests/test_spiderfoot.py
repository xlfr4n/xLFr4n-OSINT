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


def test_spiderfoot_filters_seed_target_echo(monkeypatch) -> None:
    from types import SimpleNamespace

    from xlfr4n_osint.providers.spiderfoot import SpiderFootProvider

    payload = json.dumps([
        {
            "type": "USERNAME",
            "data": "xLFr4n",
            "module": "SpiderFoot UI",
            "source": "xLFr4n",
        },
        {
            "type": "USERNAME",
            "data": "xLFr4n",
            "module": "sfp_example",
            "source": "https://example.com/xLFr4n",
        },
    ])

    def fake_run(command, *, timeout):
        return SimpleNamespace(returncode=0, stdout=payload, stderr="")

    monkeypatch.setattr(
        "xlfr4n_osint.providers.spiderfoot.run_external_command",
        fake_run,
    )

    findings = SpiderFootProvider().search_username("xLFr4n")

    assert len(findings) == 1
    assert findings[0].url == "https://example.com/xLFr4n"
