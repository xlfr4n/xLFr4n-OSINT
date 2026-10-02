from __future__ import annotations

import time

import xlfr4n_osint.providers.dns as dns_module
from xlfr4n_osint.providers.dns import DNSProvider


def test_dns_queries_record_types_in_parallel(monkeypatch) -> None:
    calls: list[str] = []

    def fake_get_json(*args, **kwargs):
        calls.append(kwargs["accept"])
        time.sleep(0.08)
        return {
            "Status": 0,
            "Answer": [
                {
                    "name": "example.com.",
                    "type": 1,
                    "TTL": 60,
                    "data": "192.0.2.10",
                }
            ],
        }

    monkeypatch.setattr(dns_module, "get_json", fake_get_json)

    provider = DNSProvider(timeout=2.0)
    started = time.monotonic()
    findings = provider.search_domain("example.com")
    elapsed = time.monotonic() - started

    assert len(calls) == len(provider.record_types)
    assert elapsed < 0.35
    assert len(findings) == 1
    assert findings[0].data["parallel"] is True
    assert findings[0].data["record_types_queried"] == list(provider.record_types)
