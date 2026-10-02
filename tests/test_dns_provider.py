from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.dns import DNSProvider


def test_dns_provider_collects_selected_public_records() -> None:
    payloads = {
        "A": {
            "Status": 0,
            "Answer": [{"name": "example.com.", "type": 1, "TTL": 300, "data": "192.0.2.10"}],
        },
        "AAAA": {"Status": 0, "Answer": []},
        "CNAME": {"Status": 0, "Answer": []},
        "MX": {
            "Status": 0,
            "Answer": [{"name": "example.com.", "type": 15, "TTL": 300, "data": "10 mail.example.com."}],
        },
        "NS": {
            "Status": 0,
            "Answer": [{"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.net."}],
        },
        "SOA": {"Status": 0, "Answer": []},
        "TXT": {
            "Status": 0,
            "Answer": [{"name": "example.com.", "type": 16, "TTL": 300, "data": "\"v=spf1 -all\""}],
        },
    }

    def fake_query(*args: object, **kwargs: object) -> dict:
        url = str(args[0])
        for record_type, payload in payloads.items():
            if f"type={record_type}" in url:
                return payload
        raise AssertionError(url)

    with patch("xlfr4n_osint.providers.dns.get_json", side_effect=fake_query):
        findings = DNSProvider().search_domain("Example.com.")

    assert len(findings) == 1
    data = findings[0].data
    assert data["records"]["A"] == ["192.0.2.10"]
    assert data["records"]["MX"] == ["10 mail.example.com."]
    assert data["nameservers"] == ["ns1.example.net."]
    assert findings[0].provenance["provider"] == "dns"
