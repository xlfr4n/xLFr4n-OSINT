from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.rdap_number import RDAPNumberProvider


def test_rdap_number_provider_resolves_ipv4_bootstrap() -> None:
    bootstrap = {
        "services": [
            [["192.0.2.0/24"], ["https://rdap.example/rdap/"]],
        ]
    }
    payload = {
        "objectClassName": "ip network",
        "handle": "NET-192-0-2-0-1",
        "ipVersion": "v4",
        "startAddress": "192.0.2.0",
        "endAddress": "192.0.2.255",
        "name": "TEST-NET-1",
        "country": "ZZ",
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
    }

    with patch("xlfr4n_osint.providers.rdap_number.get_json", side_effect=[bootstrap, payload]):
        findings = RDAPNumberProvider().search_ip("192.0.2.10")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.identifier == "192.0.2.10"
    assert finding.data["name"] == "TEST-NET-1"
    assert finding.data["ip_version"] == "v4"


def test_rdap_number_provider_resolves_asn_range() -> None:
    bootstrap = {
        "services": [
            [["64496-64511"], ["https://rdap.example/rdap/"]],
        ]
    }
    payload = {
        "objectClassName": "autnum",
        "handle": "AS64496",
        "startAutnum": 64496,
        "endAutnum": 64496,
        "name": "EXAMPLE-AS",
        "country": "ZZ",
        "status": ["active"],
        "events": [],
    }

    with patch("xlfr4n_osint.providers.rdap_number.get_json", side_effect=[bootstrap, payload]):
        findings = RDAPNumberProvider().search_asn("AS64496")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.identifier == "AS64496"
    assert finding.data["asn"] == 64496
    assert finding.data["name"] == "EXAMPLE-AS"


def test_rdap_number_provider_rejects_invalid_ip() -> None:
    provider = RDAPNumberProvider()
    try:
        provider.search_ip("not-an-ip")
    except ValueError as exc:
        assert "invalid IP address" in str(exc)
    else:
        raise AssertionError("invalid IP should raise ValueError")