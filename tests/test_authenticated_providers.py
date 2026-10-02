from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.censys import CensysProvider
from xlfr4n_osint.providers.hunter import HunterProvider
from xlfr4n_osint.providers.securitytrails import SecurityTrailsProvider
from xlfr4n_osint.providers.shodan import ShodanProvider
from xlfr4n_osint.providers.virustotal import VirusTotalProvider


def test_censys_provider_keeps_token_out_of_provenance() -> None:
    payload = {
        "result": {
            "location": {
                "country": "Spain",
                "country_code": "ES",
                "city": "Seville",
                "continent": "Europe",
            },
            "services": [
                {
                    "port": 443,
                    "service_name": "HTTPS",
                    "extended_service_name": "HTTPS",
                    "transport_protocol": "TCP",
                }
            ],
            "autonomous_system": {"asn": 64500, "name": "EXAMPLE"},
        }
    }

    with patch("xlfr4n_osint.providers.censys.get_json", return_value=payload):
        finding = CensysProvider(api_token="secret").search_ip("192.0.2.10")[0]

    assert finding.data["service_count"] == 1
    assert "secret" not in str(finding.provenance)


def test_shodan_provider_keeps_key_out_of_provenance() -> None:
    payload = {
        "ports": [80, 443],
        "hostnames": ["example.com"],
        "domains": ["example.com"],
        "org": "Example",
        "isp": "Example ISP",
        "asn": "AS64500",
        "country_name": "Spain",
        "last_update": "2026-10-02T00:00:00",
    }

    with patch("xlfr4n_osint.providers.shodan.get_json", return_value=payload) as get_json:
        finding = ShodanProvider(api_key="secret").search_ip("192.0.2.10")[0]

    request_url = get_json.call_args.args[0]
    assert "key=secret" in request_url
    assert "secret" not in str(finding.provenance)
    assert finding.data["ports"] == [80, 443]


def test_securitytrails_provider_normalizes_domain() -> None:
    payload = {
        "apex_domain": "example.com",
        "subdomain": "www",
        "current_dns": {"a": ["192.0.2.10"]},
    }

    with patch(
        "xlfr4n_osint.providers.securitytrails.get_json",
        return_value=payload,
    ):
        finding = SecurityTrailsProvider(api_key="secret").search_domain("Example.com.")[0]

    assert finding.identifier == "example.com"
    assert finding.data["current_dns"]["a"] == ["192.0.2.10"]


def test_virustotal_provider_normalizes_reputation_and_stats() -> None:
    payload = {
        "data": {
            "attributes": {
                "reputation": 3,
                "last_analysis_stats": {"malicious": 1, "harmless": 9},
                "last_analysis_date": 1760000000,
                "times_submitted": 4,
                "categories": {"example": "business"},
            }
        }
    }

    with patch(
        "xlfr4n_osint.providers.virustotal.get_json",
        return_value=payload,
    ):
        finding = VirusTotalProvider(api_key="secret").search_ip("192.0.2.10")[0]

    assert finding.data["reputation"] == 3
    assert finding.data["analysis_stats"]["malicious"] == 1
    assert "secret" not in str(finding.provenance)


def test_hunter_provider_normalizes_email_verifier() -> None:
    payload = {
        "data": {
            "status": "valid",
            "score": 100,
            "result": "deliverable",
            "regexp": True,
            "gibberish": False,
            "disposable": False,
            "webmail": False,
            "mx_records": True,
            "smtp_server": "mail.example.com",
            "smtp_check": True,
        }
    }

    with patch(
        "xlfr4n_osint.providers.hunter.get_json",
        return_value=payload,
    ):
        finding = HunterProvider(api_key="secret").search_email("user@example.com")[0]

    assert finding.data["status"] == "valid"
    assert finding.data["score"] == 100
    assert "secret" not in str(finding.provenance)
