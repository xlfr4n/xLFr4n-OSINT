from __future__ import annotations

from unittest.mock import patch

import pytest

from xlfr4n_osint.providers.rdap import RDAPProvider


def test_normalize_domain_accepts_unicode_and_trailing_dot() -> None:
    assert RDAPProvider.normalize_domain("ExÄmple.com.") == "xn--exmple-cua.com"


def test_normalize_domain_rejects_urls() -> None:
    with pytest.raises(ValueError):
        RDAPProvider.normalize_domain("https://example.com/path")


def test_rdap_provider_resolves_bootstrap_and_domain() -> None:
    bootstrap = {
        "services": [
            ["com", ["https://rdap.example/rdap/"]],
        ]
    }
    domain = {
        "objectClassName": "domain",
        "ldhName": "example.com",
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ],
        "nameservers": [
            {"ldhName": "ns1.example.net"},
            {"ldhName": "ns2.example.net"},
        ],
        "entities": [
            {"handle": "EXAMPLE-REG", "roles": ["registrar"]},
        ],
    }

    with patch(
        "xlfr4n_osint.providers.rdap.get_json",
        side_effect=[bootstrap, domain],
    ):
        findings = RDAPProvider().search_domain("Example.com.")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.identifier == "example.com"
    assert finding.data["nameservers"] == ["ns1.example.net", "ns2.example.net"]
    assert finding.data["registration_date"] == "2020-01-01T00:00:00Z"
    assert finding.data["expiration_date"] == "2030-01-01T00:00:00Z"
    assert finding.data["registrar_handles"] == ["EXAMPLE-REG"]
    assert finding.provenance["bootstrap_url"] == RDAPProvider.bootstrap_url
