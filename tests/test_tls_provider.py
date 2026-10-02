from __future__ import annotations

import socket
import ssl
from unittest.mock import MagicMock, patch

from xlfr4n_osint.providers.tls import TLSProvider, _flatten_name


def test_flatten_name_normalizes_certificate_tuples() -> None:
    value = ((("commonName", "example.com"),), (("countryName", "ES"),))
    assert _flatten_name(value) == {
        "commonName": "example.com",
        "countryName": "ES",
    }


def test_tls_provider_normalizes_verified_certificate() -> None:
    tls_socket = MagicMock()
    tls_socket.getpeercert.return_value = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example CA"),),),
        "subjectAltName": (
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
        ),
        "serialNumber": "01AB",
        "notBefore": "Oct  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
    }
    tls_socket.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    tls_socket.version.return_value = "TLSv1.3"

    context = MagicMock()
    context.wrap_socket.return_value.__enter__.return_value = tls_socket
    context.wrap_socket.return_value.__exit__.return_value = None

    fake_connection = MagicMock()
    fake_connection.__enter__.return_value = fake_connection
    fake_connection.__exit__.return_value = None

    with (
        patch(
            "xlfr4n_osint.providers.tls.ssl.create_default_context",
            return_value=context,
        ),
        patch(
            "xlfr4n_osint.providers.tls.socket.create_connection",
            return_value=fake_connection,
        ),
    ):
        findings = TLSProvider().search_domain("Example.com.")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "tls-certificate"
    assert finding.data["protocol"] == "TLSv1.3"
    assert finding.data["cipher"]["secret_bits"] == 256
    assert finding.data["subject_alt_names"] == [
        "example.com",
        "www.example.com",
    ]
    assert finding.data["tls_verified"] is True


def test_tls_provider_wraps_network_errors() -> None:
    with patch(
        "xlfr4n_osint.providers.tls.socket.create_connection",
        side_effect=socket.timeout("boom"),
    ):
        try:
            TLSProvider(timeout=1).search_domain("example.com")
        except Exception as exc:
            assert "tls timeout" in str(exc)
        else:
            raise AssertionError("TLS provider should raise on timeout")
