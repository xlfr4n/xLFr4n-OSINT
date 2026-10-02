from __future__ import annotations

import socket
import ssl
import urllib.parse

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.domain import normalize_domain
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import DomainProvider, ProviderError


def _flatten_name(value: tuple) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in value:
        if not isinstance(part, tuple):
            continue
        for key, item in part:
            result[str(key)] = str(item)
    return result


class TLSProvider(DomainProvider):
    name = "tls"
    port = 443

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def search_domain(self, domain: str) -> list[Finding]:
        clean = normalize_domain(domain)

        context = ssl.create_default_context()
        try:
            with socket.create_connection(
                (clean, self.port),
                timeout=self.config.timeout,
            ) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=clean,
                ) as tls_sock:
                    certificate = tls_sock.getpeercert()
                    cipher = tls_sock.cipher()
                    protocol = tls_sock.version()
        except (socket.timeout, TimeoutError) as exc:
            raise ProviderError(f"tls timeout: {exc}") from exc
        except (socket.gaierror, OSError, ssl.SSLError) as exc:
            raise ProviderError(f"tls connection error: {exc}") from exc

        if not certificate:
            raise ProviderError("tls peer returned no certificate")

        subject = _flatten_name(certificate.get("subject", ()))
        issuer = _flatten_name(certificate.get("issuer", ()))
        san = [
            str(value)
            for kind, value in certificate.get("subjectAltName", ())
            if kind == "DNS"
        ]

        cipher_data = {}
        if cipher:
            cipher_data = {
                "name": cipher[0],
                "protocol": cipher[1],
                "secret_bits": cipher[2],
            }

        source_url = f"tls://{urllib.parse.quote(clean, safe='')}:443"

        return [
            Finding.now(
                source=self.name,
                category="tls-certificate",
                identifier=clean,
                title=f"TLS certificate — {clean}",
                url=f"https://{clean}",
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "Python TLS client with system trust store",
                    "provider": self.name,
                },
                data={
                    "protocol": protocol,
                    "cipher": cipher_data,
                    "subject": subject,
                    "issuer": issuer,
                    "subject_alt_names": san,
                    "serial_number": certificate.get("serialNumber"),
                    "not_before": certificate.get("notBefore"),
                    "not_after": certificate.get("notAfter"),
                    "tls_verified": True,
                },
            )
        ]
