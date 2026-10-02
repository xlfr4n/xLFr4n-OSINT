from __future__ import annotations

import hashlib
import urllib.error
import urllib.request

from xlfr4n_osint.config import ScanConfig
from xlfr4n_osint.models import Finding
from xlfr4n_osint.providers.base import PasswordProvider, ProviderError


class HIBPPwnedPasswordsProvider(PasswordProvider):
    name = "hibp-passwords"
    endpoint = "https://api.pwnedpasswords.com/range"
    prefix_length = 5

    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = "xLFr4n-OSINT/0.1.0",
    ) -> None:
        self.config = ScanConfig(timeout=timeout, user_agent=user_agent)

    def check_password(self, password: str) -> list[Finding]:
        if not password:
            raise ValueError("password cannot be empty")

        digest = hashlib.sha1(
            password.encode("utf-8"),
            usedforsecurity=False,
        ).hexdigest().upper()
        prefix = digest[: self.prefix_length]
        suffix = digest[self.prefix_length :]

        request = urllib.request.Request(
            f"{self.endpoint}/{prefix}",
            headers={
                "Add-Padding": "true",
                "User-Agent": self.config.user_agent,
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.timeout,
            ) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"hibp-passwords HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ProviderError(f"hibp-passwords network error: {exc}") from exc

        count = 0
        for line in body.splitlines():
            raw_suffix, separator, raw_count = line.partition(":")
            if separator and raw_suffix.upper() == suffix:
                try:
                    count = int(raw_count)
                except ValueError as exc:
                    raise ProviderError(
                        "hibp-passwords returned an invalid prevalence count"
                    ) from exc
                break

        source_url = f"{self.endpoint}/{prefix}"
        return [
            Finding.now(
                source=self.name,
                category="password-exposure",
                identifier=f"sha1-prefix:{prefix}",
                title="HIBP Pwned Passwords",
                url=source_url,
                confidence="high",
                provenance={
                    "source_url": source_url,
                    "retrieval_method": "HIBP Pwned Passwords k-anonymity API",
                    "provider": self.name,
                },
                data={
                    "pwned": count > 0,
                    "prevalence_count": count,
                    "hash_algorithm": "SHA-1",
                    "k_anonymity_prefix_length": self.prefix_length,
                    "password_retained": False,
                    "full_hash_sent": False,
                },
            )
        ]
