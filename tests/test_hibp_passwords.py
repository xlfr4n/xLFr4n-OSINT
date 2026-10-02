from __future__ import annotations

import io
from unittest.mock import patch

from xlfr4n_osint.providers.hibp_passwords import HIBPPwnedPasswordsProvider


def test_hibp_password_provider_uses_k_anonymity_and_returns_count_only() -> None:
    password = "password"
    body = "61E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"
    response = io.BytesIO(body.encode())
    response.getcode = lambda: 200

    with patch(
        "xlfr4n_osint.providers.hibp_passwords.urllib.request.urlopen",
        return_value=response,
    ) as urlopen:

        findings = HIBPPwnedPasswordsProvider().check_password(password)

    assert len(findings) == 1
    finding = findings[0]
    requested_url = urlopen.call_args.args[0].full_url
    assert requested_url.endswith("/5BAA6")
    assert finding.data["pwned"] is True
    assert finding.data["prevalence_count"] == 42
    assert finding.data["password_retained"] is False
    assert finding.data["full_hash_sent"] is False
    assert finding.identifier.startswith("sha1-prefix:")
