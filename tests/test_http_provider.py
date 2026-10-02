from __future__ import annotations

from unittest.mock import MagicMock, patch

from xlfr4n_osint.providers.http import HTTPProvider


def test_http_provider_collects_selected_headers() -> None:
    response = MagicMock()
    response.getcode.return_value = 200
    response.geturl.return_value = "https://example.com/"
    response.headers.get.side_effect = lambda key: {
        "server": "example-server",
        "content-type": "text/html",
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
    }.get(key)

    with patch(
        "xlfr4n_osint.providers.http.urllib.request.urlopen",
        return_value=response,
    ):
        findings = HTTPProvider().search_domain("Example.com.")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "http-metadata"
    assert finding.data["status"] == 200
    assert finding.data["headers"]["server"] == "example-server"
    assert finding.data["headers"]["strict-transport-security"] == "max-age=31536000"
    assert "set-cookie" not in finding.data["headers"]
    assert finding.provenance["retrieval_method"] == "HTTPS HEAD request"
    response.close.assert_called_once()
