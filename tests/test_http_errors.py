from __future__ import annotations

import urllib.error
from unittest.mock import patch

import pytest

from xlfr4n_osint.http import get_json
from xlfr4n_osint.providers.base import (
    ProviderAccessError,
    ProviderHTTPError,
    ProviderNotFoundError,
    ProviderRateLimitError,
    ProviderServiceError,
)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (404, ProviderNotFoundError),
        (429, ProviderRateLimitError),
        (401, ProviderAccessError),
        (403, ProviderAccessError),
        (500, ProviderServiceError),
        (503, ProviderServiceError),
        (400, ProviderHTTPError),
    ],
)
def test_get_json_classifies_http_errors(
    status: int,
    expected: type[ProviderHTTPError],
) -> None:
    error = urllib.error.HTTPError(
        "https://example.test",
        status,
        "error",
        {},
        None,
    )

    with patch("xlfr4n_osint.http.urllib.request.urlopen", side_effect=error):
        with pytest.raises(expected) as raised:
            get_json(
                "https://example.test",
                timeout=1,
                user_agent="xLFr4n-test",
            )

    assert raised.value.status_code == status
