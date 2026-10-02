from __future__ import annotations

import urllib.error
import urllib.request
from unittest.mock import patch

import pytest

from xlfr4n_osint.http import get_text, post_json
from xlfr4n_osint.providers.base import (
    ProviderAccessError,
    ProviderRateLimitError,
    ProviderServiceError,
)
from xlfr4n_osint.retry import RetryPolicy


class _Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://example.test",
        code,
        "error",
        {},
        None,
    )


def test_http_retries_rate_limit_then_succeeds() -> None:
    responses = [urllib.error.HTTPError(
        "https://example.test",
        429,
        "rate",
        {},
        None,
    ), _Response(b"ok")]

    with patch(
        "xlfr4n_osint.http.urllib.request.urlopen",
        side_effect=responses,
    ) as urlopen:
        value = get_text(
            "https://example.test",
            timeout=1,
            user_agent="test",
            retry_policy=RetryPolicy(max_attempts=2, base_delay=0),
        )

    assert value == "ok"
    assert urlopen.call_count == 2


def test_http_does_not_retry_auth_failure() -> None:
    with patch(
        "xlfr4n_osint.http.urllib.request.urlopen",
        side_effect=_http_error(401),
    ) as urlopen:
        with pytest.raises(ProviderAccessError):
            get_text(
                "https://example.test",
                timeout=1,
                user_agent="test",
                retry_policy=RetryPolicy(max_attempts=4, base_delay=0),
            )

    assert urlopen.call_count == 1


def test_http_retries_server_failure_until_budget_exhausted() -> None:
    with patch(
        "xlfr4n_osint.http.urllib.request.urlopen",
        side_effect=_http_error(503),
    ) as urlopen:
        with pytest.raises(ProviderServiceError):
            get_text(
                "https://example.test",
                timeout=1,
                user_agent="test",
                retry_policy=RetryPolicy(max_attempts=3, base_delay=0),
            )

    assert urlopen.call_count == 3

def test_post_json_accepts_empty_204_response() -> None:
    response = _Response(b"")

    with patch(
        "xlfr4n_osint.http.urllib.request.urlopen",
        return_value=response,
    ):
        assert post_json(
            "https://example.test/webhook",
            {"content": "hello"},
            timeout=1,
            user_agent="test",
            retry_policy=RetryPolicy(max_attempts=1, base_delay=0),
        ) is None

