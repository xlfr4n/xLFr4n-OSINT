from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

from xlfr4n_osint.logging_utils import get_logger
from xlfr4n_osint.providers.base import (
    ProviderAccessError,
    ProviderError,
    ProviderHTTPError,
    ProviderNotFoundError,
    ProviderRateLimitError,
    ProviderServiceError,
)
from xlfr4n_osint.retry import DEFAULT_RETRY_POLICY, RetryPolicy, run_with_retry


_LOGGER = get_logger("http")


def _request_bytes(
    request: urllib.request.Request,
    *,
    timeout: float,
) -> bytes:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ProviderNotFoundError("HTTP 404", exc.code) from exc
        if exc.code == 429:
            raise ProviderRateLimitError("HTTP 429", exc.code) from exc
        if exc.code in {401, 403}:
            raise ProviderAccessError(f"HTTP {exc.code}", exc.code) from exc
        if 500 <= exc.code <= 599:
            raise ProviderServiceError(f"HTTP {exc.code}", exc.code) from exc
        raise ProviderHTTPError(f"HTTP {exc.code}", exc.code) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ProviderError(f"network error: {exc}") from exc


def get_json(
    url: str,
    *,
    timeout: float,
    user_agent: str,
    accept: str = "application/json",
    headers: Mapping[str, str] | None = None,
    retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY,
) -> Any:
    request_headers = {
        "Accept": accept,
        "User-Agent": user_agent,
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)

    raw = run_with_retry(
        lambda: _request_bytes(request, timeout=timeout),
        policy=retry_policy,
        logger=_LOGGER,
    )
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ProviderError("source returned invalid JSON") from exc


def post_json(
    url: str,
    payload: object,
    *,
    timeout: float,
    user_agent: str,
    headers: Mapping[str, str] | None = None,
    retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY,
) -> Any:
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": user_agent,
    }
    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )

    raw = run_with_retry(
        lambda: _request_bytes(request, timeout=timeout),
        policy=retry_policy,
        logger=_LOGGER,
    )
    if not raw.strip():
        return None
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ProviderError("source returned invalid JSON") from exc


def get_text(
    url: str,
    *,
    timeout: float,
    user_agent: str,
    accept: str = "text/plain",
    headers: Mapping[str, str] | None = None,
    retry_policy: RetryPolicy = DEFAULT_RETRY_POLICY,
) -> str:
    request_headers = {
        "Accept": accept,
        "User-Agent": user_agent,
    }
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)

    raw = run_with_retry(
        lambda: _request_bytes(request, timeout=timeout),
        policy=retry_policy,
        logger=_LOGGER,
    )
    return raw.decode("utf-8", errors="replace")
