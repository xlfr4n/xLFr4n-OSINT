from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from xlfr4n_osint.providers.base import (
    ProviderAccessError,
    ProviderHTTPError,
    ProviderNotFoundError,
    ProviderRateLimitError,
    ProviderServiceError,
)


def get_json(
    url: str,
    *,
    timeout: float,
    user_agent: str,
    accept: str = "application/json",
) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "User-Agent": user_agent,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
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
    except json.JSONDecodeError as exc:
        raise ProviderError("source returned invalid JSON") from exc
