from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from xlfr4n_osint.providers.base import ProviderError


def get_json(url: str, *, timeout: float, user_agent: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": user_agent,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise ProviderError(f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ProviderError(f"network error: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProviderError("source returned invalid JSON") from exc
