from __future__ import annotations

import urllib.parse


def normalize_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("URL cannot be empty")

    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("URL userinfo is not allowed")

    hostname = parsed.hostname.encode("idna").decode("ascii")
    netloc = hostname
    if parsed.port is not None:
        if parsed.port < 1 or parsed.port > 65535:
            raise ValueError("URL port is invalid")
        netloc = f"{hostname}:{parsed.port}"

    path = parsed.path or "/"
    return urllib.parse.urlunsplit(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.query,
            parsed.fragment,
        )
    )
