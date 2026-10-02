from __future__ import annotations


def normalize_domain(domain: str) -> str:
    value = domain.strip().rstrip(".").lower()
    if "://" in value or "/" in value:
        raise ValueError("domain must not include a URL scheme or path")
    if not value or len(value) > 253:
        raise ValueError("invalid domain")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain contains invalid IDN data") from exc

    labels = value.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        raise ValueError("invalid domain")
    return value
