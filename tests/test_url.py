from __future__ import annotations

import pytest

from xlfr4n_osint.url import normalize_url


def test_normalize_url_defaults_empty_path_and_lowercases_scheme() -> None:
    assert normalize_url("HTTPS://Example.com") == "https://example.com/"


def test_normalize_url_preserves_port_query_and_fragment() -> None:
    assert (
        normalize_url("https://Example.com:8443/a?q=1#section")
        == "https://example.com:8443/a?q=1#section"
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "example.com/path",
        "ftp://example.com",
        "https://user:pass@example.com",
        "https:///missing-host",
    ],
)
def test_normalize_url_rejects_unsafe_inputs(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_url(value)
