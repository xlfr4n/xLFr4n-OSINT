from __future__ import annotations

import pytest

from xlfr4n_osint.identifiers import normalize_email, normalize_phone, normalize_username


def test_normalize_username_strips_at_prefix() -> None:
    assert normalize_username("@xLFr4n") == "xLFr4n"


@pytest.mark.parametrize("value", ["../secret", "foo/bar", "foo\\bar", "foo\x00bar"])
def test_normalize_username_rejects_path_or_control_characters(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_username(value)


def test_normalize_username_rejects_excessive_length() -> None:
    with pytest.raises(ValueError):
        normalize_username("a" * 129)


def test_normalize_email_rejects_control_characters() -> None:
    with pytest.raises(ValueError):
        normalize_email("user@example.com\nX")


@pytest.mark.parametrize("value", ["+34 600 123 456", "(123) 456-789"])
def test_normalize_phone_accepts_common_public_formats(value: str) -> None:
    assert normalize_phone(value) == value


def test_normalize_phone_rejects_arbitrary_text() -> None:
    with pytest.raises(ValueError):
        normalize_phone("phone-number")
