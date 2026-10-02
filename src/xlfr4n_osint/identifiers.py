from __future__ import annotations

import re


def normalize_username(username: str) -> str:
    value = username.strip().lstrip("@")
    if not value:
        return ""
    if len(value) > 128:
        raise ValueError("username is too long")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("username contains control characters")
    if "/" in value or "\\" in value:
        raise ValueError("username cannot contain path separators")
    return value


def normalize_email(email: str) -> str:
    value = email.strip()
    if not value or len(value) > 320 or any(ord(char) < 32 for char in value):
        raise ValueError("invalid email")
    return value


_PHONE_RE = re.compile(r"^[0-9+().\-\s]{3,32}$")


def normalize_phone(phone: str) -> str:
    value = phone.strip()
    if not _PHONE_RE.fullmatch(value):
        raise ValueError("invalid phone number")
    return value