from __future__ import annotations

import io
import json
from unittest.mock import patch
import urllib.error

from xlfr4n_osint.providers.github import GitHubProvider


def _response(payload: dict) -> io.BytesIO:
    stream = io.BytesIO(json.dumps(payload).encode())
    stream.status = 200
    stream.getcode = lambda: 200
    return stream


def test_github_provider_normalizes_public_profile() -> None:
    payload = {
        "login": "xlfr4n",
        "name": "xLFr4n",
        "html_url": "https://github.com/xlfr4n",
        "public_repos": 7,
        "followers": 3,
        "following": 4,
        "bio": "builder",
        "company": None,
        "location": "Spain",
        "blog": "https://example.com",
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2026-10-02T00:00:00Z",
    }

    with patch(
        "xlfr4n_osint.providers.github.urllib.request.urlopen",
        return_value=_response(payload),
    ):
        findings = GitHubProvider().search_username("@xlfr4n")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "github"
    assert finding.identifier == "xlfr4n"
    assert finding.url == "https://github.com/xlfr4n"
    assert finding.data["public_repos"] == 7
    assert finding.confidence == "high"


def test_github_provider_returns_no_finding_for_missing_user() -> None:
    error = urllib.error.HTTPError(
        "https://api.github.com/users/missing",
        404,
        "Not Found",
        {},
        None,
    )

    with patch(
        "xlfr4n_osint.providers.github.urllib.request.urlopen",
        side_effect=error,
    ):
        assert GitHubProvider().search_username("missing") == []


def test_github_provider_ignores_empty_username() -> None:
    assert GitHubProvider().search_username("   @@@   ") == []
