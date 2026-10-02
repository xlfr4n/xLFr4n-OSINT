from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.gitlab import GitLabProvider


def test_gitlab_provider_selects_exact_username() -> None:
    payload = [
        {"username": "other", "name": "Other", "web_url": "https://gitlab.com/other"},
        {
            "username": "xLFr4n",
            "name": "xLFr4n",
            "web_url": "https://gitlab.com/xLFr4n",
            "bio": "builder",
        },
    ]

    with patch(
        "xlfr4n_osint.providers.gitlab.get_json",
        return_value=payload,
    ):
        findings = GitLabProvider().search_username("@xlfr4n")

    assert len(findings) == 1
    assert findings[0].identifier == "xLFr4n"
    assert findings[0].source == "gitlab"
    assert findings[0].provenance["provider"] == "gitlab"
