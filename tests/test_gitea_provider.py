from __future__ import annotations

from unittest.mock import patch

from xlfr4n_osint.providers.gitea import GiteaProvider


def test_gitea_provider_normalizes_public_user() -> None:
    payload = {
        "login": "xLFr4n",
        "full_name": "xLFr4n",
        "html_url": "https://gitea.com/xLFr4n",
        "description": "builder",
        "location": "Spain",
        "followers_count": 2,
        "following_count": 4,
        "type": "User",
        "visibility": "public",
    }

    with patch(
        "xlfr4n_osint.providers.gitea.get_json",
        return_value=payload,
    ):
        findings = GiteaProvider().search_username("@xlfr4n")

    assert len(findings) == 1
    assert findings[0].identifier == "xLFr4n"
    assert findings[0].source == "gitea"
    assert findings[0].data["visibility"] == "public"
