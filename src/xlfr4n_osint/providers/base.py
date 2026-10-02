from __future__ import annotations

from abc import ABC, abstractmethod

from xlfr4n_osint.models import Finding


class ProviderError(RuntimeError):
    """Raised when an OSINT provider cannot complete a request."""


class Provider(ABC):
    name: str

    @abstractmethod
    def search_username(self, username: str) -> list[Finding]:
        """Return public-source findings for a username."""
        raise NotImplementedError
