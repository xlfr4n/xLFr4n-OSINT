from __future__ import annotations

from abc import ABC, abstractmethod

from xlfr4n_osint.models import Finding


class ProviderError(RuntimeError):
    """Base error for provider failures."""


class ProviderHTTPError(ProviderError):
    """Remote HTTP failure with a stable status code."""

    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class ProviderNotFoundError(ProviderHTTPError):
    """The requested public resource does not exist."""


class ProviderRateLimitError(ProviderHTTPError):
    """The provider rejected a request because of rate limiting."""


class ProviderAccessError(ProviderHTTPError):
    """The provider rejected access to the requested endpoint."""


class ProviderServiceError(ProviderHTTPError):
    """The provider reported a server-side failure."""


class Provider(ABC):
    name: str


class UsernameProvider(Provider):
    @abstractmethod
    def search_username(self, username: str) -> list[Finding]:
        """Return public-source findings for a username."""
        raise NotImplementedError


class DomainProvider(Provider):
    @abstractmethod
    def search_domain(self, domain: str) -> list[Finding]:
        """Return public-source findings for a domain."""
        raise NotImplementedError
