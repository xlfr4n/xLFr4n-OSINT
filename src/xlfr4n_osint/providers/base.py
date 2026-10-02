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


class IPProvider(Provider):
    @abstractmethod
    def search_ip(self, address: str) -> list[Finding]:
        """Return public registration data for an IP address."""
        raise NotImplementedError


class ASNProvider(Provider):
    @abstractmethod
    def search_asn(self, asn: str) -> list[Finding]:
        """Return public registration data for an AS number."""
        raise NotImplementedError


class EmailProvider(Provider):
    @abstractmethod
    def search_email(self, email: str) -> list[Finding]:
        """Return public exposure findings for an email address."""
        raise NotImplementedError


class PhoneProvider(Provider):
    @abstractmethod
    def search_phone(self, phone: str) -> list[Finding]:
        """Return public exposure findings for a phone number."""
        raise NotImplementedError


class PasswordProvider(Provider):
    @abstractmethod
    def check_password(self, password: str) -> list[Finding]:
        """Return password exposure risk metadata without retaining the password."""
        raise NotImplementedError


class URLProvider(Provider):
    @abstractmethod
    def search_url(self, url: str) -> list[Finding]:
        """Return public intelligence for a URL."""
        raise NotImplementedError


class PersonProvider(Provider):
    @abstractmethod
    def search_person(self, name: str) -> list[Finding]:
        """Return public-source findings for a person/name query."""
        raise NotImplementedError
