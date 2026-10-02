from __future__ import annotations

from collections.abc import Callable

from xlfr4n_osint.providers.base import Provider


ProviderFactory = Callable[..., Provider]


class ProviderRegistry:
    """Registry for explicitly enabled OSINT providers and capabilities."""

    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}
        self._capabilities: dict[str, set[str]] = {}

    def register(
        self,
        name: str,
        factory: ProviderFactory,
        *,
        capabilities: set[str] | frozenset[str],
    ) -> None:
        key = name.strip().lower()
        if not key:
            raise ValueError("provider name cannot be empty")
        if key in self._factories:
            raise ValueError(f"provider already registered: {key}")
        if not capabilities:
            raise ValueError(f"provider has no capabilities: {key}")

        self._factories[key] = factory
        self._capabilities[key] = set(capabilities)

    def names(self, capability: str | None = None) -> tuple[str, ...]:
        if capability is None:
            return tuple(sorted(self._factories))

        wanted = capability.strip().lower()
        return tuple(
            sorted(
                name
                for name, capabilities in self._capabilities.items()
                if wanted in capabilities
            )
        )

    def build(
        self,
        names: list[str] | None = None,
        *,
        capability: str | None = None,
        **kwargs: object,
    ) -> list[Provider]:
        selected = [item.strip().lower() for item in names or self.names(capability)]
        available = set(self.names(capability))
        unknown = sorted(set(selected) - available)
        if unknown:
            label = capability or "registered"
            raise ValueError(f"unknown {label} provider(s): {', '.join(unknown)}")
        return [self._factories[name](**kwargs) for name in selected]
