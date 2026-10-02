from __future__ import annotations

from collections.abc import Callable

from xlfr4n_osint.providers.base import Provider


ProviderFactory = Callable[..., Provider]


class ProviderRegistry:
    """Registry for explicitly enabled OSINT providers."""

    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}
        self._capabilities: dict[str, set[str]] = {}
        self._defaults: set[str] = set()

    def register(
        self,
        name: str,
        factory: ProviderFactory,
        *,
        capabilities: set[str] | frozenset[str],
        default_enabled: bool = True,
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
        if default_enabled:
            self._defaults.add(key)

    def names(
        self,
        capability: str | None = None,
        *,
        default_only: bool = False,
    ) -> tuple[str, ...]:
        wanted = capability.strip().lower() if capability else None
        names = self._factories.keys()

        if wanted:
            names = (
                name
                for name in names
                if wanted in self._capabilities[name]
            )

        if default_only:
            names = (name for name in names if name in self._defaults)

        return tuple(sorted(names))

    def capabilities(self, name: str) -> tuple[str, ...]:
        key = name.strip().lower()
        if key not in self._factories:
            raise ValueError(f"unknown provider: {key}")
        return tuple(sorted(self._capabilities[key]))

    def is_default_enabled(self, name: str) -> bool:
        return name.strip().lower() in self._defaults

    def build(
        self,
        names: list[str] | None = None,
        *,
        capability: str | None = None,
        all_sources: bool = False,
        **kwargs: object,
    ) -> list[Provider]:
        if names is None:
            selected = list(
                self.names(
                    capability,
                    default_only=not all_sources,
                )
            )
        else:
            selected = [item.strip().lower() for item in names]

        available = set(self.names(capability))
        unknown = sorted(set(selected) - available)
        if unknown:
            label = capability or "registered"
            raise ValueError(f"unknown {label} provider(s): {', '.join(unknown)}")

        return [self._factories[name](**kwargs) for name in selected]
