from __future__ import annotations

from collections.abc import Callable

from xlfr4n_osint.providers.base import Provider


ProviderFactory = Callable[..., Provider]


class ProviderRegistry:
    """Small registry for explicitly enabled OSINT providers."""

    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}

    def register(self, name: str, factory: ProviderFactory) -> None:
        key = name.strip().lower()
        if not key:
            raise ValueError("provider name cannot be empty")
        if key in self._factories:
            raise ValueError(f"provider already registered: {key}")
        self._factories[key] = factory

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._factories))

    def build(self, names: list[str] | None = None, **kwargs: object) -> list[Provider]:
        selected = [item.strip().lower() for item in names or self.names()]
        unknown = sorted(set(selected) - set(self._factories))
        if unknown:
            raise ValueError(f"unknown provider(s): {', '.join(unknown)}")
        return [self._factories[name](**kwargs) for name in selected]
