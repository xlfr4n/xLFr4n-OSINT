from __future__ import annotations

import logging
from dataclasses import dataclass
from time import sleep
from typing import Callable

from xlfr4n_osint.providers.base import (
    ProviderAccessError,
    ProviderError,
    ProviderRateLimitError,
    ProviderServiceError,
)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.25
    max_delay: float = 4.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay < 0:
            raise ValueError("base_delay cannot be negative")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")

    def delay_for(self, failed_attempt: int) -> float:
        return min(
            self.base_delay * (2 ** max(0, failed_attempt - 1)),
            self.max_delay,
        )


DEFAULT_RETRY_POLICY = RetryPolicy()


def _retryable(error: Exception) -> bool:
    if isinstance(error, ProviderAccessError):
        return False
    if isinstance(error, ProviderRateLimitError):
        return True
    if isinstance(error, ProviderServiceError):
        return True
    if isinstance(error, (TimeoutError, OSError)):
        return True
    if isinstance(error, ProviderError):
        return "network error:" in str(error).casefold()
    return False


def run_with_retry(
    operation: Callable[[], object],
    *,
    policy: RetryPolicy = DEFAULT_RETRY_POLICY,
    sleep_fn: Callable[[float], None] = sleep,
    logger: logging.Logger | None = None,
) -> object:
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return operation()
        except Exception as exc:
            if attempt >= policy.max_attempts or not _retryable(exc):
                raise
            delay = policy.delay_for(attempt)
            if logger:
                logger.debug(
                    "retrying provider operation attempt=%s delay=%.2f error=%s",
                    attempt + 1,
                    delay,
                    type(exc).__name__,
                )
            sleep_fn(delay)

    raise AssertionError("unreachable")
