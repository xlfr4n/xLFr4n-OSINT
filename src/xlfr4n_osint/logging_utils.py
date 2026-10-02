from __future__ import annotations

import logging
import os


LOGGER_NAME = "xlfr4n_osint"


def get_logger(name: str | None = None) -> logging.Logger:
    logger = logging.getLogger(
        f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME
    )
    logger.addHandler(logging.NullHandler())
    return logger


def configure_logging(level: str | None = None) -> None:
    raw_level = level or os.getenv("XLFR4N_OSINT_LOG_LEVEL", "WARNING")
    normalized = raw_level.strip().upper()
    numeric = getattr(logging, normalized, None)
    if not isinstance(numeric, int):
        raise ValueError(
            f"invalid log level: {raw_level!r}; expected DEBUG, INFO, WARNING, ERROR or CRITICAL"
        )

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric)

    if not any(
        isinstance(handler, logging.StreamHandler)
        and getattr(handler, "_xlfr4n_configured", False)
        for handler in logger.handlers
    ):
        handler = logging.StreamHandler()
        handler._xlfr4n_configured = True
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s %(message)s"
            )
        )
        logger.addHandler(handler)
