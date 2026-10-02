from __future__ import annotations

import logging


LOGGER_NAME = "xlfr4n_osint"


def get_logger(name: str | None = None) -> logging.Logger:
    logger = logging.getLogger(
        f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME
    )
    logger.addHandler(logging.NullHandler())
    return logger
