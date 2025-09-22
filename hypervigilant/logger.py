from __future__ import annotations

import logging
import sys
from typing import Any


def get_logger(
    name: str | None = None,
    *,
    level: int | str | None = None,
    handlers: list[logging.Handler] | None = None,
    formatter: logging.Formatter | None = None,
    propagate: bool | None = None,
    **kwargs: Any,
) -> logging.Logger:
    logger = logging.getLogger(name or __name__)

    if level is not None:
        logger.setLevel(level if isinstance(level, int) else getattr(logging, level))

    if handlers is not None:
        logger.handlers.clear()
        for handler in handlers:
            if formatter and not handler.formatter:
                handler.setFormatter(formatter)
            logger.addHandler(handler)
    elif not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if formatter:
            handler.setFormatter(formatter)
        logger.addHandler(handler)

    if propagate is not None:
        logger.propagate = propagate

    for key, value in kwargs.items():
        setattr(logger, key, value)

    return logger
