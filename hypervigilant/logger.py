from __future__ import annotations

import logging
import sys
from collections.abc import Sequence


def get_logger(
    name: str | None = None,
    *,
    level: int | str | None = None,
    handlers: Sequence[logging.Handler] | None = None,
    formatter: logging.Formatter | None = None,
    propagate: bool = False,
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

    logger.propagate = propagate

    return logger
