from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_context_vars: dict[str, ContextVar[dict[str, Any] | None]] = {}


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        context = get_context(record.name)
        if context:
            log_obj.update(context)

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj, default=str)


def get_logger(
    name: str | None = None,
    *,
    level: int | str | None = None,
    formatter: logging.Formatter | None = None,
    handlers: list[logging.Handler] | None = None,
    json: bool = False,
    console: bool = True,
    propagate: bool | None = None,
    **kwargs: Any,
) -> logging.Logger:
    logger = logging.getLogger(name or __name__)

    if level is not None:
        logger.setLevel(level if isinstance(level, int) else getattr(logging, level))

    if handlers is not None:
        logger.handlers.clear()
        for handler in handlers:
            logger.addHandler(handler)
    elif not logger.handlers and console:
        handler = logging.StreamHandler(sys.stdout)

        if formatter is not None:
            handler.setFormatter(formatter)
        elif json:
            handler.setFormatter(JSONFormatter())

        logger.addHandler(handler)

    if propagate is not None:
        logger.propagate = propagate

    for key, value in kwargs.items():
        setattr(logger, key, value)

    return logger


def bind_context(logger_name: str | None = None, **kwargs: Any) -> None:
    key = logger_name or "__global__"
    if key not in _context_vars:
        _context_vars[key] = ContextVar(f"context_{key}", default=None)

    current = _context_vars[key].get()
    updated = {**(current or {}), **kwargs}
    _context_vars[key].set(updated)


def get_context(logger_name: str | None = None) -> dict[str, Any] | None:
    key = logger_name or "__global__"
    if key in _context_vars:
        return _context_vars[key].get()
    if "__global__" in _context_vars:
        return _context_vars["__global__"].get()
    return None


def clear_context(logger_name: str | None = None) -> None:
    key = logger_name or "__global__"
    if key in _context_vars:
        _context_vars[key].set(None)
