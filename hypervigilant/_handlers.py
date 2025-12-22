from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .core import LogLevel

from .core import LOG_LEVEL_MAP


def create_rotating_file_handler(
    file_path: str,
    max_bytes: int,
    backup_count: int,
    level: LogLevel,
) -> RotatingFileHandler:
    log_path = Path(file_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        filename=str(log_path),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setLevel(LOG_LEVEL_MAP[level])
    return handler


def create_stream_handler(level: LogLevel) -> logging.StreamHandler[Any]:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(LOG_LEVEL_MAP[level])
    return handler


def apply_library_log_levels(library_log_levels: dict[str, LogLevel]) -> None:
    for lib_name, lib_level in library_log_levels.items():
        logging.getLogger(lib_name).setLevel(LOG_LEVEL_MAP[lib_level])


def remove_handler_from_root(handler: logging.Handler | None, *, close: bool = True) -> None:
    if handler is None:
        return
    root = logging.getLogger()
    if handler in root.handlers:
        root.removeHandler(handler)
    if close:
        handler.close()
