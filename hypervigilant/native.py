from __future__ import annotations

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Final, Self

from pydantic import Field

from .core import LOG_LEVEL_MAP, BaseLoggingConfig

_STANDARD_LOG_RECORD_ATTRS: Final[frozenset[str]] = frozenset(
    logging.LogRecord(
        name="",
        level=0,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    ).__dict__.keys()
)


class NativeLoggingConfig(BaseLoggingConfig):
    format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    date_format: str = Field(default="%Y-%m-%d %H:%M:%S")


class JSONFormatter(logging.Formatter):
    def __init__(self, datefmt: str | None = None) -> None:
        super().__init__(datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "filename": record.filename,
            "lineno": record.lineno,
            "funcName": record.funcName,
            "message": record.getMessage(),
        }

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        extras = {
            k: v for k, v in record.__dict__.items() if k not in _STANDARD_LOG_RECORD_ATTRS and not k.startswith("_")
        }
        log_data.update(extras)

        return json.dumps(log_data, default=str)


class LoggerFactory:
    _handler: logging.Handler | None = None

    @classmethod
    def create(cls: type[Self], config: NativeLoggingConfig) -> logging.Logger:
        root = logging.getLogger()

        if cls._handler is not None:
            if cls._handler in root.handlers:
                root.removeHandler(cls._handler)
            cls._handler.close()

        handler: logging.Handler
        if config.file_path:
            log_path = Path(config.file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                filename=str(log_path),
                maxBytes=config.max_bytes,
                backupCount=config.backup_count,
                encoding="utf-8",
            )
        else:
            handler = logging.StreamHandler(sys.stdout)

        handler.setLevel(LOG_LEVEL_MAP[config.level])

        if config.json_output:
            handler.setFormatter(JSONFormatter(datefmt=config.date_format))
        else:
            handler.setFormatter(logging.Formatter(fmt=config.format, datefmt=config.date_format))

        root.addHandler(handler)
        root.setLevel(LOG_LEVEL_MAP[config.level])

        cls._handler = handler

        for lib_name, lib_level in config.library_log_levels.items():
            logging.getLogger(lib_name).setLevel(LOG_LEVEL_MAP[lib_level])

        return root

    @classmethod
    def reset(cls: type[Self]) -> None:
        if cls._handler is not None:
            root = logging.getLogger()
            if cls._handler in root.handlers:
                root.removeHandler(cls._handler)
            cls._handler.close()
            cls._handler = None


def configure_logging(config: NativeLoggingConfig | None = None) -> None:
    LoggerFactory.create(config or NativeLoggingConfig())


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(name)
