from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar, Final, Self

from pydantic import Field

from .core import BaseLoggingConfig
from .factory import BaseLoggerFactory
from .handlers import create_rotating_file_handler, create_stream_handler

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
    def __init__(self, indent: int | None = 4) -> None:
        super().__init__()
        self._indent = indent

    @staticmethod
    def _format_timestamp(created: float) -> str:
        return datetime.fromtimestamp(created, tz=UTC).isoformat().replace("+00:00", "Z")

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": self._format_timestamp(record.created),
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

        return json.dumps(log_data, default=str, indent=self._indent, ensure_ascii=False)


class LoggerFactory(BaseLoggerFactory[NativeLoggingConfig, logging.Logger]):
    _handler: ClassVar[logging.Handler | None] = None
    _close_on_replace: ClassVar[bool] = True
    _library_levels: ClassVar[dict[str, int]] = {}

    @classmethod
    def create(cls: type[Self], config: NativeLoggingConfig) -> logging.Logger:
        handler: logging.Handler
        if config.file_path:
            handler = create_rotating_file_handler(
                config.file_path,
                config.max_bytes,
                config.backup_count,
                config.level,
            )
        else:
            handler = create_stream_handler(config.level)

        if config.json_output:
            handler.setFormatter(JSONFormatter(indent=config.json_indent))
        else:
            handler.setFormatter(logging.Formatter(fmt=config.format, datefmt=config.date_format))

        cls._replace_handler(handler)
        cls._finalize_root(config.level, config.library_log_levels)
        return logging.getLogger()


def configure_logging(config: NativeLoggingConfig | None = None) -> None:
    LoggerFactory.create(config or NativeLoggingConfig())


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(name)
