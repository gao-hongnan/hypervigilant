from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, Self, cast

import structlog
from pydantic import Field
from structlog.processors import CallsiteParameter

from .core import LOG_LEVEL_MAP, BaseLoggingConfig

if TYPE_CHECKING:
    from structlog.types import Processor


type BoundLogger = structlog.stdlib.BoundLogger


class StructlogConfig(BaseLoggingConfig):
    service_name: str = Field(default="hypervigilant")
    enable_otel: bool = Field(default=False)


class FormatterStrategy(Protocol):
    def build_processors(self, enable_otel: bool) -> list[Processor]: ...


class OutputStrategy(Protocol):
    def create_handler(self, config: StructlogConfig) -> logging.Handler: ...


def _get_otel_processor() -> Processor | None:
    try:
        from ._otel import get_otel_processor

        return get_otel_processor()
    except ImportError:
        return None


def _build_shared_processors(enable_otel: bool, timestamp_fmt: str, utc: bool) -> list[Processor]:
    processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.CallsiteParameterAdder(
            parameters=[
                CallsiteParameter.FILENAME,
                CallsiteParameter.LINENO,
                CallsiteParameter.MODULE,
            ]
        ),
        structlog.processors.TimeStamper(fmt=timestamp_fmt, utc=utc),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if enable_otel:
        otel_processor = _get_otel_processor()
        if otel_processor is not None:
            processors.append(otel_processor)

    return processors


class JsonFormatterStrategy:
    def build_processors(self, enable_otel: bool) -> list[Processor]:
        shared = _build_shared_processors(enable_otel, timestamp_fmt="iso", utc=True)
        return [
            *shared,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(),
        ]


class ConsoleFormatterStrategy:
    def build_processors(self, enable_otel: bool) -> list[Processor]:
        shared = _build_shared_processors(enable_otel, timestamp_fmt="%Y-%m-%d %H:%M:%S", utc=False)
        return [
            *shared,
            structlog.dev.ConsoleRenderer(),
        ]


class FileOutputStrategy:
    def create_handler(self, config: StructlogConfig) -> logging.Handler:
        if not config.file_path:
            raise ValueError("file_path required for FileOutputStrategy")

        log_path = Path(config.file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        handler = RotatingFileHandler(
            filename=str(log_path),
            maxBytes=config.max_bytes,
            backupCount=config.backup_count,
            encoding="utf-8",
        )
        handler.setLevel(LOG_LEVEL_MAP[config.level])
        handler.setFormatter(logging.Formatter("%(message)s"))

        return handler


class StreamOutputStrategy:
    def create_handler(self, config: StructlogConfig) -> logging.Handler:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(LOG_LEVEL_MAP[config.level])
        handler.setFormatter(logging.Formatter("%(message)s"))

        return handler


class LoggerFactory:
    _handler: logging.Handler | None = None

    @classmethod
    def create(cls: type[Self], config: StructlogConfig) -> BoundLogger:
        formatter: FormatterStrategy = JsonFormatterStrategy() if config.json_output else ConsoleFormatterStrategy()

        processors = formatter.build_processors(config.enable_otel)

        structlog.configure(
            processors=processors,
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

        output: OutputStrategy = FileOutputStrategy() if config.file_path else StreamOutputStrategy()
        new_handler = output.create_handler(config)

        root = logging.getLogger()

        if cls._handler is not None and cls._handler in root.handlers:
            root.removeHandler(cls._handler)

        root.addHandler(new_handler)
        root.setLevel(LOG_LEVEL_MAP[config.level])
        cls._handler = new_handler

        for lib_name, lib_level in config.library_log_levels.items():
            logging.getLogger(lib_name).setLevel(LOG_LEVEL_MAP[lib_level])

        structlog.contextvars.bind_contextvars(service=config.service_name)

        return cast(BoundLogger, structlog.get_logger())

    @classmethod
    def reset(cls: type[Self]) -> None:
        if cls._handler is not None:
            root = logging.getLogger()
            if cls._handler in root.handlers:
                root.removeHandler(cls._handler)
            cls._handler.close()
            cls._handler = None
        structlog.reset_defaults()
        structlog.contextvars.clear_contextvars()


def configure_logging(config: StructlogConfig | None = None) -> None:
    LoggerFactory.create(config or StructlogConfig())


def get_logger(name: str | None = None) -> BoundLogger:
    return cast(BoundLogger, structlog.get_logger(name))


def bind_context(**kwargs: Any) -> None:
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()
