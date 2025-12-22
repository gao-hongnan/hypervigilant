from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar, Protocol, Self, cast

import structlog
from pydantic import Field
from structlog.processors import CallsiteParameter

from ._factory import BaseLoggerFactory
from ._handlers import apply_library_log_levels, create_rotating_file_handler, create_stream_handler
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
    def __init__(self, indent: int | None = 4) -> None:
        self._indent = indent

    def build_processors(self, enable_otel: bool) -> list[Processor]:
        shared = _build_shared_processors(enable_otel, timestamp_fmt="iso", utc=True)
        return [
            *shared,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(indent=self._indent),
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

        handler = create_rotating_file_handler(
            config.file_path,
            config.max_bytes,
            config.backup_count,
            config.level,
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        return handler


class StreamOutputStrategy:
    def create_handler(self, config: StructlogConfig) -> logging.Handler:
        handler = create_stream_handler(config.level)
        handler.setFormatter(logging.Formatter("%(message)s"))
        return handler


class LoggerFactory(BaseLoggerFactory[StructlogConfig, BoundLogger]):
    _handler: ClassVar[logging.Handler | None] = None
    _close_on_replace: ClassVar[bool] = False

    @classmethod
    def create(cls: type[Self], config: StructlogConfig) -> BoundLogger:
        formatter: FormatterStrategy = (
            JsonFormatterStrategy(indent=config.json_indent) if config.json_output else ConsoleFormatterStrategy()
        )

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

        cls._replace_handler(new_handler)

        root = logging.getLogger()
        root.setLevel(LOG_LEVEL_MAP[config.level])

        apply_library_log_levels(config.library_log_levels)

        structlog.contextvars.bind_contextvars(service=config.service_name)

        return cast(BoundLogger, structlog.get_logger())

    @classmethod
    def _on_reset(cls: type[Self]) -> None:
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
