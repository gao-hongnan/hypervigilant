from __future__ import annotations

import logging
from typing import Any, ClassVar, Protocol, Self, cast

import structlog
from pydantic import ConfigDict, Field
from structlog.processors import CallsiteParameter
from structlog.typing import Processor

from .core import BaseLoggingConfig
from .factory import BaseLoggerFactory
from .handlers import create_rotating_file_handler, create_stream_handler

type BoundLogger = structlog.stdlib.BoundLogger


class StructlogConfig(BaseLoggingConfig):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True, extra="forbid")

    service_name: str = Field(default="hypervigilant")
    extra_processors: tuple[Processor, ...] = Field(default=())


class FormatterStrategy(Protocol):
    def build_processors(self, extra_processors: tuple[Processor, ...]) -> list[Processor]: ...


class OutputStrategy(Protocol):
    def create_handler(self, config: StructlogConfig) -> logging.Handler: ...


def _build_shared_processors(
    extra_processors: tuple[Processor, ...],
    timestamp_fmt: str,
    utc: bool,
) -> list[Processor]:
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
    processors.extend(extra_processors)
    return processors


class JsonFormatterStrategy:
    def __init__(self, indent: int | None = 4) -> None:
        self._indent = indent

    def build_processors(self, extra_processors: tuple[Processor, ...]) -> list[Processor]:
        shared = _build_shared_processors(extra_processors, timestamp_fmt="iso", utc=True)
        return [
            *shared,
            structlog.processors.dict_tracebacks,
            structlog.processors.JSONRenderer(indent=self._indent),
        ]


class ConsoleFormatterStrategy:
    def build_processors(self, extra_processors: tuple[Processor, ...]) -> list[Processor]:
        shared = _build_shared_processors(extra_processors, timestamp_fmt="%Y-%m-%d %H:%M:%S", utc=False)
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

        processors = formatter.build_processors(config.extra_processors)

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
        cls._finalize_root(config.level, config.library_log_levels)

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
