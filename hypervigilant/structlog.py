from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

import structlog
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from structlog.processors import CallsiteParameter

if TYPE_CHECKING:
    from structlog.types import Processor

__all__ = [
    "BoundLogger",
    "LogLevel",
    "LoggingConfig",
    "FormatterStrategy",
    "OutputStrategy",
    "JsonFormatterStrategy",
    "ConsoleFormatterStrategy",
    "FileOutputStrategy",
    "StreamOutputStrategy",
    "LoggerFactory",
    "configure_logging",
    "get_logger",
    "bind_context",
    "clear_context",
]

BoundLogger = structlog.stdlib.BoundLogger
LogLevel = Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]

_LOG_LEVEL_MAP: dict[str, int] = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}


class LoggingConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="LOG_",
        extra="ignore",
        frozen=True,
    )

    level: LogLevel = Field(default="INFO")
    json_output: bool = Field(default=False)
    service_name: str = Field(default="hypervigilant")
    file_path: str | None = Field(default=None)
    max_bytes: int = Field(default=50_000_000, ge=1024)
    backup_count: int = Field(default=10, ge=0)
    library_log_levels: dict[str, LogLevel] = Field(default_factory=dict)
    enable_otel: bool = Field(default=False)

    @field_validator("level", "library_log_levels", mode="before")
    @classmethod
    def validate_log_level(cls, v: Any) -> Any:
        if isinstance(v, str):
            upper_v = v.upper()
            if upper_v not in _LOG_LEVEL_MAP:
                valid_levels = ", ".join(_LOG_LEVEL_MAP.keys())
                raise ValueError(f"Invalid log level: {v}. Must be one of: {valid_levels}")
            return upper_v
        if isinstance(v, dict):
            return {k: cls.validate_log_level(val) for k, val in v.items()}
        return v


class FormatterStrategy(Protocol):
    def build_processors(self, enable_otel: bool) -> list[Processor]: ...


class OutputStrategy(Protocol):
    def create_handler(self, config: LoggingConfig) -> logging.Handler: ...


def _get_otel_processor() -> Processor | None:
    try:
        from hypervigilant._otel import get_otel_processor

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
    def create_handler(self, config: LoggingConfig) -> logging.Handler:
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
        handler.setLevel(_LOG_LEVEL_MAP[config.level])
        handler.setFormatter(logging.Formatter("%(message)s"))

        return handler


class StreamOutputStrategy:
    def create_handler(self, config: LoggingConfig) -> logging.Handler:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(_LOG_LEVEL_MAP[config.level])
        handler.setFormatter(logging.Formatter("%(message)s"))

        return handler


class LoggerFactory:
    _configured: bool = False
    _handler: logging.Handler | None = None

    @classmethod
    def create(cls, config: LoggingConfig) -> BoundLogger:
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
        root.setLevel(_LOG_LEVEL_MAP[config.level])
        cls._handler = new_handler
        cls._configured = True

        for lib_name, lib_level in config.library_log_levels.items():
            logging.getLogger(lib_name).setLevel(_LOG_LEVEL_MAP[lib_level])

        structlog.contextvars.bind_contextvars(service=config.service_name)

        return cast(BoundLogger, structlog.get_logger())

    @classmethod
    def reset(cls) -> None:
        if cls._handler is not None:
            root = logging.getLogger()
            if cls._handler in root.handlers:
                root.removeHandler(cls._handler)
            cls._handler.close()
            cls._handler = None
        cls._configured = False
        structlog.reset_defaults()
        structlog.contextvars.clear_contextvars()


_default_config: LoggingConfig | None = None


def _get_default_config() -> LoggingConfig:
    global _default_config
    if _default_config is None:
        _default_config = LoggingConfig()
    return _default_config


def configure_logging(config: LoggingConfig | None = None) -> None:
    actual_config = config if config is not None else _get_default_config()
    LoggerFactory.create(actual_config)


def get_logger(name: str | None = None) -> BoundLogger:
    return cast(BoundLogger, structlog.get_logger(name))


def bind_context(**kwargs: Any) -> None:
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    structlog.contextvars.clear_contextvars()
