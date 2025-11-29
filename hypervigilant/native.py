from __future__ import annotations

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "LogLevel",
    "LoggingConfig",
    "JSONFormatter",
    "LoggerFactory",
    "configure_logging",
    "get_logger",
]

type LogLevel = Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]

_LOG_LEVEL_MAP: Final[dict[str, int]] = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}

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


class LoggingConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="LOG_",
        extra="ignore",
        frozen=True,
    )

    level: LogLevel = Field(default="INFO")
    json_output: bool = Field(default=False)
    format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    date_format: str = Field(default="%Y-%m-%d %H:%M:%S")
    file_path: str | None = Field(default=None)
    max_bytes: int = Field(default=50_000_000, ge=1024)
    backup_count: int = Field(default=10, ge=0)
    library_log_levels: dict[str, LogLevel] = Field(default_factory=dict)

    @field_validator("level", "library_log_levels", mode="before")
    @classmethod
    def validate_log_level(cls, v: Any) -> Any:
        if isinstance(v, str):
            upper_v = v.upper()
            if upper_v not in _LOG_LEVEL_MAP:
                valid = ", ".join(_LOG_LEVEL_MAP.keys())
                raise ValueError(f"Invalid log level: {v}. Must be one of: {valid}")
            return upper_v
        if isinstance(v, dict):
            return {k: cls.validate_log_level(val) for k, val in v.items()}
        return v


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
    _configured: bool = False
    _handler: logging.Handler | None = None

    @classmethod
    def create(cls, config: LoggingConfig) -> logging.Logger:
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

        handler.setLevel(_LOG_LEVEL_MAP[config.level])

        if config.json_output:
            handler.setFormatter(JSONFormatter(datefmt=config.date_format))
        else:
            handler.setFormatter(logging.Formatter(fmt=config.format, datefmt=config.date_format))

        root.addHandler(handler)
        root.setLevel(_LOG_LEVEL_MAP[config.level])

        cls._handler = handler
        cls._configured = True

        for lib_name, lib_level in config.library_log_levels.items():
            logging.getLogger(lib_name).setLevel(_LOG_LEVEL_MAP[lib_level])

        return root

    @classmethod
    def reset(cls) -> None:
        if cls._handler is not None:
            root = logging.getLogger()
            if cls._handler in root.handlers:
                root.removeHandler(cls._handler)
            cls._handler.close()
            cls._handler = None
        cls._configured = False


_default_config: LoggingConfig | None = None


def _get_default_config() -> LoggingConfig:
    global _default_config
    if _default_config is None:
        _default_config = LoggingConfig()
    return _default_config


def configure_logging(config: LoggingConfig | None = None) -> None:
    actual_config = config if config is not None else _get_default_config()
    LoggerFactory.create(actual_config)


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(name)
