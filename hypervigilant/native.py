from __future__ import annotations

import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = [
    "LogLevel",
    "LoggingConfig",
    "JSONFormatter",
    "configure_logging",
    "get_logger",
]

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
        dummy = logging.LogRecord(
            name="",
            level=0,
            pathname="",
            lineno=0,
            msg="",
            args=(),
            exc_info=None,
        )
        self._standard_attrs = frozenset(dummy.__dict__.keys())

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

        extras = {k: v for k, v in record.__dict__.items() if k not in self._standard_attrs and not k.startswith("_")}
        log_data.update(extras)

        return json.dumps(log_data, default=str)


_handler: logging.Handler | None = None


def configure_logging(config: LoggingConfig | None = None) -> None:
    global _handler

    cfg = config or LoggingConfig()
    root = logging.getLogger()

    if _handler is not None and _handler in root.handlers:
        root.removeHandler(_handler)
        _handler.close()

    if cfg.file_path:
        log_path = Path(cfg.file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            filename=str(log_path),
            maxBytes=cfg.max_bytes,
            backupCount=cfg.backup_count,
            encoding="utf-8",
        )
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setLevel(_LOG_LEVEL_MAP[cfg.level])

    if cfg.json_output:
        handler.setFormatter(JSONFormatter(datefmt=cfg.date_format))
    else:
        handler.setFormatter(logging.Formatter(fmt=cfg.format, datefmt=cfg.date_format))

    root.addHandler(handler)
    root.setLevel(_LOG_LEVEL_MAP[cfg.level])
    _handler = handler

    for lib_name, lib_level in cfg.library_log_levels.items():
        logging.getLogger(lib_name).setLevel(_LOG_LEVEL_MAP[lib_level])


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(name)
