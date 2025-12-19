from __future__ import annotations

import logging
from typing import Any, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator

type LogLevel = Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"]

LOG_LEVEL_MAP: Final[dict[str, int]] = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}


class BaseLoggingConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    level: LogLevel = Field(default="INFO")
    json_output: bool = Field(default=False)
    file_path: str | None = Field(default=None)
    max_bytes: int = Field(default=50_000_000, ge=1024)
    backup_count: int = Field(default=10, ge=0)
    library_log_levels: dict[str, LogLevel] = Field(default_factory=dict)

    @classmethod
    def _normalize_level(cls: type[Self], level: str) -> str:
        upper = level.upper()
        if upper not in LOG_LEVEL_MAP:
            valid = ", ".join(LOG_LEVEL_MAP.keys())
            raise ValueError(f"Invalid log level: {level}. Must be one of: {valid}")
        return upper

    @field_validator("level", "library_log_levels", mode="before")
    @classmethod
    def validate_log_level(cls: type[Self], v: str | dict[str, Any]) -> str | dict[str, str]:
        if isinstance(v, str):
            return cls._normalize_level(v)
        return {k: cls._normalize_level(val) for k, val in v.items()}
