from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Generator
from io import StringIO
from typing import TYPE_CHECKING

import pytest

from hypervigilant import native
from hypervigilant.structlog import LoggerFactory

if TYPE_CHECKING:
    from hypervigilant.structlog import BoundLogger


class LogCapture:
    def __init__(self) -> None:
        self.stream = StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setFormatter(logging.Formatter("%(message)s"))
        self.handler.setLevel(logging.DEBUG)
        self._original_handlers: list[logging.Handler] = []

    def start(self) -> None:
        root = logging.getLogger()
        self._original_handlers = root.handlers.copy()
        root.handlers = [self.handler]
        root.setLevel(logging.DEBUG)

    def stop(self) -> None:
        root = logging.getLogger()
        root.handlers = self._original_handlers
        self._original_handlers = []

    def get_output(self) -> str:
        return self.stream.getvalue()

    def get_lines(self) -> list[str]:
        return [line for line in self.get_output().strip().split("\n") if line]

    def get_json_logs(self) -> list[dict[str, object]]:
        logs: list[dict[str, object]] = []
        for line in self.get_lines():
            with contextlib.suppress(json.JSONDecodeError):
                logs.append(json.loads(line))
        return logs

    def clear(self) -> None:
        self.stream.truncate(0)
        self.stream.seek(0)


@pytest.fixture
def log_capture() -> Generator[LogCapture, None, None]:
    capture = LogCapture()
    capture.start()
    yield capture
    capture.stop()


@pytest.fixture(autouse=True)
def reset_logging() -> Generator[None, None, None]:
    yield
    LoggerFactory.reset()
    native.LoggerFactory.reset()
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.WARNING)


@pytest.fixture
def temp_log_file(tmp_path: object) -> str:
    from pathlib import Path

    return str(Path(tmp_path) / "test.log")  # type: ignore[arg-type]


@pytest.fixture
def configured_logger() -> BoundLogger:
    from hypervigilant.structlog import LoggingConfig, configure_logging, get_logger

    configure_logging(LoggingConfig(level="DEBUG", json_output=False))
    return get_logger("test")
