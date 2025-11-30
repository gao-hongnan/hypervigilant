from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest

from hypervigilant.native import (
    JSONFormatter,
    LoggerFactory,
    LoggingConfig,
    configure_logging,
    get_logger,
)


class TestLoggingConfig:
    def test_defaults(self) -> None:
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.json_output is False
        assert config.format == "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        assert config.date_format == "%Y-%m-%d %H:%M:%S"
        assert config.file_path is None
        assert config.max_bytes == 50_000_000
        assert config.backup_count == 10
        assert config.library_log_levels == {}

    def test_custom_values(self) -> None:
        config = LoggingConfig(
            level="DEBUG",
            json_output=True,
            format="%(message)s",
            date_format="%H:%M:%S",
            file_path="/tmp/test.log",
            max_bytes=1024,
            backup_count=5,
            library_log_levels={"urllib3": "WARNING"},
        )
        assert config.level == "DEBUG"
        assert config.json_output is True
        assert config.format == "%(message)s"
        assert config.date_format == "%H:%M:%S"
        assert config.file_path == "/tmp/test.log"
        assert config.max_bytes == 1024
        assert config.backup_count == 5
        assert config.library_log_levels == {"urllib3": "WARNING"}

    @pytest.mark.parametrize(
        ("level", "expected"),
        [("debug", "DEBUG"), ("Warning", "WARNING"), ("INFO", "INFO")],
    )
    def test_level_normalization(self, level: str, expected: str) -> None:
        config = LoggingConfig(level=level)  # type: ignore[arg-type]
        assert config.level == expected

    def test_invalid_level_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid log level"):
            LoggingConfig(level="INVALID")  # type: ignore[arg-type]

    def test_frozen(self) -> None:
        from pydantic import ValidationError

        config = LoggingConfig()
        with pytest.raises(ValidationError):
            config.level = "DEBUG"  # type: ignore[misc]

    def test_max_bytes_constraint(self) -> None:
        with pytest.raises(ValueError):
            LoggingConfig(max_bytes=100)

    def test_backup_count_constraint(self) -> None:
        with pytest.raises(ValueError):
            LoggingConfig(backup_count=-1)

    def test_library_log_levels_normalization(self) -> None:
        config = LoggingConfig(library_log_levels={"urllib3": "warning", "httpx": "Error"})  # type: ignore[dict-item]
        assert config.library_log_levels == {"urllib3": "WARNING", "httpx": "ERROR"}


class TestJSONFormatter:
    def test_basic_format(self) -> None:
        formatter = JSONFormatter(datefmt="%Y-%m-%d")
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)

        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert data["filename"] == "test.py"
        assert data["lineno"] == 42
        assert data["message"] == "Test message"
        assert "timestamp" in data

    def test_message_with_args(self) -> None:
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Value: %d",
            args=(42,),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data["message"] == "Value: 42"

    def test_extra_fields(self) -> None:
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None,
        )
        record.request_id = "abc-123"
        record.user_id = 456

        output = formatter.format(record)
        data = json.loads(output)

        assert data["request_id"] == "abc-123"
        assert data["user_id"] == 456

    def test_exception_formatting(self) -> None:
        formatter = JSONFormatter()
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        data = json.loads(output)

        assert "exception" in data
        assert "ValueError" in data["exception"]
        assert "Test error" in data["exception"]


class TestLoggerFactory:
    def test_create_returns_logger(self) -> None:
        logger = LoggerFactory.create(LoggingConfig())
        assert all(hasattr(logger, m) for m in ("info", "error", "debug", "warning"))
        assert callable(logger.info)

    def test_create_sets_state(self) -> None:
        LoggerFactory.create(LoggingConfig())
        assert LoggerFactory._configured is True
        assert LoggerFactory._handler is not None

    def test_reset_clears_state(self) -> None:
        LoggerFactory.create(LoggingConfig())
        LoggerFactory.reset()
        assert LoggerFactory._configured is False
        assert LoggerFactory._handler is None

    def test_library_log_levels(self) -> None:
        config = LoggingConfig(library_log_levels={"urllib3": "WARNING", "httpx": "ERROR"})
        LoggerFactory.create(config)
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.ERROR

    def test_handler_replacement(self) -> None:
        LoggerFactory.create(LoggingConfig(level="DEBUG"))
        handler1 = LoggerFactory._handler

        LoggerFactory.create(LoggingConfig(level="INFO"))
        handler2 = LoggerFactory._handler

        assert handler1 is not handler2
        root = logging.getLogger()
        assert handler1 not in root.handlers
        assert handler2 in root.handlers

    def test_no_duplicate_handlers(self) -> None:
        for _ in range(5):
            LoggerFactory.create(LoggingConfig())

        root = logging.getLogger()
        handler_count = sum(1 for h in root.handlers if h is LoggerFactory._handler)
        assert handler_count == 1

    def test_stream_handler_created(self) -> None:
        LoggerFactory.create(LoggingConfig())
        assert isinstance(LoggerFactory._handler, logging.StreamHandler)

    def test_file_handler_created(self, tmp_path: Path) -> None:
        from logging.handlers import RotatingFileHandler

        log_file = tmp_path / "test.log"
        config = LoggingConfig(file_path=str(log_file))
        LoggerFactory.create(config)

        assert isinstance(LoggerFactory._handler, RotatingFileHandler)
        LoggerFactory.reset()


class TestPublicAPI:
    def test_configure_logging_default(self) -> None:
        configure_logging()
        assert LoggerFactory._configured is True

    def test_configure_logging_custom(self) -> None:
        config = LoggingConfig(level="DEBUG")
        configure_logging(config)
        assert LoggerFactory._configured is True
        root = logging.getLogger()
        assert root.level == logging.DEBUG

    def test_get_logger(self) -> None:
        configure_logging()
        logger = get_logger()
        assert isinstance(logger, logging.Logger)
        assert hasattr(logger, "info") and callable(logger.info)

    def test_get_logger_named(self) -> None:
        configure_logging()
        logger = get_logger("my_module")
        assert logger.name == "my_module"

    def test_reconfiguration_idempotent(self) -> None:
        configure_logging(LoggingConfig(level="DEBUG"))
        configure_logging(LoggingConfig(level="INFO"))
        configure_logging(LoggingConfig(level="WARNING"))

        root = logging.getLogger()
        hypervigilant_handlers = [h for h in root.handlers if h is LoggerFactory._handler]
        assert len(hypervigilant_handlers) == 1


class TestFileLogging:
    def test_file_creation(self, tmp_path: Path) -> None:
        log_file = tmp_path / "app.log"
        config = LoggingConfig(level="INFO", file_path=str(log_file))
        configure_logging(config)

        logger = get_logger("test")
        logger.info("Test message")
        LoggerFactory.reset()

        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message" in content

    def test_file_json_output(self, tmp_path: Path) -> None:
        log_file = tmp_path / "app.log"
        config = LoggingConfig(level="INFO", file_path=str(log_file), json_output=True)
        configure_logging(config)

        logger = get_logger("test")
        logger.info("JSON log entry")
        LoggerFactory.reset()

        content = log_file.read_text().strip()
        data = json.loads(content.split("\n")[0])
        assert data["message"] == "JSON log entry"
        assert data["level"] == "INFO"

    def test_file_creates_parent_dirs(self, tmp_path: Path) -> None:
        log_file = tmp_path / "subdir" / "nested" / "app.log"
        config = LoggingConfig(file_path=str(log_file))
        configure_logging(config)

        assert log_file.parent.exists()
        LoggerFactory.reset()

    def test_rotating_file_handler_config(self, tmp_path: Path) -> None:
        from logging.handlers import RotatingFileHandler

        log_file = tmp_path / "app.log"
        config = LoggingConfig(file_path=str(log_file), max_bytes=2048, backup_count=3)
        configure_logging(config)

        handler = LoggerFactory._handler
        assert isinstance(handler, RotatingFileHandler)
        assert handler.maxBytes == 2048
        assert handler.backupCount == 3
        LoggerFactory.reset()


class TestLogLevelFiltering:
    def test_level_filtering(self) -> None:
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.WARNING)

        config = LoggingConfig(level="WARNING")
        configure_logging(config)

        root = logging.getLogger()
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(logging.WARNING)

        logger = get_logger("test")
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")

        output = stream.getvalue()
        assert "Debug message" not in output
        assert "Info message" not in output
        assert "Warning message" in output
        assert "Error message" in output

    def test_library_log_suppression(self) -> None:
        stream = StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(name)s - %(message)s"))

        config = LoggingConfig(level="DEBUG", library_log_levels={"noisy_lib": "ERROR"})
        configure_logging(config)

        root = logging.getLogger()
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)

        noisy_logger = logging.getLogger("noisy_lib")
        noisy_logger.setLevel(logging.ERROR)
        noisy_logger.debug("Noisy debug")
        noisy_logger.info("Noisy info")
        noisy_logger.error("Noisy error")

        output = stream.getvalue()
        assert "Noisy debug" not in output
        assert "Noisy info" not in output
        assert "Noisy error" in output
