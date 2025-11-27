from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import structlog

from hypervigilant.structlog import (
    ConsoleFormatterStrategy,
    FileOutputStrategy,
    JsonFormatterStrategy,
    LoggerFactory,
    LoggingConfig,
    StreamOutputStrategy,
    bind_context,
    clear_context,
    configure_logging,
    get_logger,
)

if TYPE_CHECKING:
    from tests.conftest import LogCapture


class TestLoggingConfig:
    def test_default_values(self) -> None:
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.json_output is False
        assert config.service_name == "hypervigilant"
        assert config.file_path is None
        assert config.max_bytes == 50_000_000
        assert config.backup_count == 10
        assert config.library_log_levels == {}
        assert config.enable_otel is False

    def test_custom_values(self) -> None:
        config = LoggingConfig(
            level="DEBUG",
            json_output=True,
            service_name="test-service",
            file_path="/tmp/test.log",
            max_bytes=1024,
            backup_count=5,
            library_log_levels={"urllib3": "WARNING"},
            enable_otel=True,
        )
        assert config.level == "DEBUG"
        assert config.json_output is True
        assert config.service_name == "test-service"
        assert config.file_path == "/tmp/test.log"
        assert config.max_bytes == 1024
        assert config.backup_count == 5
        assert config.library_log_levels == {"urllib3": "WARNING"}
        assert config.enable_otel is True

    def test_env_loading(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("LOG_JSON_OUTPUT", "true")
        monkeypatch.setenv("LOG_SERVICE_NAME", "env-service")
        config = LoggingConfig()
        assert config.level == "DEBUG"
        assert config.json_output is True
        assert config.service_name == "env-service"

    def test_level_case_insensitive(self) -> None:
        config = LoggingConfig(level="debug")  # type: ignore[arg-type]
        assert config.level == "DEBUG"

        config2 = LoggingConfig(level="Warning")  # type: ignore[arg-type]
        assert config2.level == "WARNING"

    def test_invalid_level_raises_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid log level"):
            LoggingConfig(level="INVALID")  # type: ignore[arg-type]

    def test_frozen_config(self) -> None:
        from pydantic import ValidationError

        config = LoggingConfig()
        with pytest.raises(ValidationError):
            config.level = "DEBUG"  # type: ignore[misc]

    def test_max_bytes_validation(self) -> None:
        with pytest.raises(ValueError):
            LoggingConfig(max_bytes=100)

    def test_backup_count_validation(self) -> None:
        with pytest.raises(ValueError):
            LoggingConfig(backup_count=-1)


class TestFormatterStrategies:
    def test_json_formatter_processors(self) -> None:
        strategy = JsonFormatterStrategy()
        processors = strategy.build_processors(enable_otel=False)
        assert len(processors) > 0
        assert any("JSONRenderer" in str(type(p).__name__) for p in processors)

    def test_console_formatter_processors(self) -> None:
        strategy = ConsoleFormatterStrategy()
        processors = strategy.build_processors(enable_otel=False)
        assert len(processors) > 0
        assert any("ConsoleRenderer" in str(type(p).__name__) for p in processors)

    def test_json_formatter_with_otel(self) -> None:
        strategy = JsonFormatterStrategy()
        processors_without_otel = strategy.build_processors(enable_otel=False)
        processors_with_otel = strategy.build_processors(enable_otel=True)
        assert len(processors_with_otel) >= len(processors_without_otel)

    def test_console_formatter_with_otel(self) -> None:
        strategy = ConsoleFormatterStrategy()
        processors_without_otel = strategy.build_processors(enable_otel=False)
        processors_with_otel = strategy.build_processors(enable_otel=True)
        assert len(processors_with_otel) >= len(processors_without_otel)


class TestOutputStrategies:
    def test_stream_handler_creation(self) -> None:
        strategy = StreamOutputStrategy()
        config = LoggingConfig(level="DEBUG")
        handler = strategy.create_handler(config)
        assert isinstance(handler, logging.StreamHandler)
        assert handler.level == logging.DEBUG

    def test_file_handler_creation(self, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        strategy = FileOutputStrategy()
        config = LoggingConfig(level="INFO", file_path=str(log_file))
        handler = strategy.create_handler(config)
        try:
            assert handler.level == logging.INFO
            assert log_file.parent.exists()
        finally:
            handler.close()

    def test_file_handler_requires_path(self) -> None:
        strategy = FileOutputStrategy()
        config = LoggingConfig()
        with pytest.raises(ValueError, match="file_path required"):
            strategy.create_handler(config)

    def test_file_handler_creates_parent_dirs(self, tmp_path: Path) -> None:
        log_file = tmp_path / "subdir" / "nested" / "test.log"
        strategy = FileOutputStrategy()
        config = LoggingConfig(file_path=str(log_file))
        handler = strategy.create_handler(config)
        try:
            assert log_file.parent.exists()
        finally:
            handler.close()

    def test_file_handler_rotation_settings(self, tmp_path: Path) -> None:
        from logging.handlers import RotatingFileHandler

        log_file = tmp_path / "test.log"
        strategy = FileOutputStrategy()
        config = LoggingConfig(file_path=str(log_file), max_bytes=2048, backup_count=3)
        handler = strategy.create_handler(config)
        try:
            assert isinstance(handler, RotatingFileHandler)
            assert handler.maxBytes == 2048
            assert handler.backupCount == 3
        finally:
            handler.close()


class TestLoggerFactory:
    def test_create_returns_bound_logger(self) -> None:
        config = LoggingConfig()
        logger = LoggerFactory.create(config)
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")
        assert callable(logger.info)

    def test_create_configures_structlog(self) -> None:
        config = LoggingConfig()
        LoggerFactory.create(config)
        assert LoggerFactory._configured is True

    def test_create_sets_library_log_levels(self) -> None:
        config = LoggingConfig(library_log_levels={"urllib3": "WARNING", "httpx": "ERROR"})
        LoggerFactory.create(config)
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.ERROR

    def test_create_binds_service_context(self) -> None:
        config = LoggingConfig(service_name="test-service")
        LoggerFactory.create(config)
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("service") == "test-service"

    def test_create_sets_configured_state(self) -> None:
        config = LoggingConfig()
        LoggerFactory.create(config)
        assert LoggerFactory._configured is True
        assert LoggerFactory._handler is not None

    def test_reset_clears_state(self) -> None:
        config = LoggingConfig()
        LoggerFactory.create(config)
        LoggerFactory.reset()
        assert not LoggerFactory._configured
        assert LoggerFactory._handler is None

    def test_multiple_creates_replace_handler(self) -> None:
        config1 = LoggingConfig(level="DEBUG")
        LoggerFactory.create(config1)
        handler1 = LoggerFactory._handler

        config2 = LoggingConfig(level="INFO")
        LoggerFactory.create(config2)
        handler2 = LoggerFactory._handler

        assert handler1 is not handler2
        root = logging.getLogger()
        assert handler1 not in root.handlers
        assert handler2 in root.handlers


class TestPublicAPI:
    def test_configure_logging_with_default_config(self) -> None:
        configure_logging()
        assert LoggerFactory._configured is True

    def test_configure_logging_with_custom_config(self) -> None:
        config = LoggingConfig(level="DEBUG", service_name="custom")
        configure_logging(config)
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("service") == "custom"

    def test_get_logger_returns_bound_logger(self) -> None:
        configure_logging()
        logger = get_logger()
        assert hasattr(logger, "info")
        assert hasattr(logger, "error")
        assert callable(logger.info)

    def test_get_logger_with_name(self) -> None:
        configure_logging()
        logger = get_logger("my_module")
        assert logger is not None

    def test_bind_context_adds_to_contextvars(self) -> None:
        configure_logging()
        bind_context(request_id="123", user_id=456)
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("request_id") == "123"
        assert ctx.get("user_id") == 456

    def test_clear_context_removes_all(self) -> None:
        configure_logging()
        bind_context(key1="value1", key2="value2")
        clear_context()
        ctx = structlog.contextvars.get_contextvars()
        assert "key1" not in ctx
        assert "key2" not in ctx


class TestOtelIntegration:
    def test_otel_processor_handles_no_package(self) -> None:
        strategy = JsonFormatterStrategy()
        processors = strategy.build_processors(enable_otel=True)
        assert len(processors) > 0

    def test_otel_module_availability_check(self) -> None:
        from hypervigilant._otel import is_otel_available

        result = is_otel_available()
        assert isinstance(result, bool)

    def test_get_otel_processor_returns_callable_or_none(self) -> None:
        from hypervigilant._otel import get_otel_processor

        processor = get_otel_processor()
        assert processor is None or callable(processor)


class TestLoggingOutput:
    def test_console_output_format(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=False)
        configure_logging(config)

        logger = get_logger("test")
        logger.info("test message", extra_field="value")

        output = log_capture.get_output()
        assert "test message" in output
        assert "INFO" in output.upper() or "info" in output

    def test_json_output_format(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True)
        configure_logging(config)

        logger = get_logger("test")
        logger.info("test message", extra_field="value")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 1
        log_entry = logs[0]
        assert log_entry.get("event") == "test message"
        assert log_entry.get("extra_field") == "value"

    def test_log_levels_filter_correctly(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="WARNING", json_output=False)
        configure_logging(config)

        logger = get_logger("test")
        logger.debug("debug message")
        logger.info("info message")
        logger.warning("warning message")
        logger.error("error message")

        output = log_capture.get_output()
        assert "debug message" not in output
        assert "info message" not in output
        assert "warning message" in output
        assert "error message" in output

    def test_context_appears_in_logs(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True)
        configure_logging(config)

        bind_context(request_id="req-123")
        logger = get_logger("test")
        logger.info("test with context")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 1
        assert logs[0].get("request_id") == "req-123"


class TestFileLogging:
    def test_file_logging_creates_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "app.log"
        config = LoggingConfig(level="INFO", file_path=str(log_file), json_output=True)
        configure_logging(config)

        logger = get_logger("test")
        logger.info("file log message")

        LoggerFactory.reset()

        assert log_file.exists()
        content = log_file.read_text()
        assert "file log message" in content

    def test_file_logging_with_json(self, tmp_path: Path) -> None:
        import json

        log_file = tmp_path / "app.log"
        config = LoggingConfig(level="INFO", file_path=str(log_file), json_output=True)
        configure_logging(config)

        logger = get_logger("test")
        logger.info("json file log", key="value")

        LoggerFactory.reset()

        content = log_file.read_text().strip()
        log_entry = json.loads(content.split("\n")[0])
        assert log_entry["event"] == "json file log"
        assert log_entry["key"] == "value"
