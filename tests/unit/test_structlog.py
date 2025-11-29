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
    from hypervigilant.structlog import FormatterStrategy


class TestLoggingConfig:
    def test_defaults(self) -> None:
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


class TestFormatterStrategies:
    @pytest.mark.parametrize(
        ("strategy_cls", "renderer_name", "enable_otel"),
        [
            (JsonFormatterStrategy, "JSONRenderer", False),
            (JsonFormatterStrategy, "JSONRenderer", True),
            (ConsoleFormatterStrategy, "ConsoleRenderer", False),
            (ConsoleFormatterStrategy, "ConsoleRenderer", True),
        ],
    )
    def test_processors(
        self,
        strategy_cls: type[FormatterStrategy],
        renderer_name: str,
        enable_otel: bool,
    ) -> None:
        strategy = strategy_cls()
        processors = strategy.build_processors(enable_otel=enable_otel)
        assert len(processors) > 0
        assert any(renderer_name in str(type(p).__name__) for p in processors)


class TestOutputStrategies:
    def test_stream_handler(self) -> None:
        strategy = StreamOutputStrategy()
        config = LoggingConfig(level="DEBUG")
        handler = strategy.create_handler(config)
        assert isinstance(handler, logging.StreamHandler)
        assert handler.level == logging.DEBUG

    def test_file_handler(self, tmp_path: Path) -> None:
        from logging.handlers import RotatingFileHandler

        log_file = tmp_path / "test.log"
        strategy = FileOutputStrategy()
        config = LoggingConfig(file_path=str(log_file), max_bytes=2048, backup_count=3)
        handler = strategy.create_handler(config)
        try:
            assert isinstance(handler, RotatingFileHandler)
            assert handler.maxBytes == 2048
            assert handler.backupCount == 3
            assert log_file.parent.exists()
        finally:
            handler.close()

    def test_file_handler_creates_dirs(self, tmp_path: Path) -> None:
        log_file = tmp_path / "subdir" / "nested" / "test.log"
        strategy = FileOutputStrategy()
        config = LoggingConfig(file_path=str(log_file))
        handler = strategy.create_handler(config)
        try:
            assert log_file.parent.exists()
        finally:
            handler.close()

    def test_file_handler_requires_path(self) -> None:
        strategy = FileOutputStrategy()
        with pytest.raises(ValueError, match="file_path required"):
            strategy.create_handler(LoggingConfig())


class TestLoggerFactory:
    def test_create_returns_bound_logger(self) -> None:
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
        configured = LoggerFactory._configured
        handler = LoggerFactory._handler
        assert configured is False
        assert handler is None

    def test_library_log_levels(self) -> None:
        config = LoggingConfig(library_log_levels={"urllib3": "WARNING", "httpx": "ERROR"})
        LoggerFactory.create(config)
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.ERROR

    def test_service_context_bound(self) -> None:
        LoggerFactory.create(LoggingConfig(service_name="test-service"))
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("service") == "test-service"

    def test_handler_replacement(self) -> None:
        LoggerFactory.create(LoggingConfig(level="DEBUG"))
        handler1 = LoggerFactory._handler

        LoggerFactory.create(LoggingConfig(level="INFO"))
        handler2 = LoggerFactory._handler

        assert handler1 is not handler2
        root = logging.getLogger()
        assert handler1 not in root.handlers
        assert handler2 in root.handlers


class TestPublicAPI:
    def test_configure_logging(self) -> None:
        configure_logging()
        assert LoggerFactory._configured is True

        configure_logging(LoggingConfig(service_name="custom"))
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("service") == "custom"

    def test_get_logger(self) -> None:
        configure_logging()
        logger = get_logger()
        assert hasattr(logger, "info") and callable(logger.info)

        named_logger = get_logger("my_module")
        assert named_logger is not None

    def test_context_binding(self) -> None:
        configure_logging()
        bind_context(request_id="123", user_id=456)
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("request_id") == "123"
        assert ctx.get("user_id") == 456

        clear_context()
        ctx = structlog.contextvars.get_contextvars()
        assert "request_id" not in ctx


class TestOtelIntegration:
    def test_otel_module(self) -> None:
        from hypervigilant._otel import get_otel_processor, is_otel_available

        assert isinstance(is_otel_available(), bool)
        processor = get_otel_processor()
        assert processor is None or callable(processor)

    def test_otel_processor_graceful(self) -> None:
        strategy = JsonFormatterStrategy()
        processors = strategy.build_processors(enable_otel=True)
        assert len(processors) > 0


class TestFileLogging:
    def test_file_logging_json(self, tmp_path: Path) -> None:
        import json

        log_file = tmp_path / "app.log"
        config = LoggingConfig(level="INFO", file_path=str(log_file), json_output=True)
        configure_logging(config)

        get_logger("test").info("json file log", key="value")
        LoggerFactory.reset()

        assert log_file.exists()
        content = log_file.read_text().strip()
        log_entry = json.loads(content.split("\n")[0])
        assert log_entry["event"] == "json file log"
        assert log_entry["key"] == "value"
