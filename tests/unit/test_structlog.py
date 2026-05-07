from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import structlog

from hypervigilant.loggers.structlog import (
    ConsoleFormatterStrategy,
    FileOutputStrategy,
    JsonFormatterStrategy,
    LoggerFactory,
    StreamOutputStrategy,
    StructlogConfig,
    bind_context,
    clear_context,
    configure_logging,
    get_logger,
)

if TYPE_CHECKING:
    from structlog.typing import EventDict, WrappedLogger

    from hypervigilant.loggers.structlog import FormatterStrategy


class TestStructlogConfig:
    def test_defaults(self) -> None:
        config = StructlogConfig()
        assert config.level == "INFO"
        assert config.json_output is False
        assert config.service_name == "hypervigilant"
        assert config.file_path is None
        assert config.max_bytes == 50_000_000
        assert config.backup_count == 10
        assert config.library_log_levels == {}
        assert config.extra_processors == ()

    def test_custom_values(self) -> None:
        config = StructlogConfig(
            level="DEBUG",
            json_output=True,
            service_name="test-service",
            file_path="/tmp/test.log",
            max_bytes=1024,
            backup_count=5,
            library_log_levels={"urllib3": "WARNING"},
        )
        assert config.level == "DEBUG"
        assert config.json_output is True
        assert config.service_name == "test-service"
        assert config.file_path == "/tmp/test.log"
        assert config.max_bytes == 1024
        assert config.backup_count == 5
        assert config.library_log_levels == {"urllib3": "WARNING"}

    @pytest.mark.parametrize(
        ("level", "expected"),
        [("debug", "DEBUG"), ("Warning", "WARNING"), ("INFO", "INFO")],
    )
    def test_level_normalization(self, level: str, expected: str) -> None:
        config = StructlogConfig(level=level)  # type: ignore[arg-type]
        assert config.level == expected

    def test_invalid_level_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid log level"):
            StructlogConfig(level="INVALID")  # type: ignore[arg-type]

    def test_frozen(self) -> None:
        from pydantic import ValidationError

        config = StructlogConfig()
        with pytest.raises(ValidationError):
            config.level = "DEBUG"  # type: ignore[misc]

    def test_max_bytes_constraint(self) -> None:
        with pytest.raises(ValueError):
            StructlogConfig(max_bytes=100)

    def test_backup_count_constraint(self) -> None:
        with pytest.raises(ValueError):
            StructlogConfig(backup_count=-1)


class TestFormatterStrategies:
    @pytest.mark.parametrize(
        ("strategy_cls", "renderer_name"),
        [
            (JsonFormatterStrategy, "JSONRenderer"),
            (ConsoleFormatterStrategy, "ConsoleRenderer"),
        ],
    )
    def test_processors(
        self,
        strategy_cls: type[FormatterStrategy],
        renderer_name: str,
    ) -> None:
        strategy = strategy_cls()
        processors = strategy.build_processors(extra_processors=())
        assert len(processors) > 0
        assert any(renderer_name in str(type(p).__name__) for p in processors)


class TestOutputStrategies:
    def test_stream_handler(self) -> None:
        strategy = StreamOutputStrategy()
        config = StructlogConfig(level="DEBUG")
        handler = strategy.create_handler(config)
        assert isinstance(handler, logging.StreamHandler)
        assert handler.level == logging.DEBUG

    def test_file_handler(self, tmp_path: Path) -> None:
        from logging.handlers import RotatingFileHandler

        log_file = tmp_path / "test.log"
        strategy = FileOutputStrategy()
        config = StructlogConfig(file_path=str(log_file), max_bytes=2048, backup_count=3)
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
        config = StructlogConfig(file_path=str(log_file))
        handler = strategy.create_handler(config)
        try:
            assert log_file.parent.exists()
        finally:
            handler.close()

    def test_file_handler_requires_path(self) -> None:
        strategy = FileOutputStrategy()
        with pytest.raises(ValueError, match="file_path required"):
            strategy.create_handler(StructlogConfig())


class TestLoggerFactory:
    def test_create_returns_bound_logger(self) -> None:
        logger = LoggerFactory.create(StructlogConfig())
        assert all(hasattr(logger, m) for m in ("info", "error", "debug", "warning"))
        assert callable(logger.info)

    def test_create_sets_state(self) -> None:
        LoggerFactory.create(StructlogConfig())
        assert LoggerFactory._handler is not None

    def test_reset_clears_state(self) -> None:
        LoggerFactory.create(StructlogConfig())
        LoggerFactory.reset()
        assert LoggerFactory._handler is None

    def test_library_log_levels(self) -> None:
        config = StructlogConfig(library_log_levels={"urllib3": "WARNING", "httpx": "ERROR"})
        LoggerFactory.create(config)
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.ERROR

    def test_service_context_bound(self) -> None:
        LoggerFactory.create(StructlogConfig(service_name="test-service"))
        ctx = structlog.contextvars.get_contextvars()
        assert ctx.get("service") == "test-service"

    def test_handler_replacement(self) -> None:
        LoggerFactory.create(StructlogConfig(level="DEBUG"))
        handler1 = LoggerFactory._handler

        LoggerFactory.create(StructlogConfig(level="INFO"))
        handler2 = LoggerFactory._handler

        assert handler1 is not handler2
        root = logging.getLogger()
        assert handler1 not in root.handlers
        assert handler2 in root.handlers


class TestPublicAPI:
    def test_configure_logging(self) -> None:
        configure_logging()
        assert LoggerFactory._handler is not None

        configure_logging(StructlogConfig(service_name="custom"))
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


class TestExtraProcessors:
    def test_default_value(self) -> None:
        config = StructlogConfig()
        assert config.extra_processors == ()

    def test_json_appends_after_builtins_before_renderer(self) -> None:
        def marker(_logger: WrappedLogger, _name: str, event_dict: EventDict) -> EventDict:
            return event_dict

        processors = JsonFormatterStrategy().build_processors(extra_processors=(marker,))
        unicode_idx = next(i for i, p in enumerate(processors) if isinstance(p, structlog.processors.UnicodeDecoder))
        marker_idx = processors.index(marker)
        assert marker_idx > unicode_idx
        assert isinstance(processors[-1], structlog.processors.JSONRenderer)
        assert marker_idx < len(processors) - 1

    def test_console_preserves_caller_order(self) -> None:
        def p1(_logger: WrappedLogger, _name: str, event_dict: EventDict) -> EventDict:
            return event_dict

        def p2(_logger: WrappedLogger, _name: str, event_dict: EventDict) -> EventDict:
            return event_dict

        processors = ConsoleFormatterStrategy().build_processors(extra_processors=(p1, p2))
        assert processors.index(p1) < processors.index(p2)


class TestFileLogging:
    def test_file_logging_json(self, tmp_path: Path) -> None:
        import json

        log_file = tmp_path / "app.log"
        config = StructlogConfig(level="INFO", file_path=str(log_file), json_output=True)
        configure_logging(config)

        get_logger("test").info("json file log", key="value")
        LoggerFactory.reset()

        assert log_file.exists()
        content = log_file.read_text().strip()
        log_entry = json.loads(content.split("\n")[0])
        assert log_entry["event"] == "json file log"
        assert log_entry["key"] == "value"
