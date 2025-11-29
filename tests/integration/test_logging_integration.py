from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from hypervigilant.structlog import (
    LoggerFactory,
    LoggingConfig,
    bind_context,
    clear_context,
    configure_logging,
    get_logger,
)

if TYPE_CHECKING:
    from tests.conftest import LogCapture


class TestJsonOutput:
    def test_valid_json_with_all_fields(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="DEBUG", json_output=True, service_name="test-svc")
        configure_logging(config)

        logger = get_logger("integration.json")
        logger.info("test message", field1="value1", field2=123)
        logger.warning("warning message", nested={"key": "value"})
        logger.error("error message")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 3

        for log_entry in logs:
            assert all(k in log_entry for k in ("event", "level", "timestamp"))
            assert log_entry.get("service") == "test-svc"

        assert logs[0].get("field1") == "value1"
        assert logs[0].get("field2") == 123


class TestConsoleOutput:
    def test_readable(self, log_capture: LogCapture) -> None:
        configure_logging(LoggingConfig(level="DEBUG", json_output=False))
        get_logger("test").info("readable message", key="value")

        output = log_capture.get_output()
        assert all(s in output for s in ("readable message", "key", "value"))


class TestFileLogging:
    def test_rotation_and_persistence(self, tmp_path: Path) -> None:
        log_file = tmp_path / "rotating.log"
        config = LoggingConfig(
            level="DEBUG",
            file_path=str(log_file),
            max_bytes=1024,
            backup_count=3,
            json_output=False,
        )
        configure_logging(config)

        logger = get_logger("rotation.test")
        for i in range(200):
            logger.info(f"Log message {i} with padding to trigger rotation")

        LoggerFactory.reset()

        log_files = list(tmp_path.glob("rotating.log*"))
        assert len(log_files) >= 1
        assert any(f.stat().st_size > 0 for f in log_files)


class TestLogLevelFiltering:
    @pytest.mark.parametrize(
        ("config_level", "messages"),
        [
            ("WARNING", {"warning": True, "error": True, "info": False, "debug": False}),
            ("DEBUG", {"warning": True, "error": True, "info": True, "debug": True}),
            ("ERROR", {"warning": False, "error": True, "info": False, "debug": False}),
        ],
    )
    def test_levels(self, log_capture: LogCapture, config_level: str, messages: dict[str, bool]) -> None:
        configure_logging(LoggingConfig(level=config_level, json_output=False))  # type: ignore[arg-type]
        logger = get_logger("filter.test")

        logger.debug("debug msg")
        logger.info("info msg")
        logger.warning("warning msg")
        logger.error("error msg")

        output = log_capture.get_output()
        for level, should_appear in messages.items():
            if should_appear:
                assert f"{level} msg" in output
            else:
                assert f"{level} msg" not in output

    def test_library_suppression(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="DEBUG", json_output=False, library_log_levels={"noisy_lib": "ERROR"})
        configure_logging(config)

        logging.getLogger("noisy_lib").warning("noisy - should not appear")
        logging.getLogger("noisy_lib").error("noisy error - should appear")
        get_logger("app").debug("app debug - should appear")

        output = log_capture.get_output()
        assert "noisy - should not appear" not in output
        assert "noisy error" in output
        assert "app debug" in output


class TestContextPropagation:
    def test_across_modules(self, log_capture: LogCapture) -> None:
        configure_logging(LoggingConfig(level="INFO", json_output=True))
        bind_context(request_id="req-456", user_id="user-789")

        get_logger("module1").info("log from module1")
        get_logger("module2").info("log from module2")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 2
        for log_entry in logs:
            assert log_entry.get("request_id") == "req-456"
            assert log_entry.get("user_id") == "user-789"

    def test_clear(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True)
        configure_logging(config)

        bind_context(temp_key="temp_value")
        get_logger("ctx").info("with context")

        clear_context()
        configure_logging(config)
        get_logger("ctx").info("without context")

        logs = log_capture.get_json_logs()
        assert logs[0].get("temp_key") == "temp_value"
        assert logs[-1].get("temp_key") is None


class TestReconfiguration:
    def test_idempotent(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=False)
        for _ in range(3):
            configure_logging(config)

        get_logger("test").info("single message")
        assert log_capture.get_output().count("single message") == 1

    def test_level_change(self, log_capture: LogCapture) -> None:
        configure_logging(LoggingConfig(level="ERROR", json_output=False))
        get_logger("test").info("should not appear")

        configure_logging(LoggingConfig(level="DEBUG", json_output=False))
        get_logger("test").info("should appear")

        output = log_capture.get_output()
        assert "should not appear" not in output
        assert "should appear" in output


class TestExceptionLogging:
    def test_exception_captured(self, log_capture: LogCapture) -> None:
        configure_logging(LoggingConfig(level="ERROR", json_output=True))

        try:
            raise ValueError("test error message")
        except ValueError:
            get_logger("exc").exception("caught exception")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 1
        log_entry = logs[0]
        assert log_entry.get("event") == "caught exception"
        assert any(k in log_entry for k in ("exception", "exc_info", "traceback"))


class TestThreadSafety:
    def test_concurrent_logging(self, log_capture: LogCapture) -> None:
        configure_logging(LoggingConfig(level="INFO", json_output=True))

        def log_from_thread(thread_id: int) -> None:
            logger = get_logger(f"thread.{thread_id}")
            for i in range(10):
                logger.info(f"msg {i}", thread_id=thread_id)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(log_from_thread, i) for i in range(4)]
            for f in futures:
                f.result()

        logs = log_capture.get_json_logs()
        assert len(logs) >= 40
        thread_ids = {e.get("thread_id") for e in logs if "thread_id" in e}
        assert len(thread_ids) == 4
