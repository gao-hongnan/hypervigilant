from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

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


class TestJsonOutputIntegration:
    def test_json_output_is_valid_json(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="DEBUG", json_output=True)
        configure_logging(config)

        logger = get_logger("integration.json")
        logger.info("test message", field1="value1", field2=123, field3=True)
        logger.warning("warning message", nested={"key": "value"})
        logger.error("error message")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 3

        for log_entry in logs:
            assert "event" in log_entry
            assert "level" in log_entry
            assert "timestamp" in log_entry

    def test_json_output_contains_all_fields(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True, service_name="test-svc")
        configure_logging(config)

        logger = get_logger("integration.fields")
        logger.info("complete log", custom_field="custom_value")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 1

        log_entry = logs[0]
        assert log_entry.get("event") == "complete log"
        assert log_entry.get("custom_field") == "custom_value"
        assert log_entry.get("service") == "test-svc"
        assert "filename" in log_entry
        assert "lineno" in log_entry
        assert "module" in log_entry


class TestConsoleOutputIntegration:
    def test_console_output_readable(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="DEBUG", json_output=False)
        configure_logging(config)

        logger = get_logger("integration.console")
        logger.info("readable message", key="value")

        output = log_capture.get_output()
        assert "readable message" in output
        assert "key" in output
        assert "value" in output


class TestFileRotationIntegration:
    def test_file_rotation_creates_backup(self, tmp_path: Path) -> None:
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
            logger.info(f"Log message number {i} with extra padding to trigger rotation fast")

        LoggerFactory.reset()

        log_files = list(tmp_path.glob("rotating.log*"))
        assert len(log_files) >= 1

    def test_file_persists_after_reset(self, tmp_path: Path) -> None:
        log_file = tmp_path / "persist.log"
        config = LoggingConfig(level="INFO", file_path=str(log_file), json_output=True)
        configure_logging(config)

        logger = get_logger("persist.test")
        logger.info("persistent message", data="value")

        LoggerFactory.reset()

        assert log_file.exists()
        content = log_file.read_text()
        assert "persistent message" in content


class TestLogLevelFiltering:
    def test_levels_filter_correctly(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="WARNING", json_output=False)
        configure_logging(config)

        logger = get_logger("filter.test")
        logger.debug("should not appear")
        logger.info("should not appear")
        logger.warning("should appear warning")
        logger.error("should appear error")
        logger.critical("should appear critical")

        output = log_capture.get_output()
        assert "should not appear" not in output
        assert "should appear warning" in output
        assert "should appear error" in output
        assert "should appear critical" in output

    def test_library_level_suppression(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="DEBUG", json_output=False, library_log_levels={"noisy_lib": "ERROR"})
        configure_logging(config)

        noisy_logger = logging.getLogger("noisy_lib")
        noisy_logger.debug("noisy debug - should not appear")
        noisy_logger.info("noisy info - should not appear")
        noisy_logger.warning("noisy warning - should not appear")
        noisy_logger.error("noisy error - should appear")

        app_logger = get_logger("app")
        app_logger.debug("app debug - should appear")

        output = log_capture.get_output()
        assert "noisy debug" not in output
        assert "noisy info" not in output
        assert "noisy warning" not in output
        assert "noisy error" in output
        assert "app debug" in output


class TestContextPropagation:
    def test_context_propagation_across_modules(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True)
        configure_logging(config)

        bind_context(request_id="req-456", user_id="user-789")

        logger1 = get_logger("module1")
        logger2 = get_logger("module2")

        logger1.info("log from module1")
        logger2.info("log from module2")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 2

        for log_entry in logs:
            assert log_entry.get("request_id") == "req-456"
            assert log_entry.get("user_id") == "user-789"

    def test_context_cleared_properly(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True)
        configure_logging(config)

        bind_context(temp_key="temp_value")
        logger = get_logger("context.test")
        logger.info("with context")

        clear_context()
        configure_logging(config)
        logger.info("without context")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 2
        assert logs[0].get("temp_key") == "temp_value"
        assert "temp_key" not in logs[-1] or logs[-1].get("temp_key") is None


class TestMultipleConfigureCalls:
    def test_multiple_configure_calls_idempotent(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=False)

        configure_logging(config)
        configure_logging(config)
        configure_logging(config)

        logger = get_logger("idempotent.test")
        logger.info("single message")

        output = log_capture.get_output()
        count = output.count("single message")
        assert count == 1

    def test_reconfigure_with_different_level(self, log_capture: LogCapture) -> None:
        config_error = LoggingConfig(level="ERROR", json_output=False)
        configure_logging(config_error)

        logger = get_logger("reconfig.test")
        logger.info("should not appear with ERROR level")

        config_debug = LoggingConfig(level="DEBUG", json_output=False)
        configure_logging(config_debug)

        logger.info("should appear with DEBUG level")

        output = log_capture.get_output()
        assert "should not appear" not in output
        assert "should appear with DEBUG level" in output


class TestExceptionLogging:
    def test_exception_info_captured(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="ERROR", json_output=True)
        configure_logging(config)

        logger = get_logger("exception.test")

        try:
            raise ValueError("test error message")
        except ValueError:
            logger.exception("caught exception")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 1

        log_entry = logs[0]
        assert log_entry.get("event") == "caught exception"
        assert "exception" in log_entry or "exc_info" in log_entry or "traceback" in log_entry


class TestThreadSafety:
    def test_concurrent_logging(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True)
        configure_logging(config)

        def log_from_thread(thread_id: int) -> None:
            logger = get_logger(f"thread.{thread_id}")
            for i in range(10):
                logger.info(f"message {i} from thread {thread_id}", thread_id=thread_id, msg_id=i)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(log_from_thread, i) for i in range(4)]
            for future in futures:
                future.result()

        logs = log_capture.get_json_logs()
        assert len(logs) >= 40

        thread_ids = {log_entry.get("thread_id") for log_entry in logs if "thread_id" in log_entry}
        assert len(thread_ids) == 4


class TestServiceNamePropagation:
    def test_service_name_in_all_logs(self, log_capture: LogCapture) -> None:
        config = LoggingConfig(level="INFO", json_output=True, service_name="my-microservice")
        configure_logging(config)

        logger = get_logger("service.test")
        logger.info("log1")
        logger.warning("log2")
        logger.error("log3")

        logs = log_capture.get_json_logs()
        assert len(logs) >= 3

        for log_entry in logs:
            assert log_entry.get("service") == "my-microservice"
