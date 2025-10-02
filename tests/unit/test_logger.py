from __future__ import annotations

import logging
from io import StringIO

from hypervigilant.logger import get_logger


def test_get_logger_default():
    logger = get_logger()
    assert isinstance(logger, logging.Logger)
    assert logger.name == "hypervigilant.logger"
    assert len(logger.handlers) > 0


def test_get_logger_with_name():
    logger = get_logger("test_logger")
    assert logger.name == "test_logger"


def test_get_logger_with_level():
    logger = get_logger("debug_logger", level="DEBUG")
    assert logger.level == logging.DEBUG

    logger2 = get_logger("info_logger", level=logging.INFO)
    assert logger2.level == logging.INFO


def test_get_logger_with_custom_handler():
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")

    logger = get_logger("custom_logger", level="INFO", handlers=[handler], formatter=formatter)

    logger.info("test message")
    output = stream.getvalue()
    assert "INFO:custom_logger:test message" in output


def test_get_logger_propagate():
    logger = get_logger("no_propagate", propagate=False)
    assert logger.propagate is False

    logger2 = get_logger("yes_propagate", propagate=True)
    assert logger2.propagate is True


def test_get_logger_custom_attributes():
    # Users can still set custom attributes directly on the logger
    logger = get_logger("extra_attrs")
    logger.custom_attr = "test_value"  # type: ignore[attr-defined]
    assert hasattr(logger, "custom_attr")
    assert getattr(logger, "custom_attr") == "test_value"  # noqa: B009
