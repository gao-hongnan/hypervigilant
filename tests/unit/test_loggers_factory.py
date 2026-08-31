from __future__ import annotations

import logging

import pytest

from hypervigilant.loggers.factory import BaseLoggerFactory
from hypervigilant.loggers.native import LoggerFactory as NativeLoggerFactory
from hypervigilant.loggers.structlog import LoggerFactory as StructlogLoggerFactory

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _reset_root() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.NOTSET)
    logging.getLogger("httpx").setLevel(logging.NOTSET)
    BaseLoggerFactory._library_levels = {}


class TestFinalizeRoot:
    def test_sets_root_level(self) -> None:
        BaseLoggerFactory._finalize_root("DEBUG", {})
        assert logging.getLogger().level == logging.DEBUG

    def test_applies_library_log_levels(self) -> None:
        BaseLoggerFactory._finalize_root("INFO", {"urllib3": "WARNING", "httpx": "ERROR"})
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.ERROR

    def test_empty_library_levels_does_not_mutate(self) -> None:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)
        BaseLoggerFactory._finalize_root("INFO", {})
        assert logging.getLogger("urllib3").level == logging.DEBUG


class TestLibraryLevelRestore:
    def test_reset_restores_previous_library_levels(self) -> None:
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

        BaseLoggerFactory._finalize_root("INFO", {"urllib3": "ERROR"})
        assert logging.getLogger("urllib3").level == logging.ERROR

        BaseLoggerFactory.reset()
        assert logging.getLogger("urllib3").level == logging.DEBUG

    def test_reconfigure_restores_libraries_dropped_from_config(self) -> None:
        BaseLoggerFactory._finalize_root("INFO", {"httpx": "ERROR"})
        assert logging.getLogger("httpx").level == logging.ERROR

        BaseLoggerFactory._finalize_root("INFO", {"urllib3": "WARNING"})
        assert logging.getLogger("httpx").level == logging.NOTSET
        assert logging.getLogger("urllib3").level == logging.WARNING

    def test_reset_clears_snapshot(self) -> None:
        BaseLoggerFactory._finalize_root("INFO", {"httpx": "ERROR"})
        BaseLoggerFactory.reset()
        assert BaseLoggerFactory._library_levels == {}

    def test_subclasses_do_not_share_snapshots(self) -> None:
        assert NativeLoggerFactory._library_levels is not StructlogLoggerFactory._library_levels
