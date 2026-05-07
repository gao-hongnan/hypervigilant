from __future__ import annotations

import logging

import pytest

from hypervigilant.loggers.factory import BaseLoggerFactory


@pytest.fixture(autouse=True)
def _reset_root() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.NOTSET)
    logging.getLogger("httpx").setLevel(logging.NOTSET)


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
