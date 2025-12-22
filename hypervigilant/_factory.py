from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import ClassVar, Generic, Self, TypeVar

from ._handlers import remove_handler_from_root

ConfigT = TypeVar("ConfigT")
LoggerT = TypeVar("LoggerT")


class BaseLoggerFactory(ABC, Generic[ConfigT, LoggerT]):
    _handler: ClassVar[logging.Handler | None] = None
    _close_on_replace: ClassVar[bool] = True

    @classmethod
    @abstractmethod
    def create(cls: type[Self], config: ConfigT) -> LoggerT: ...

    @classmethod
    def _replace_handler(cls: type[Self], new_handler: logging.Handler) -> None:
        remove_handler_from_root(cls._handler, close=cls._close_on_replace)
        root = logging.getLogger()
        root.addHandler(new_handler)
        cls._handler = new_handler

    @classmethod
    def reset(cls: type[Self]) -> None:
        remove_handler_from_root(cls._handler, close=True)
        cls._handler = None
        cls._on_reset()

    @classmethod
    def _on_reset(cls: type[Self]) -> None: ...
