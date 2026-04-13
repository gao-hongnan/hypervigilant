from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from tenacity import RetryCallState, RetryError
from tenacity.retry import retry_base
from tenacity.stop import stop_base
from tenacity.wait import wait_base

T = TypeVar("T")

type StopBaseT = stop_base | Callable[[RetryCallState], bool]
type WaitBaseT = wait_base | Callable[[RetryCallState], float | int]
type RetryBaseT = retry_base | Callable[[RetryCallState], bool]
type BeforeCallback = Callable[[RetryCallState], Awaitable[None] | None]
type AfterCallback = Callable[[RetryCallState], Awaitable[None] | None]
type BeforeSleepCallback = Callable[[RetryCallState], Awaitable[None] | None]
type SleepFunc = Callable[[float], Awaitable[None]]
type RetryErrorCallback = Callable[[RetryCallState], Awaitable[Any] | Any]
type RetryErrorClass = type[RetryError]
