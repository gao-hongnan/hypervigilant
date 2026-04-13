from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, overload

from tenacity import (
    AsyncRetrying,
    after_nothing,
    before_nothing,
    retry_if_exception,
    retry_if_exception_type,
    retry_if_not_exception_type,
    stop_never,
    wait_none,
)
from tenacity.asyncio import _portable_async_sleep

from .types import (
    AfterCallback,
    BeforeCallback,
    BeforeSleepCallback,
    RetryBaseT,
    RetryError,
    RetryErrorCallback,
    RetryErrorClass,
    SleepFunc,
    StopBaseT,
    T,
    WaitBaseT,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


def build_retry_condition(
    retry_on: tuple[type[Exception], ...] | None = None,
    never_retry_on: tuple[type[Exception], ...] | None = None,
    retry_if: Callable[[BaseException], bool] | None = None,
) -> RetryBaseT:
    if retry_if is not None:
        return retry_if_exception(retry_if)
    positive_condition = retry_if_exception_type(retry_on or Exception)
    if never_retry_on:
        return positive_condition & retry_if_not_exception_type(never_retry_on)
    return positive_condition


@overload
def retry(
    mode: Literal["decorator"] = "decorator",
    *,
    stop: StopBaseT = ...,
    wait: WaitBaseT = ...,
    retry_condition: RetryBaseT = ...,
    before: BeforeCallback = ...,
    after: AfterCallback = ...,
    before_sleep: BeforeSleepCallback | None = ...,
    sleep: SleepFunc = ...,
    reraise: bool = ...,
    retry_error_cls: RetryErrorClass = ...,
    retry_error_callback: RetryErrorCallback | None = ...,
    **kwargs: Any,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]: ...


@overload
def retry(
    mode: Literal["context_manager"],
    *,
    stop: StopBaseT = ...,
    wait: WaitBaseT = ...,
    retry_condition: RetryBaseT = ...,
    before: BeforeCallback = ...,
    after: AfterCallback = ...,
    before_sleep: BeforeSleepCallback | None = ...,
    sleep: SleepFunc = ...,
    reraise: bool = ...,
    retry_error_cls: RetryErrorClass = ...,
    retry_error_callback: RetryErrorCallback | None = ...,
    **kwargs: Any,
) -> AsyncRetrying: ...


def retry(
    mode: Literal["decorator", "context_manager"] = "decorator",
    *,
    stop: StopBaseT = stop_never,
    wait: WaitBaseT = wait_none(),  # noqa: B008
    retry_condition: RetryBaseT = retry_if_exception_type(),  # noqa: B008
    before: BeforeCallback = before_nothing,
    after: AfterCallback = after_nothing,
    before_sleep: BeforeSleepCallback | None = None,
    sleep: SleepFunc = _portable_async_sleep,
    reraise: bool = False,
    retry_error_cls: RetryErrorClass = RetryError,
    retry_error_callback: RetryErrorCallback | None = None,
    **kwargs: Any,
) -> AsyncRetrying | Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    retrying = AsyncRetrying(
        stop=stop,
        wait=wait,
        retry=retry_condition,
        before=before,
        after=after,
        before_sleep=before_sleep,
        sleep=sleep,
        reraise=reraise,
        retry_error_cls=retry_error_cls,
        retry_error_callback=retry_error_callback,
        **kwargs,
    )
    if mode == "decorator":
        return retrying.wraps
    return retrying
