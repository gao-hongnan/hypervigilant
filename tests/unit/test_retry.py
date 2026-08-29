"""Unit tests for the retry module.

Covers :class:`RetryConfig` Pydantic validation, the
:func:`build_retry_condition` branch matrix, :func:`retry` decorator and
``CONTEXT_MANAGER`` execution modes against real ``tenacity.AsyncRetrying``, and
the :func:`_log_retry` observability callback.
"""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    RetryError,
    stop_after_attempt,
    wait_exponential,
    wait_none,
)

from hypervigilant.retry import (
    RetryConfig,
    RetryMode,
    _log_retry,
    build_retry_condition,
    retry,
)

pytestmark = pytest.mark.unit


class TestRetryConfig:
    def test_defaults(self) -> None:
        config = RetryConfig()

        assert config.max_attempts == 3
        assert config.wait_min == 1.0
        assert config.wait_max == 60.0
        assert config.multiplier == 1.0
        assert config.exp_base == 2.0
        assert config.retry_on_exceptions is None
        assert config.never_retry_on is None
        assert config.retry_if is None
        assert config.reraise is True

    def test_accepts_custom_values(self) -> None:
        def always_retry(_: BaseException) -> bool:
            return True

        config = RetryConfig(
            max_attempts=10,
            wait_min=0.5,
            wait_max=120.0,
            multiplier=2.5,
            exp_base=3.0,
            retry_on_exceptions=(ValueError, KeyError),
            never_retry_on=(TypeError,),
            retry_if=always_retry,
            reraise=False,
        )

        assert config.max_attempts == 10
        assert config.wait_min == 0.5
        assert config.wait_max == 120.0
        assert config.multiplier == 2.5
        assert config.exp_base == 3.0
        assert config.retry_on_exceptions == (ValueError, KeyError)
        assert config.never_retry_on == (TypeError,)
        assert config.retry_if is always_retry
        assert config.reraise is False

    def test_max_attempts_below_one_rejected(self) -> None:
        with pytest.raises(ValueError):
            RetryConfig(max_attempts=0)

    def test_negative_float_bounds_rejected(self) -> None:
        with pytest.raises(ValueError):
            RetryConfig(wait_min=-1.0)
        with pytest.raises(ValueError):
            RetryConfig(wait_max=-1.0)
        with pytest.raises(ValueError):
            RetryConfig(multiplier=-1.0)

    def test_wait_min_above_wait_max_rejected(self) -> None:
        with pytest.raises(ValidationError, match="wait_min"):
            RetryConfig(wait_min=0.75, wait_max=0.5)

    def test_exp_base_below_one_rejected(self) -> None:
        with pytest.raises(ValueError):
            RetryConfig(exp_base=0.5)

    def test_min_boundary_values_accepted(self) -> None:
        config = RetryConfig(
            max_attempts=1,
            wait_min=0,
            wait_max=0,
            multiplier=0,
            exp_base=1,
        )

        assert config.max_attempts == 1
        assert config.wait_min == 0
        assert config.wait_max == 0
        assert config.multiplier == 0
        assert config.exp_base == 1

    def test_is_frozen(self) -> None:
        config = RetryConfig()

        with pytest.raises(ValidationError, match="frozen"):
            config.max_attempts = 1  # type: ignore[misc]

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError, match="extra_forbidden"):
            RetryConfig.model_validate({"unknown": True})


class TestRetryMode:
    def test_is_str_enum(self) -> None:
        assert issubclass(RetryMode, str)
        assert RetryMode.DECORATOR.value == "decorator"
        assert RetryMode.CONTEXT_MANAGER.value == "context_manager"

    def test_member_count(self) -> None:
        assert len(RetryMode) == 2


class TestBuildRetryCondition:
    async def test_retry_if_predicate_takes_precedence(self) -> None:
        condition = build_retry_condition(
            retry_on=(TypeError,),
            retry_if=lambda exc: isinstance(exc, ValueError),
        )
        decorator = retry(
            stop=stop_after_attempt(5),
            wait=wait_none(),
            retry_condition=condition,
            reraise=True,
        )

        calls = 0

        @decorator
        async def raises_value_error() -> None:
            nonlocal calls
            calls += 1
            raise ValueError("predicate says retry")

        with pytest.raises(ValueError):
            await raises_value_error()
        assert calls == 5

    async def test_retry_if_predicate_false_stops_immediately(self) -> None:
        condition = build_retry_condition(retry_if=lambda _: False)
        decorator = retry(stop=stop_after_attempt(5), wait=wait_none(), retry_condition=condition)

        calls = 0

        @decorator
        async def always_fails() -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("predicate says never retry")

        with pytest.raises(RuntimeError):
            await always_fails()
        assert calls == 1

    async def test_retry_on_specific_exception_only(self) -> None:
        condition = build_retry_condition(retry_on=(ValueError,))
        decorator = retry(stop=stop_after_attempt(5), wait=wait_none(), retry_condition=condition)

        calls = 0

        @decorator
        async def raises_type_error() -> None:
            nonlocal calls
            calls += 1
            raise TypeError("not in retry_on")

        with pytest.raises(TypeError):
            await raises_type_error()
        assert calls == 1

    async def test_never_retry_on_overrides_retry_on(self) -> None:
        condition = build_retry_condition(
            retry_on=(Exception,),
            never_retry_on=(TypeError,),
        )
        decorator = retry(stop=stop_after_attempt(5), wait=wait_none(), retry_condition=condition)

        type_error_calls = 0

        @decorator
        async def raises_type_error() -> None:
            nonlocal type_error_calls
            type_error_calls += 1
            raise TypeError("never_retry_on blocks this")

        with pytest.raises(TypeError):
            await raises_type_error()
        assert type_error_calls == 1

    async def test_never_retry_on_allows_other_exceptions(self) -> None:
        condition = build_retry_condition(
            retry_on=(Exception,),
            never_retry_on=(TypeError,),
        )
        decorator = retry(stop=stop_after_attempt(3), wait=wait_none(), retry_condition=condition)

        value_error_calls = 0

        @decorator
        async def raises_value_error() -> int:
            nonlocal value_error_calls
            value_error_calls += 1
            if value_error_calls < 3:
                raise ValueError("retryable")
            return 7

        assert await raises_value_error() == 7
        assert value_error_calls == 3

    async def test_defaults_retry_on_all_exceptions(self) -> None:
        condition = build_retry_condition()
        decorator = retry(stop=stop_after_attempt(2), wait=wait_none(), retry_condition=condition)

        calls = 0

        @decorator
        async def raises_runtime_error() -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("any exception retries")

        with pytest.raises((RuntimeError, RetryError)):
            await raises_runtime_error()
        assert calls == 2


class TestRetryDecoratorMode:
    async def test_returns_callable_decorator(self) -> None:
        decorator = retry(stop=stop_after_attempt(1), wait=wait_none())
        assert callable(decorator)

    async def test_retries_until_success(self) -> None:
        decorator = retry(stop=stop_after_attempt(5), wait=wait_none(), reraise=True)

        calls = 0

        @decorator
        async def flaky() -> str:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise ValueError("transient")
            return "ok"

        assert await flaky() == "ok"
        assert calls == 3

    async def test_reraise_true_propagates_last_exception(self) -> None:
        decorator = retry(stop=stop_after_attempt(3), wait=wait_none(), reraise=True)

        calls = 0

        @decorator
        async def always_fails() -> None:
            nonlocal calls
            calls += 1
            raise ValueError(f"attempt {calls}")

        with pytest.raises(ValueError, match="attempt 3"):
            await always_fails()
        assert calls == 3

    async def test_reraise_false_raises_retry_error(self) -> None:
        decorator = retry(stop=stop_after_attempt(2), wait=wait_none(), reraise=False)

        @decorator
        async def always_fails() -> None:
            raise ValueError("wrapped")

        with pytest.raises(RetryError) as exc_info:
            await always_fails()
        assert isinstance(exc_info.value.last_attempt.exception(), ValueError)

    async def test_before_after_before_sleep_callbacks_invoked(self) -> None:
        before_attempts: list[int] = []
        after_attempts: list[int] = []
        before_sleep_attempts: list[int] = []

        async def before(state: RetryCallState) -> None:
            before_attempts.append(state.attempt_number)

        async def after(state: RetryCallState) -> None:
            after_attempts.append(state.attempt_number)

        async def before_sleep(state: RetryCallState) -> None:
            before_sleep_attempts.append(state.attempt_number)

        decorator = retry(
            stop=stop_after_attempt(3),
            wait=wait_none(),
            before=before,
            after=after,
            before_sleep=before_sleep,
            reraise=True,
        )

        @decorator
        async def always_fails() -> None:
            raise ValueError("fail")

        with pytest.raises(ValueError):
            await always_fails()
        assert before_attempts == [1, 2, 3]
        assert after_attempts == [1, 2, 3]
        assert before_sleep_attempts == [1, 2]

    async def test_wait_schedule_uses_injected_sleep(self) -> None:
        sleeps: list[float] = []

        async def recording_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        decorator = retry(
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=1, max=8, exp_base=2),
            sleep=recording_sleep,
            reraise=True,
        )

        @decorator
        async def always_fails() -> None:
            raise ValueError("fail")

        with pytest.raises(ValueError):
            await always_fails()
        assert sleeps == [1.0, 2.0]

    async def test_retry_error_callback_invoked_on_exhaustion(self) -> None:
        captured: list[RetryCallState] = []

        def on_error(state: RetryCallState) -> str:
            captured.append(state)
            return "fallback"

        decorator = retry(
            stop=stop_after_attempt(2),
            wait=wait_none(),
            retry_error_callback=on_error,
        )

        @decorator
        async def always_fails() -> str:
            raise ValueError("fail")

        assert await always_fails() == "fallback"
        assert len(captured) == 1


class TestRetryContextManagerMode:
    async def test_returns_async_retrying_instance(self) -> None:
        retrying = retry(
            mode=RetryMode.CONTEXT_MANAGER,
            stop=stop_after_attempt(3),
            wait=wait_none(),
        )
        assert isinstance(retrying, AsyncRetrying)

    async def test_call_executes_retry_loop(self) -> None:
        retrying = retry(
            mode=RetryMode.CONTEXT_MANAGER,
            stop=stop_after_attempt(5),
            wait=wait_none(),
            reraise=True,
        )

        calls = 0

        async def flaky() -> int:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise ValueError("transient")
            return 99

        assert await retrying(flaky) == 99
        assert calls == 3

    async def test_call_reraises_on_exhaustion(self) -> None:
        retrying = retry(
            mode=RetryMode.CONTEXT_MANAGER,
            stop=stop_after_attempt(2),
            wait=wait_none(),
            reraise=True,
        )

        async def always_fails() -> None:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            await retrying(always_fails)

    async def test_call_passes_positional_and_keyword_args(self) -> None:
        retrying = retry(
            mode=RetryMode.CONTEXT_MANAGER,
            stop=stop_after_attempt(5),
            wait=wait_none(),
            reraise=True,
        )

        async def add(a: int, b: int, *, scale: int) -> int:
            return a + b * scale

        assert await retrying(add, 2, 3, scale=10) == 32


class TestLogRetryCallback:
    async def test_logs_warning_with_attempt_and_exception(self, caplog: pytest.LogCaptureFixture) -> None:
        decorator = retry(
            stop=stop_after_attempt(2),
            wait=wait_none(),
            before_sleep=_log_retry,
            reraise=True,
        )

        @decorator
        async def always_fails() -> None:
            raise ValueError("kaput")

        with (
            caplog.at_level(logging.WARNING, logger="hypervigilant.retry.callbacks"),
            pytest.raises(ValueError),
        ):
            await always_fails()

        retry_records = [r for r in caplog.records if "Retry attempt" in r.getMessage()]
        assert len(retry_records) == 1
        assert "Retry attempt 1" in retry_records[0].getMessage()
        assert "kaput" in retry_records[0].getMessage()
        assert retry_records[0].levelno == logging.WARNING


class TestRetryPublicApi:
    def test_all_exports_resolve(self) -> None:
        import hypervigilant.retry as module

        expected = {
            "AfterCallback",
            "BeforeCallback",
            "BeforeSleepCallback",
            "RetryBaseT",
            "RetryConfig",
            "RetryErrorCallback",
            "RetryErrorClass",
            "RetryMode",
            "SleepFunc",
            "StopBaseT",
            "WaitBaseT",
            "_log_retry",
            "build_retry_condition",
            "retry",
        }
        assert set(module.__all__) == expected
        for name in expected:
            assert getattr(module, name) is not None
