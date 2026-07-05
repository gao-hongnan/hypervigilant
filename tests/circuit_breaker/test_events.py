"""Tests for the typed event surface and ``EventDispatcher`` (PR 4 / task 4A).

Covers FR-010 (async hooks scheduled post-aexit; exceptions logged-and-
swallowed), FR-012 (event names drop the ``Circuit`` prefix), and AC-008
(hook exception isolation).
"""

import asyncio

import pytest

from hypervigilant.circuit_breaker import Snapshot, StorageFailurePolicy
from hypervigilant.circuit_breaker.events import (
    BreakerCreated,
    BreakerEvent,
    BreakerFailed,
    BreakerRecovered,
    BreakerStateChanged,
    EventDispatcher,
)
from hypervigilant.circuit_breaker.policy import Decision


class _CapturingObserver:
    """Records every observer callback for inspection."""

    __slots__ = ("calls", "decisions", "errors", "fallbacks")

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, float]] = []
        self.errors: list[tuple[str, str, BaseException]] = []
        self.decisions: list[tuple[str, Snapshot, Decision]] = []
        self.fallbacks: list[tuple[str, str, BaseException, StorageFailurePolicy]] = []

    def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
        self.calls.append((op, name, duration_ms))

    def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
        self.errors.append((op, name, exc))

    def on_decision(self, *, name: str, snapshot: Snapshot, decision: Decision) -> None:
        self.decisions.append((name, snapshot, decision))

    def on_storage_failure(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        fell_back_to: StorageFailurePolicy,
    ) -> None:
        self.fallbacks.append((op, name, exc, fell_back_to))


# ---------------------------------------------------------------------------
# Event dataclass shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_event_classes_drop_circuit_prefix() -> None:
    """FR-012: vendor names (``CircuitBreakerCreated`` etc.) MUST NOT be exported."""
    from hypervigilant.circuit_breaker import events as module

    assert hasattr(module, "BreakerCreated")
    assert hasattr(module, "BreakerStateChanged")
    assert hasattr(module, "BreakerFailed")
    assert hasattr(module, "BreakerRecovered")
    assert not hasattr(module, "CircuitBreakerCreated")
    assert not hasattr(module, "CircuitBreakerFailed")
    assert not hasattr(module, "CircuitBreakerRecovered")
    assert not hasattr(module, "ContextChanged")


@pytest.mark.unit
def test_breaker_event_union_alias_exists() -> None:
    """:data:`BreakerEvent` is the discriminated union of the four event types."""
    evt: BreakerEvent = BreakerCreated(name="x", config_repr="cfg")
    assert isinstance(evt, BreakerCreated)


# ---------------------------------------------------------------------------
# Dispatcher behaviour
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_sync_handler_runs_inline() -> None:
    """A sync handler is invoked synchronously inside ``dispatch``."""
    received: list[str] = []
    dispatcher = EventDispatcher()
    dispatcher.register(BreakerCreated, lambda evt: received.append(evt.name))
    await dispatcher.dispatch(BreakerCreated(name="svc", config_repr="cfg"))
    assert received == ["svc"]


@pytest.mark.unit
async def test_async_handler_runs_via_create_task() -> None:
    """An async handler is scheduled via ``asyncio.create_task`` and runs out-of-line."""
    received: list[str] = []

    async def handler(evt: BreakerEvent) -> None:
        await asyncio.sleep(0)
        received.append(evt.name)

    dispatcher = EventDispatcher()
    dispatcher.register(BreakerStateChanged, handler)
    await dispatcher.dispatch(
        BreakerStateChanged(
            name="svc",
            from_state="closed",
            to_state="opened",
            generation=1,
        ),
    )
    # The async handler hasn't necessarily run yet; aclose drains it.
    await dispatcher.aclose()
    assert received == ["svc"]


@pytest.mark.unit
async def test_sync_handler_exception_is_isolated_and_logged() -> None:
    """A sync handler exception is caught and routed to the observer."""
    observer = _CapturingObserver()
    dispatcher = EventDispatcher(observer=observer)

    def bad(evt: BreakerEvent) -> None:
        del evt
        msg = "boom"
        raise ValueError(msg)

    dispatcher.register(BreakerCreated, bad)
    await dispatcher.dispatch(BreakerCreated(name="svc", config_repr="cfg"))
    assert len(observer.errors) == 1
    op, name, exc = observer.errors[0]
    assert op == "hook_dispatch"
    assert name == "svc"
    assert isinstance(exc, ValueError)


@pytest.mark.unit
async def test_async_handler_exception_is_isolated_and_logged() -> None:
    """An async handler exception is caught and routed to the observer."""
    observer = _CapturingObserver()
    dispatcher = EventDispatcher(observer=observer)

    async def bad(evt: BreakerEvent) -> None:
        del evt
        await asyncio.sleep(0)
        msg = "async boom"
        raise RuntimeError(msg)

    dispatcher.register(BreakerFailed, bad)
    await dispatcher.dispatch(
        BreakerFailed(name="svc", exception_repr="oops", failure_count=3),
    )
    await dispatcher.aclose()
    assert len(observer.errors) == 1
    assert isinstance(observer.errors[0][2], RuntimeError)


@pytest.mark.unit
async def test_unsubscribe_removes_handler() -> None:
    """The callable returned by ``register`` removes the handler when invoked."""
    received: list[str] = []
    dispatcher = EventDispatcher()
    unsub = dispatcher.register(BreakerCreated, lambda evt: received.append(evt.name))
    unsub()
    await dispatcher.dispatch(BreakerCreated(name="svc", config_repr="cfg"))
    assert received == []


@pytest.mark.unit
async def test_unsubscribe_is_idempotent() -> None:
    """Calling the unsubscribe callable twice does not raise."""
    dispatcher = EventDispatcher()
    unsub = dispatcher.register(BreakerCreated, lambda _: None)
    unsub()
    unsub()  # no exception.


@pytest.mark.unit
async def test_multiple_handlers_dispatch_in_registration_order() -> None:
    """Sync handlers run in registration order; one failing handler doesn't block others."""
    observer = _CapturingObserver()
    received: list[str] = []
    dispatcher = EventDispatcher(observer=observer)

    def first(evt: BreakerEvent) -> None:
        received.append(f"first:{evt.name}")
        msg = "first failed"
        raise ValueError(msg)

    def second(evt: BreakerEvent) -> None:
        received.append(f"second:{evt.name}")

    dispatcher.register(BreakerRecovered, first)
    dispatcher.register(BreakerRecovered, second)
    await dispatcher.dispatch(BreakerRecovered(name="svc", generation=2))
    assert received == ["first:svc", "second:svc"]
    assert len(observer.errors) == 1
