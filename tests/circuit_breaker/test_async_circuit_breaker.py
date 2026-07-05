"""Async unit and integration tests for the migrated circuit_breaker(...) factory.

Re-targeted in PR 5 to consume the new public surface
(:class:`AsyncBreakerRegistry`, typed events, :exc:`BreakerOpenError`).
The behavioural contract is identical to the legacy purgatory-backed
suite this file replaces:

* ``CLOSED -> OPENED`` after ``threshold`` consecutive failures.
* ``OPENED -> HALF_OPENED -> CLOSED`` after TTL elapses + a successful probe.
* Excluded exceptions do not count as failures.
* Event hooks fire with the typed events at the correct transitions.
"""

import asyncio

import pytest

from hypervigilant.circuit_breaker import (
    BreakerEvent,
    BreakerFailed,
    BreakerStateChanged,
)
from hypervigilant.circuit_breaker.core import circuit_breaker
from hypervigilant.circuit_breaker.errors import BreakerOpenError


class ClientError(Exception):
    """Simulates a 4xx client error (should NOT trip circuit)."""


class ServerError(Exception):
    """Simulates a 5xx server error (should trip circuit)."""


@pytest.mark.unit
async def test_circuit_opens_after_consecutive_failures() -> None:
    """``CLOSED -> OPENED`` after ``threshold`` consecutive failures."""
    cb = circuit_breaker(threshold=3, ttl=30.0)

    @cb("test-state-transition")
    async def failing_operation() -> None:
        raise ServerError("Service unavailable")

    for _ in range(3):
        with pytest.raises(ServerError, match="Service unavailable"):
            await failing_operation()

    with pytest.raises(BreakerOpenError):
        await failing_operation()


@pytest.mark.integration
async def test_circuit_recovers_after_ttl_and_successful_call() -> None:
    """``OPENED -> HALF_OPENED -> CLOSED`` after TTL and a successful probe."""
    close_events: list[str] = []

    def tracking_hook(event: BreakerEvent) -> None:
        if isinstance(event, BreakerStateChanged) and event.to_state == "closed":
            close_events.append(event.name)

    cb = circuit_breaker(threshold=2, ttl=0.1, hooks=[tracking_hook])

    call_count = 0

    @cb("test-recovery")
    async def unstable_operation() -> str:
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            raise ServerError("Temporary failure")
        return "success"

    for _ in range(2):
        with pytest.raises(ServerError):
            await unstable_operation()

    with pytest.raises(BreakerOpenError):
        await unstable_operation()

    await asyncio.sleep(0.15)

    result = await unstable_operation()
    assert result == "success"

    await asyncio.sleep(0.05)

    assert "test-recovery" in close_events

    result = await unstable_operation()
    assert result == "success"


@pytest.mark.unit
async def test_excluded_exceptions_do_not_trip_circuit() -> None:
    """Excluded exceptions propagate but do NOT count toward the threshold."""
    cb = circuit_breaker(threshold=2, ttl=30.0, exclude=[ClientError])

    exception_type_to_raise: type[Exception] = ClientError

    @cb("test-exclusion")
    async def conditional_operation() -> str:
        raise exception_type_to_raise("Error occurred")

    for _ in range(5):
        with pytest.raises(ClientError):
            await conditional_operation()

    exception_type_to_raise = ServerError

    with pytest.raises(ServerError):
        await conditional_operation()

    with pytest.raises(ServerError):
        await conditional_operation()

    with pytest.raises(BreakerOpenError):
        await conditional_operation()


@pytest.mark.unit
async def test_legacy_3_arg_hook_signature_is_adapted() -> None:
    """H4 regression: pre-rewrite consumers passed ``hook(name, event_type, event)``.

    The native dispatcher calls 1-arg hooks; without arity detection a
    legacy 3-arg hook raises ``TypeError`` on every dispatch and the
    user sees zero telemetry. The factory must detect 3-arg arity and
    wrap the legacy callable as ``lambda evt: hook(evt.name,
    legacy_type, evt)``.
    """
    received: list[tuple[str, str, BreakerEvent]] = []

    def legacy_hook(name: str, event_type: str, event: BreakerEvent) -> None:
        received.append((name, event_type, event))

    cb = circuit_breaker(threshold=2, ttl=30.0, hooks=[legacy_hook])

    @cb("test-legacy")
    async def failing_op() -> None:
        msg = "oops"
        raise ServerError(msg)

    for _ in range(2):
        with pytest.raises(ServerError):
            await failing_op()
    await cb.aclose()

    legacy_event_types = {evt_type for _, evt_type, _ in received}
    assert "circuit_breaker_created" in legacy_event_types
    assert "failed" in legacy_event_types
    assert "state_changed" in legacy_event_types
    assert all(name == "test-legacy" for name, _, _ in received)


@pytest.mark.unit
async def test_modern_1_arg_hook_signature_passes_through() -> None:
    """H4: a modern 1-arg hook receiving ``BreakerEvent`` is not adapted."""
    received: list[BreakerEvent] = []

    def modern_hook(event: BreakerEvent) -> None:
        received.append(event)

    cb = circuit_breaker(threshold=2, ttl=30.0, hooks=[modern_hook])

    @cb("test-modern")
    async def failing_op() -> None:
        msg = "oops"
        raise ServerError(msg)

    for _ in range(2):
        with pytest.raises(ServerError):
            await failing_op()
    await cb.aclose()

    assert any(isinstance(evt, BreakerFailed) for evt in received)
    assert any(isinstance(evt, BreakerStateChanged) for evt in received)


@pytest.mark.unit
async def test_hook_fires_on_state_transitions() -> None:
    """``BreakerFailed`` and ``BreakerStateChanged`` fire at the right moments."""
    state_changes: list[tuple[str, str]] = []
    failure_events: list[tuple[str, int]] = []

    def tracking_hook(event: BreakerEvent) -> None:
        if isinstance(event, BreakerStateChanged):
            state_changes.append((event.name, event.to_state))
        elif isinstance(event, BreakerFailed):
            failure_events.append((event.name, event.failure_count))

    cb = circuit_breaker(threshold=2, ttl=30.0, hooks=[tracking_hook])

    @cb("test-hook")
    async def failing_operation() -> None:
        raise ServerError("Service failure")

    for _ in range(2):
        with pytest.raises(ServerError):
            await failing_operation()

    await asyncio.sleep(0.05)

    assert len(failure_events) == 2
    assert failure_events[0] == ("test-hook", 1)
    assert failure_events[1] == ("test-hook", 2)
    assert any(name == "test-hook" and to_state == "opened" for name, to_state in state_changes)
