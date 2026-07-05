"""Tests for ``AsyncCircuitBreaker`` + ``AsyncBreakerRegistry`` (PR 4 / task 4B).

Covers FR-001 (async context manager), FR-002 (registry semantics),
FR-013 (snapshot value object), AC-001..AC-008 in-memory variants.
"""

import asyncio

import pytest

from hypervigilant.circuit_breaker import (
    AsyncBreakerRegistry,
    AsyncCircuitBreaker,
    BreakerConfig,
    BreakerOpenError,
    BreakerStatus,
    FakeClock,
)
from hypervigilant.circuit_breaker.config import CountingPolicy
from hypervigilant.circuit_breaker.events import (
    BreakerCreated,
    BreakerFailed,
    BreakerRecovered,
    BreakerStateChanged,
)
from hypervigilant.circuit_breaker.policy import AllowCall
from hypervigilant.circuit_breaker.state import Snapshot
from hypervigilant.circuit_breaker.stores.memory import InMemoryStore


@pytest.mark.unit
async def test_get_returns_same_instance_for_same_name() -> None:
    """Identity Map: ``get(x)`` followed by ``get(x)`` returns the same object."""
    reg = AsyncBreakerRegistry()
    a = await reg.get("x")
    b = await reg.get("x")
    assert a is b


@pytest.mark.unit
async def test_get_returns_distinct_instances_for_distinct_names() -> None:
    """Different names map to different breakers."""
    reg = AsyncBreakerRegistry()
    a = await reg.get("x")
    b = await reg.get("y")
    assert a is not b
    assert a.name == "x"
    assert b.name == "y"


@pytest.mark.unit
async def test_async_with_breaker_runs_body_when_closed() -> None:
    """Happy-path: a closed breaker permits the body."""
    reg = AsyncBreakerRegistry()
    breaker = await reg.get("svc")
    entered = False
    async with breaker:
        entered = True
    assert entered


@pytest.mark.unit
async def test_failure_in_body_records_via_breaker() -> None:
    """A failure inside the body is recorded as a circuit failure."""
    reg = AsyncBreakerRegistry(default_config=BreakerConfig(threshold=2))
    breaker = await reg.get("svc")
    with pytest.raises(RuntimeError):
        async with breaker:
            msg = "oops"
            raise RuntimeError(msg)
    status = await breaker.snapshot()
    assert status.failure_count == 1


@pytest.mark.unit
async def test_threshold_crossing_raises_breaker_open_error_on_next_acquire() -> None:
    """After threshold failures the next acquire raises ``BreakerOpenError``."""
    reg = AsyncBreakerRegistry(default_config=BreakerConfig(threshold=2))
    breaker = await reg.get("svc")
    for _ in range(2):
        with pytest.raises(RuntimeError):
            async with breaker:
                msg = "oops"
                raise RuntimeError(msg)
    with pytest.raises(BreakerOpenError) as excinfo:
        async with breaker:
            pass  # never reached
    err = excinfo.value
    assert err.name == "svc"
    assert err.retry_after >= 0.0


@pytest.mark.unit
async def test_excluded_exception_does_not_count_as_failure() -> None:
    """``BreakerConfig.exclude`` skips failure recording."""
    reg = AsyncBreakerRegistry(
        default_config=BreakerConfig(threshold=2, exclude=(ValueError,)),
    )
    breaker = await reg.get("svc")
    for _ in range(5):
        with pytest.raises(ValueError, match="filter"):
            async with breaker:
                msg = "filter"
                raise ValueError(msg)
    status = await breaker.snapshot()
    assert status.failure_count == 0
    assert status.state == "closed"


@pytest.mark.unit
async def test_cancelled_error_propagates_without_recording_failure() -> None:
    """``asyncio.CancelledError`` is treated as cooperative shutdown, not a failure."""
    reg = AsyncBreakerRegistry()
    breaker = await reg.get("svc")
    with pytest.raises(asyncio.CancelledError):
        async with breaker:
            raise asyncio.CancelledError
    status = await breaker.snapshot()
    assert status.failure_count == 0


@pytest.mark.unit
async def test_decorator_wraps_async_function() -> None:
    """``registry('name')`` returns a decorator that protects the call.

    Applied via explicit decorator-call rather than ``@`` syntax to keep
    the test mypy-strict-clean (mypy refuses to track ParamSpec through
    ``@`` decoration on async functions in strict mode).
    """
    reg = AsyncBreakerRegistry()

    async def raw(arg: int) -> int:
        return arg * 2

    wrapped = reg("svc")(raw)
    assert await wrapped(3) == 6


@pytest.mark.unit
async def test_on_subscribes_to_breaker_state_changed() -> None:
    """``registry.on(EventType, handler)`` fires on state transitions."""
    reg = AsyncBreakerRegistry(default_config=BreakerConfig(threshold=2))
    seen: list[tuple[str, str, str]] = []

    def handler(evt: BreakerStateChanged) -> None:
        seen.append((evt.name, evt.from_state, evt.to_state))

    reg.on(BreakerStateChanged, handler)
    breaker = await reg.get("svc")
    for _ in range(2):
        with pytest.raises(RuntimeError):
            async with breaker:
                msg = "oops"
                raise RuntimeError(msg)
    await reg.aclose()
    assert ("svc", "closed", "opened") in seen


@pytest.mark.unit
async def test_breaker_created_event_fires_on_first_get() -> None:
    """``BreakerCreated`` fires exactly once per name."""
    reg = AsyncBreakerRegistry()
    received: list[str] = []
    reg.on(BreakerCreated, lambda evt: received.append(evt.name))
    await reg.get("svc")
    await reg.get("svc")  # second call MUST NOT re-emit.
    await reg.aclose()
    assert received == ["svc"]


@pytest.mark.unit
async def test_breaker_failed_event_fires_on_failure() -> None:
    """``BreakerFailed`` carries the exception repr and post-mutation count."""
    reg = AsyncBreakerRegistry(default_config=BreakerConfig(threshold=5))
    failed: list[BreakerFailed] = []
    reg.on(BreakerFailed, failed.append)
    breaker = await reg.get("svc")
    with pytest.raises(RuntimeError):
        async with breaker:
            msg = "oops"
            raise RuntimeError(msg)
    await reg.aclose()
    assert len(failed) == 1
    assert failed[0].name == "svc"
    assert failed[0].failure_count == 1


@pytest.mark.unit
async def test_breaker_recovered_event_fires_after_half_open_success() -> None:
    """A successful probe call emits ``BreakerRecovered`` and ``BreakerStateChanged``."""
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    reg = AsyncBreakerRegistry(
        default_config=BreakerConfig(threshold=2, ttl=30.0),
        store=store,
    )
    recovered: list[BreakerRecovered] = []
    reg.on(BreakerRecovered, recovered.append)

    breaker = await reg.get("svc")
    for _ in range(2):
        with pytest.raises(RuntimeError):
            async with breaker:
                msg = "oops"
                raise RuntimeError(msg)
    clock.advance(35.0)
    async with breaker:
        pass  # probe succeeds
    await reg.aclose()
    assert len(recovered) == 1
    assert recovered[0].name == "svc"


@pytest.mark.unit
async def test_snapshot_returns_breaker_status_value_object() -> None:
    """``await breaker.snapshot()`` returns an immutable ``BreakerStatus``."""
    reg = AsyncBreakerRegistry()
    breaker = await reg.get("svc")
    status = await breaker.snapshot()
    assert isinstance(status, BreakerStatus)
    assert status.name == "svc"
    assert status.state == "closed"


@pytest.mark.unit
async def test_async_circuit_breaker_has_no_live_state_attribute() -> None:
    """FR-013: the breaker MUST NOT expose a live ``state`` attribute."""
    reg = AsyncBreakerRegistry()
    breaker = await reg.get("svc")
    assert isinstance(breaker, AsyncCircuitBreaker)
    assert not hasattr(breaker, "state")
    assert not hasattr(breaker, "failure_count")


# ---------------------------------------------------------------------------
# H7 — lifespan API + handler timeout.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_registry_supports_async_with_lifespan() -> None:
    """H7: ``async with AsyncBreakerRegistry(...) as reg:`` is the canonical lifespan."""
    async with AsyncBreakerRegistry(default_config=BreakerConfig(threshold=2)) as reg:
        breaker = await reg.get("svc")
        async with breaker:
            pass


@pytest.mark.unit
async def test_dispatcher_handler_timeout_isolates_hung_handlers() -> None:
    """H7 regression: a hung async handler must not block ``aclose`` indefinitely.

    The dispatcher applies ``asyncio.timeout(handler_timeout_seconds)``
    to every async handler so a wedged exporter cannot pin the registry's
    lifespan teardown forever.
    """
    from hypervigilant.circuit_breaker.events import EventDispatcher

    errors: list[BaseException] = []

    class _Capture:
        def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
            del op, name, duration_ms

        def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
            del op, name
            errors.append(exc)

        def on_decision(self, *, name: str, snapshot: object, decision: object) -> None:
            del name, snapshot, decision

        def on_storage_failure(
            self,
            *,
            op: str,
            name: str,
            exc: BaseException,
            fell_back_to: object,
        ) -> None:
            del op, name, exc, fell_back_to

    dispatcher = EventDispatcher(observer=_Capture(), handler_timeout_seconds=0.05)  # type: ignore[arg-type]

    async def slow_handler(event: BreakerCreated) -> None:
        del event
        await asyncio.sleep(10.0)

    dispatcher.register(BreakerCreated, slow_handler)
    await dispatcher.dispatch(BreakerCreated(name="x", config_repr="<...>"))
    await dispatcher.aclose()

    assert errors, "Expected handler timeout to be reported via observer.on_error."
    assert any(isinstance(exc, TimeoutError) for exc in errors)


# ---------------------------------------------------------------------------
# H1 regression — retry_after uses opened_at + ttl, not config.ttl constant.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_retry_after_decreases_as_time_elapses() -> None:
    """H1 regression: ``retry_after`` MUST be ``max(ttl - elapsed, 0.0)``.

    The buggy implementation returned ``config.ttl`` for any non-closed
    state, ignoring ``snap.opened_at`` and the store's clock entirely.
    """
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    reg = AsyncBreakerRegistry(
        default_config=BreakerConfig(threshold=2, ttl=30.0),
        store=store,
    )
    breaker = await reg.get("svc")

    for _ in range(2):
        with pytest.raises(RuntimeError):
            async with breaker:
                msg = "trip"
                raise RuntimeError(msg)

    status_at_open = await breaker.snapshot()
    assert status_at_open.state == "opened"
    assert status_at_open.retry_after == pytest.approx(30.0)

    clock.advance(5.0)
    status_after_5s = await breaker.snapshot()
    assert status_after_5s.retry_after == pytest.approx(25.0)

    clock.advance(20.0)
    status_after_25s = await breaker.snapshot()
    assert status_after_25s.retry_after == pytest.approx(5.0)

    clock.advance(10.0)
    status_after_ttl = await breaker.snapshot()
    assert status_after_ttl.retry_after == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# B3 + B4 regressions — pre-snapshot plumbing.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_store_acquire_returns_decision_and_snapshot_tuple() -> None:
    """B3+B4 contract: ``BreakerStore.acquire`` returns ``(Decision, Snapshot)``.

    Eliminates the second ``peek`` round-trip in ``__aenter__`` and is the
    structural fix that lets pre-snapshot live in task-scoped storage instead
    of an instance attribute.
    """
    store = InMemoryStore()
    result = await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    assert isinstance(result, tuple)
    decision, snapshot = result
    assert isinstance(decision, AllowCall)
    assert isinstance(snapshot, Snapshot)
    assert snapshot.name == "svc"
    assert snapshot.state == "closed"


@pytest.mark.unit
async def test_aenter_does_not_call_peek() -> None:
    """B4 regression: ``__aenter__`` must not issue a second store round-trip.

    The Lua ``acquire`` script (and the in-memory equivalent) already returns
    the post-mutation snapshot; the runtime layer used to follow up with
    ``peek``, doubling the Redis traffic on every protected call.
    """

    class CountingStore(InMemoryStore):
        peek_count: int = 0

        def __init__(self) -> None:  # noqa: D401 -- test double
            super().__init__()
            object.__setattr__(self, "peek_count", 0)

        async def peek(self, name: str) -> Snapshot | None:
            self.peek_count += 1
            return await super().peek(name)

    store = CountingStore()
    reg = AsyncBreakerRegistry(store=store)
    breaker = await reg.get("svc")

    pre = store.peek_count
    async with breaker:
        pass
    post_aenter_only = store.peek_count
    assert post_aenter_only == pre, (
        f"__aenter__/__aexit__ should not call store.peek; the snapshot is "
        f"already returned by acquire. peek_count went from {pre} to "
        f"{post_aenter_only}."
    )


@pytest.mark.unit
async def test_aexit_preserves_user_exception_when_record_failure_raises() -> None:
    """B2 regression: storage failure during ``__aexit__`` MUST NOT shadow the user exception.

    With FAIL_STATIC + cold cache + Redis outage, the store's
    ``record_failure`` raises ``CircuitStorageError``. Without the fix the
    caller's ``except RuntimeError`` clause silently mis-fires because
    ``__aexit__`` re-raised ``CircuitStorageError`` instead of letting the
    original exception propagate.
    """
    from hypervigilant.circuit_breaker.errors import CircuitStorageError

    class StorageDownStore(InMemoryStore):
        async def record_failure(
            self,
            name: str,
            *,
            threshold: int,
            ttl_seconds: float,
            counting: CountingPolicy | None = None,
        ) -> Snapshot:
            del name, threshold, ttl_seconds, counting
            msg = "simulated Redis outage during record_failure"
            raise CircuitStorageError(msg)

    reg = AsyncBreakerRegistry(
        default_config=BreakerConfig(threshold=2),
        store=StorageDownStore(),
    )
    breaker = await reg.get("svc")
    with pytest.raises(RuntimeError, match="downstream-500"):
        async with breaker:
            msg = "downstream-500"
            raise RuntimeError(msg)
    await reg.aclose()


@pytest.mark.unit
async def test_aexit_surfaces_storage_failure_when_body_succeeded() -> None:
    """B2: when the body succeeded, a storage failure during ``record_success``
    MUST surface to the caller (no in-flight exception to preserve).
    """
    from hypervigilant.circuit_breaker.errors import CircuitStorageError

    class StorageDownOnSuccessStore(InMemoryStore):
        async def record_success(
            self,
            name: str,
            *,
            counting: CountingPolicy | None = None,
        ) -> Snapshot:
            del name, counting
            msg = "simulated Redis outage during record_success"
            raise CircuitStorageError(msg)

    reg = AsyncBreakerRegistry(store=StorageDownOnSuccessStore())
    breaker = await reg.get("svc")
    with pytest.raises(CircuitStorageError, match="record_success"):
        async with breaker:
            pass
    await reg.aclose()


@pytest.mark.unit
async def test_concurrent_aenter_does_not_drop_state_change_event() -> None:
    """B3 regression: ``BreakerStateChanged`` must fire on the closed→opened
    transition even when a concurrent task races into ``__aenter__``.

    The buggy implementation stored pre-state on the ``AsyncCircuitBreaker``
    instance, but the registry's Identity Map returns the same instance for
    a given name. Under the timing reproduced here (Task B's ``__aenter__``
    runs between Task A's ``record_failure`` and Task A's
    ``_maybe_emit_state_change``), Task B overwrote Task A's pre-state to
    ``opened``, and Task A's state-change emission compared
    ``pre.state == new.state == opened`` and silently dropped the event.

    The fix stores pre-snapshot in task-scoped storage (a ``ContextVar``
    stack), so each task observes its own pre-state regardless of how the
    Identity Map shares the breaker instance.
    """
    state_changes: list[BreakerStateChanged] = []

    a_passed_record_failure = asyncio.Event()
    b_finished_aenter = asyncio.Event()

    class CoordinatedStore(InMemoryStore):
        async def record_failure(
            self,
            name: str,
            *,
            threshold: int,
            ttl_seconds: float,
            counting: CountingPolicy | None = None,
        ) -> Snapshot:
            snap = await super().record_failure(
                name,
                threshold=threshold,
                ttl_seconds=ttl_seconds,
                counting=counting,
            )
            a_passed_record_failure.set()
            await b_finished_aenter.wait()
            return snap

    reg = AsyncBreakerRegistry(
        default_config=BreakerConfig(threshold=1, ttl=30.0),
        store=CoordinatedStore(),
    )
    reg.on(BreakerStateChanged, state_changes.append)
    breaker = await reg.get("svc")

    async def task_a() -> None:
        with pytest.raises(RuntimeError):
            async with breaker:
                msg = "threshold-crossing failure"
                raise RuntimeError(msg)

    async def task_b() -> None:
        await a_passed_record_failure.wait()
        with pytest.raises(BreakerOpenError):
            async with breaker:
                pass  # would-be no-op; rejected because state is now opened
        b_finished_aenter.set()

    await asyncio.gather(task_a(), task_b())
    await reg.aclose()

    closed_to_opened = [evt for evt in state_changes if evt.from_state == "closed" and evt.to_state == "opened"]
    assert len(closed_to_opened) == 1, (
        f"Expected exactly one closed→opened state-change event under "
        f"concurrent same-breaker access; got {len(closed_to_opened)}: "
        f"{state_changes}. The race in __aenter__ overwrote pre_state "
        f"and the event was silently dropped."
    )


# ---------------------------------------------------------------------------
# Sliding-window counting through the public surface (DRAFT-0002)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_registry_rate_based_breaker_trips_and_reports_failure_rate() -> None:
    """A ``rate_based`` breaker trips via the registry and ``BreakerFailed`` carries the rate."""
    reg = AsyncBreakerRegistry(
        default_config=BreakerConfig.rate_based(size=4, rate=0.5, min_calls=4),
        store=InMemoryStore(clock=FakeClock()),
    )
    seen_rates: list[float | None] = []
    reg.on(BreakerFailed, lambda e: seen_rates.append(e.failure_rate))
    breaker = await reg.get("upstream")

    class Boom(Exception):
        pass

    for _ in range(4):
        with pytest.raises(Boom):
            async with breaker:
                raise Boom("nope")

    status = await breaker.snapshot()
    assert status.state == "opened"
    # the first three failures (closed, windowed) each carry a rate >= 0.5
    assert any(r is not None and r >= 0.5 for r in seen_rates)
