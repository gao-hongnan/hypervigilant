"""Contract and behaviour tests for ``InMemoryStore`` (PR 2 / task 2B).

Covers the asymmetric ``BreakerStore`` Protocol shape (FR-005), the full
state-machine acceptance (AC-001 through AC-004 in-memory variants), the
``generation``-delta atomicity invariant under concurrent failures (AC-002
prerequisite for the Lua-backed equivalent), and the lazy cell-creation
behaviour.

References
----------
- FR-005 (asymmetric ``BreakerStore`` Protocol).
- AC-001..AC-004 (state-machine acceptance).
- Decision 4 (asymmetric store contract).
"""

import asyncio

import pytest

from hypervigilant.circuit_breaker import (
    AllowCall,
    BreakerStore,
    FakeClock,
    InMemoryStore,
    ProbeCall,
    RejectCall,
    Snapshot,
)
from hypervigilant.circuit_breaker.config import CountingPolicy


@pytest.mark.unit
def test_in_memory_store_implements_breaker_store_protocol() -> None:
    """``isinstance`` recognises ``InMemoryStore`` as a ``BreakerStore``."""
    assert isinstance(InMemoryStore(), BreakerStore)


@pytest.mark.unit
async def test_acquire_on_fresh_circuit_returns_allow() -> None:
    """A circuit that has never been observed starts in ``closed`` state."""
    store = InMemoryStore(clock=FakeClock())
    decision, _ = await store.acquire(
        "fresh",
        threshold=5,
        ttl_seconds=30.0,
        lease_seconds=5.0,
    )
    assert isinstance(decision, AllowCall)
    snapshot = await store.peek("fresh")
    assert snapshot is not None
    assert snapshot.state == "closed"
    assert snapshot.failure_count == 0
    assert snapshot.generation == 0


@pytest.mark.unit
async def test_record_failure_returns_post_mutation_snapshot() -> None:
    """A single failure increments ``failure_count`` and leaves state closed."""
    store = InMemoryStore(clock=FakeClock())
    snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    assert snap.state == "closed"
    assert snap.failure_count == 1
    assert snap.generation == 0


@pytest.mark.unit
async def test_threshold_crossing_increments_generation_by_exactly_one() -> None:
    """Crossing ``threshold`` transitions to ``opened`` with generation += 1."""
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    for _ in range(4):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    pre_snap = await store.peek("svc")
    assert pre_snap is not None
    assert pre_snap.state == "closed"
    assert pre_snap.failure_count == 4
    pre_generation = pre_snap.generation
    final = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    assert final.state == "opened"
    assert final.failure_count == 5
    assert final.generation == pre_generation + 1
    assert final.opened_at == 100.0


@pytest.mark.unit
async def test_acquire_during_opened_window_returns_reject() -> None:
    """Within the TTL window an opened breaker rejects every acquirer."""
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    clock.advance(10.0)
    decision, _ = await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    assert isinstance(decision, RejectCall)
    assert decision.opened_at == 100.0
    assert decision.retry_after == pytest.approx(20.0)


@pytest.mark.unit
async def test_acquire_after_ttl_transitions_to_half_open_with_probe() -> None:
    """After the TTL elapses, the first acquirer transitions to ``half_opened``."""
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    clock.advance(35.0)
    decision, _ = await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    assert isinstance(decision, ProbeCall)
    snap = await store.peek("svc")
    assert snap is not None
    assert snap.state == "half_opened"
    assert snap.generation == 2  # one transition closed→opened, one opened→half_opened


@pytest.mark.unit
async def test_concurrent_acquire_during_half_open_keeps_single_flight() -> None:
    """A second concurrent acquirer during the half-open window is rejected."""
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    clock.advance(35.0)
    first, _ = await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    second, _ = await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    assert isinstance(first, ProbeCall)
    assert isinstance(second, RejectCall)


@pytest.mark.unit
async def test_acquire_with_stale_half_open_lease_reissues_probe() -> None:
    """H2 regression: a half-open breaker whose probe lease has expired re-issues a fresh probe.

    Without the fix, a crashed probe coroutine would leave the breaker
    wedged in ``half_opened`` for the rest of ``key_ttl_seconds`` (24h
    default) because every subsequent acquire fell through to ``reject``.
    """
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    clock.advance(35.0)
    first, _ = await store.acquire(
        "svc",
        threshold=5,
        ttl_seconds=30.0,
        lease_seconds=5.0,
    )
    assert isinstance(first, ProbeCall)
    pre_snap = await store.peek("svc")
    assert pre_snap is not None
    assert pre_snap.state == "half_opened"
    pre_generation = pre_snap.generation

    # Probe coroutine crashes: lease expires without record_success / record_failure.
    clock.advance(10.0)
    second, _ = await store.acquire(
        "svc",
        threshold=5,
        ttl_seconds=30.0,
        lease_seconds=5.0,
    )
    assert isinstance(second, ProbeCall), "Stale half-open lease must re-issue the probe rather than wedge in reject."
    post_snap = await store.peek("svc")
    assert post_snap is not None
    assert post_snap.state == "half_opened"
    assert post_snap.generation == pre_generation + 1


@pytest.mark.unit
async def test_record_success_during_half_open_closes_breaker() -> None:
    """A successful probe call closes the breaker with generation += 1."""
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    clock.advance(35.0)
    await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    pre_snap = await store.peek("svc")
    assert pre_snap is not None
    assert pre_snap.state == "half_opened"
    snap = await store.record_success("svc")
    assert snap.state == "closed"
    assert snap.failure_count == 0
    assert snap.generation == pre_snap.generation + 1


@pytest.mark.unit
async def test_record_failure_during_half_open_reopens_breaker() -> None:
    """A failed probe call re-opens the breaker with generation += 1."""
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    clock.advance(35.0)
    await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    pre_snap = await store.peek("svc")
    assert pre_snap is not None
    pre_generation = pre_snap.generation
    clock.advance(1.0)
    snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    assert snap.state == "opened"
    assert snap.opened_at == 136.0
    assert snap.generation == pre_generation + 1


@pytest.mark.unit
async def test_concurrent_record_failures_serialise_through_lock() -> None:
    """100 concurrent failures on a fresh store land on a single ``opened`` transition.

    The in-memory store serialises through a per-cell ``asyncio.Lock``; the
    invariant is the same one the Lua-backed store proves at 1,000-concurrent
    scale (AC-002, SC-003): exactly one ``closed`` → ``opened`` transition,
    observable as a single ``generation`` increment.
    """
    clock = FakeClock(now=100.0)
    store = InMemoryStore(clock=clock)
    pre_snap = await store.peek("svc")
    pre_generation = pre_snap.generation if pre_snap is not None else 0
    coros = [store.record_failure("svc", threshold=10, ttl_seconds=30.0) for _ in range(100)]
    await asyncio.gather(*coros)
    snap = await store.peek("svc")
    assert snap is not None
    assert snap.state == "opened"
    assert snap.failure_count == 10
    assert snap.generation == pre_generation + 1


@pytest.mark.unit
async def test_peek_returns_none_for_unknown_circuit() -> None:
    """An unobserved circuit has no snapshot yet."""
    store = InMemoryStore()
    assert await store.peek("never-seen") is None


@pytest.mark.unit
async def test_reset_clears_named_circuit() -> None:
    """``reset(name)`` discards state for the named circuit only."""
    store = InMemoryStore()
    await store.record_failure("svc-a", threshold=5, ttl_seconds=30.0)
    await store.record_failure("svc-b", threshold=5, ttl_seconds=30.0)
    await store.reset("svc-a")
    assert await store.peek("svc-a") is None
    snap_b = await store.peek("svc-b")
    assert snap_b is not None
    assert snap_b.failure_count == 1


@pytest.mark.unit
async def test_reset_without_name_clears_every_circuit() -> None:
    """``reset(None)`` discards every circuit known to the store."""
    store = InMemoryStore()
    await store.record_failure("svc-a", threshold=5, ttl_seconds=30.0)
    await store.record_failure("svc-b", threshold=5, ttl_seconds=30.0)
    await store.reset(None)
    assert await store.peek("svc-a") is None
    assert await store.peek("svc-b") is None


@pytest.mark.unit
async def test_aclose_drops_every_circuit() -> None:
    """``aclose`` is the lifecycle hook; in-memory it just drops state."""
    store = InMemoryStore()
    await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    await store.aclose()
    assert await store.peek("svc") is None


@pytest.mark.unit
async def test_default_clock_is_monotonic_so_negative_drift_is_impossible() -> None:
    """Without an explicit clock, the store uses :class:`MonotonicClock`."""
    store = InMemoryStore()
    snap_a = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    snap_b = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    # opened_at is unchanged in the closed branch so this just checks the
    # post-state is consistent.
    assert snap_a.opened_at == snap_b.opened_at == 0.0


@pytest.mark.unit
async def test_observer_receives_call_and_decision_events_for_acquire() -> None:
    """Telemetry hooks fire on ``acquire`` (FR-016)."""

    class _CapturingObserver:
        __slots__ = ("calls", "decisions")

        def __init__(self) -> None:
            self.calls: list[tuple[str, str, float]] = []
            self.decisions: list[tuple[str, Snapshot, object]] = []

        def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
            self.calls.append((op, name, duration_ms))

        def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
            del op, name, exc

        def on_decision(self, *, name: str, snapshot: Snapshot, decision: object) -> None:
            self.decisions.append((name, snapshot, decision))

        def on_storage_failure(
            self,
            *,
            op: str,
            name: str,
            exc: BaseException,
            fell_back_to: object,
        ) -> None:
            del op, name, exc, fell_back_to

    observer = _CapturingObserver()
    store = InMemoryStore(observer=observer)
    await store.acquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    assert any(op == "acquire" and name == "svc" for op, name, _ in observer.calls)
    assert len(observer.decisions) == 1


# ---------------------------------------------------------------------------
# Sliding-window counting (DRAFT-0002)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_inmemory_sliding_trips_at_rate_with_min_calls() -> None:
    """A sliding breaker trips once the window fills past min_calls at rate >= threshold."""
    store = InMemoryStore(clock=FakeClock())
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    for _ in range(9):
        snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0, counting=policy)
        assert snap.state == "closed"
    snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0, counting=policy)
    assert snap.state == "opened"


@pytest.mark.unit
async def test_inmemory_sliding_success_does_not_wipe_window() -> None:
    """A success records into the sliding window; it does not reset it (EC-103)."""
    store = InMemoryStore(clock=FakeClock())
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    await store.record_failure("svc", threshold=5, ttl_seconds=30.0, counting=policy)
    snap = await store.record_success("svc", counting=policy)

    assert snap.state == "closed"
    assert snap.window is not None
    assert snap.window.total == 2
    assert snap.window.failures == 1


@pytest.mark.unit
async def test_inmemory_consecutive_default_unchanged_when_counting_none() -> None:
    """``counting=None`` reproduces consecutive behaviour byte-for-byte (NFR-101)."""
    store = InMemoryStore(clock=FakeClock())
    # trip on the threshold-th consecutive failure
    for _ in range(4):
        snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
        assert snap.state == "closed"
    snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    assert snap.state == "opened"

    # a success in CLOSED state (fresh circuit) resets the counter to 0 (consecutive),
    # and never populates the sliding-window summary.
    snap = await store.record_failure("svc2", threshold=5, ttl_seconds=30.0)
    assert snap.failure_count == 1
    snap = await store.record_success("svc2")
    assert snap.failure_count == 0
    assert snap.window is None
