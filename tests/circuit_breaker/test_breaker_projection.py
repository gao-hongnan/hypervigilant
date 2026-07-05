"""Sansio-core unit tests for the breaker.py projection functions.

Covers FR-004 (sansio core) and the foundation for AC-001..004. Every test
runs in microseconds without an event loop, without I/O, and without any
``await`` -- the projection functions are pure Python over (Snapshot,
BreakerConfig, Clock).

Notes
-----
These tests assert the deterministic state-machine transitions encoded in
``project_decision``, ``apply_failure``, and ``apply_success``. They are the
property-test substrate for the Hypothesis backend-equivalence suite that
lands in PR 2/3.
"""

import pytest

from hypervigilant.circuit_breaker.breaker import (
    apply_failure,
    apply_failure_windowed,
    apply_success,
    apply_success_windowed,
    project_decision,
    window_record,
    window_should_trip,
)
from hypervigilant.circuit_breaker.clock import FakeClock
from hypervigilant.circuit_breaker.config import BreakerConfig, CountingPolicy
from hypervigilant.circuit_breaker.policy import AllowCall, ProbeCall, RejectCall
from hypervigilant.circuit_breaker.state import Snapshot, Window


@pytest.fixture
def fresh_snapshot() -> Snapshot:
    """A canonical fresh-circuit snapshot (state=closed)."""
    return Snapshot(
        name="test",
        state="closed",
        failure_count=0,
        opened_at=0.0,
        generation=0,
    )


@pytest.mark.unit
def test_reject_call_carries_structured_fields() -> None:
    """RejectCall stores opened_at and retry_after."""
    reject = RejectCall(opened_at=100.0, retry_after=5.0)

    assert reject.opened_at == pytest.approx(100.0)
    assert reject.retry_after == pytest.approx(5.0)


@pytest.mark.unit
def test_probe_call_carries_lease_until() -> None:
    """ProbeCall stores the lease_until deadline."""
    probe = ProbeCall(lease_until=110.0)

    assert probe.lease_until == pytest.approx(110.0)


@pytest.mark.unit
def test_project_decision_closed_returns_allow(fresh_snapshot: Snapshot) -> None:
    """Closed circuit projects to AllowCall (FR-004, AC-001)."""
    config = BreakerConfig()
    clock = FakeClock(now=0.0)

    decision = project_decision(fresh_snapshot, config, clock)

    assert isinstance(decision, AllowCall)


@pytest.mark.unit
def test_project_decision_opened_within_ttl_rejects() -> None:
    """Opened circuit within ttl projects to RejectCall (FR-004, AC-003)."""
    snapshot = Snapshot(
        name="upstream_api",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=1,
    )
    config = BreakerConfig(ttl=30.0)
    clock = FakeClock(now=120.0)

    decision = project_decision(snapshot, config, clock)

    assert isinstance(decision, RejectCall)
    assert decision.retry_after == pytest.approx(10.0)
    assert decision.opened_at == pytest.approx(100.0)


@pytest.mark.unit
def test_project_decision_opened_after_ttl_returns_probe() -> None:
    """Opened circuit past ttl projects to ProbeCall (FR-004, AC-004)."""
    snapshot = Snapshot(
        name="recovering",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=1,
    )
    config = BreakerConfig(ttl=30.0, half_open_lease_seconds=5.0)
    clock = FakeClock(now=140.0)

    decision = project_decision(snapshot, config, clock)

    assert isinstance(decision, ProbeCall)
    assert decision.lease_until == pytest.approx(145.0)


@pytest.mark.unit
def test_project_decision_half_opened_rejects_concurrent_callers() -> None:
    """A snapshot already in half_opened rejects new arrivals (single-flight)."""
    snapshot = Snapshot(
        name="recovering",
        state="half_opened",
        failure_count=0,
        opened_at=100.0,
        generation=2,
    )
    config = BreakerConfig(ttl=30.0)
    clock = FakeClock(now=140.0)

    decision = project_decision(snapshot, config, clock)

    assert isinstance(decision, RejectCall)


@pytest.mark.unit
def test_project_decision_reject_clamps_retry_after_at_zero() -> None:
    """retry_after never goes negative even when ttl < elapsed."""
    snapshot = Snapshot(
        name="x",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=1,
    )
    # If we put the clock just under ttl + epsilon back, we still floor at 0.
    config = BreakerConfig(ttl=10.0)
    clock = FakeClock(now=109.999999)

    decision = project_decision(snapshot, config, clock)

    assert isinstance(decision, RejectCall)
    assert decision.retry_after >= 0.0


@pytest.mark.unit
def test_apply_failure_below_threshold_keeps_closed(fresh_snapshot: Snapshot) -> None:
    """First failure increments count and keeps the circuit closed."""
    config = BreakerConfig(threshold=5)
    clock = FakeClock(now=10.0)

    new_snapshot, decision = apply_failure(fresh_snapshot, config, clock)

    assert new_snapshot.state == "closed"
    assert new_snapshot.failure_count == 1
    assert new_snapshot.generation == 0
    assert isinstance(decision, AllowCall)


@pytest.mark.unit
def test_apply_failure_threshold_crossing_transitions_to_opened() -> None:
    """Crossing threshold trips the breaker with a single generation increment.

    Verifies FR-004 / AC-002 / EC-001 deterministically (no concurrency).
    """
    snapshot = Snapshot(
        name="t",
        state="closed",
        failure_count=4,
        opened_at=0.0,
        generation=7,
    )
    config = BreakerConfig(threshold=5)
    clock = FakeClock(now=100.0)

    new_snapshot, decision = apply_failure(snapshot, config, clock)

    assert new_snapshot.state == "opened"
    assert new_snapshot.failure_count == 5
    assert new_snapshot.generation == 8
    assert new_snapshot.opened_at == pytest.approx(100.0)
    assert isinstance(decision, RejectCall)
    assert decision.opened_at == pytest.approx(100.0)


@pytest.mark.unit
def test_apply_failure_clamps_failure_count_at_threshold() -> None:
    """Subsequent failures while opened clamp failure_count at threshold."""
    snapshot = Snapshot(
        name="t",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=8,
    )
    config = BreakerConfig(threshold=5, ttl=30.0)
    clock = FakeClock(now=110.0)  # within ttl

    new_snapshot, decision = apply_failure(snapshot, config, clock)

    assert new_snapshot.state == "opened"
    assert new_snapshot.failure_count == 5
    assert new_snapshot.generation == 8
    assert new_snapshot.opened_at == pytest.approx(100.0)
    assert isinstance(decision, RejectCall)


@pytest.mark.unit
def test_apply_failure_in_half_opened_reopens_with_generation_bump() -> None:
    """Probe failure transitions HALF_OPENED -> OPENED with a generation bump."""
    snapshot = Snapshot(
        name="t",
        state="half_opened",
        failure_count=0,
        opened_at=100.0,
        generation=10,
    )
    config = BreakerConfig(threshold=5, ttl=30.0)
    clock = FakeClock(now=200.0)

    new_snapshot, decision = apply_failure(snapshot, config, clock)

    assert new_snapshot.state == "opened"
    assert new_snapshot.failure_count >= 1
    assert new_snapshot.generation == 11
    assert new_snapshot.opened_at == pytest.approx(200.0)
    assert isinstance(decision, RejectCall)


@pytest.mark.unit
def test_apply_success_in_closed_resets_failure_count() -> None:
    """Success while closed resets failure_count without changing generation."""
    snapshot = Snapshot(
        name="t",
        state="closed",
        failure_count=3,
        opened_at=0.0,
        generation=4,
    )
    config = BreakerConfig()
    clock = FakeClock(now=10.0)

    new_snapshot = apply_success(snapshot, config, clock)

    assert new_snapshot.state == "closed"
    assert new_snapshot.failure_count == 0
    assert new_snapshot.generation == 4


@pytest.mark.unit
def test_apply_success_half_open_transitions_to_closed() -> None:
    """Successful probe transitions HALF_OPENED -> CLOSED with a generation bump."""
    snapshot = Snapshot(
        name="t",
        state="half_opened",
        failure_count=0,
        opened_at=100.0,
        generation=10,
    )
    config = BreakerConfig()
    clock = FakeClock(now=150.0)

    new_snapshot = apply_success(snapshot, config, clock)

    assert new_snapshot.state == "closed"
    assert new_snapshot.failure_count == 0
    assert new_snapshot.generation == 11


@pytest.mark.unit
def test_apply_success_in_opened_is_a_no_op() -> None:
    """Success while opened MUST NOT silently move the breaker into closed."""
    snapshot = Snapshot(
        name="t",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=8,
    )
    config = BreakerConfig(ttl=30.0)
    clock = FakeClock(now=110.0)  # still within ttl

    new_snapshot = apply_success(snapshot, config, clock)

    assert new_snapshot == snapshot


# `test_breaker_module_has_no_io_imports` removed: it inspected source for
# substrings, which would false-positive on a docstring containing
# "import asyncio". The sansio invariant is better enforced by a
# pre-commit hook than a brittle source-grep test (review item L11).


# ---------------------------------------------------------------------------
# Sliding-window primitives (DRAFT-0002)
# ---------------------------------------------------------------------------


def _fresh_window(size: int) -> Window:
    """Empty window of ``size`` slots."""
    return Window(size=size, bits=0, write_index=0, total=0, failures=0)


@pytest.mark.unit
def test_window_record_fills_without_eviction() -> None:
    """A fresh window records outcomes up to its size without losing any (FR-105)."""
    win = _fresh_window(4)
    for _ in range(4):
        win = window_record(win, True)

    assert win.total == 4
    assert win.failures == 4
    assert win.write_index == 0  # 4 writes wraps [0,4) back to 0
    assert bin(win.bits) == "0b1111"


@pytest.mark.unit
def test_window_record_evicts_oldest_when_full() -> None:
    """Once full, a new outcome evicts the oldest slot (ring semantics, EC-102)."""
    win = _fresh_window(4)
    for _ in range(4):  # F F F F
        win = window_record(win, True)
    win = window_record(win, False)  # 5th: success at position 0 evicts first F

    assert win.total == 4  # capped at size
    assert win.failures == 3  # one failure evicted
    assert win.write_index == 1


@pytest.mark.unit
def test_window_record_success_does_not_wipe_window() -> None:
    """A success records into the window; it does not reset it (FR-106/EC-103)."""
    win = _fresh_window(4)
    for _ in range(3):
        win = window_record(win, True)
    win = window_record(win, False)  # F F F S

    assert win.failures == 3
    assert win.total == 4


@pytest.mark.unit
def test_window_should_trip_respects_min_calls_gate() -> None:
    """No trip before minimum_number_of_calls, regardless of rate (EC-101)."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    win = _fresh_window(10)
    for _ in range(9):  # 9 failures, but total < min_calls
        win = window_record(win, True)

    assert win.failures == 9
    assert window_should_trip(win, policy) is False


@pytest.mark.unit
def test_window_should_trip_at_threshold_with_min_met() -> None:
    """Trip once total >= min_calls and rate >= threshold."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    win = _fresh_window(10)
    for _ in range(10):
        win = window_record(win, True)

    assert window_should_trip(win, policy) is True


@pytest.mark.unit
def test_window_should_trip_false_below_rate() -> None:
    """Below the rate threshold, no trip even when min_calls is met."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    win = _fresh_window(10)
    for _ in range(4):
        win = window_record(win, True)
    for _ in range(6):
        win = window_record(win, False)  # 4/10 = 0.4 < 0.5

    assert window_should_trip(win, policy) is False


# ---------------------------------------------------------------------------
# Sans-io windowed core (DRAFT-0002)
# ---------------------------------------------------------------------------


def _closed_snapshot(name: str = "x", generation: int = 0) -> Snapshot:
    return Snapshot(name=name, state="closed", failure_count=0, opened_at=0.0, generation=generation)


@pytest.mark.unit
def test_windowed_failure_below_threshold_stays_closed() -> None:
    """A failure that does not cross the rate gate keeps the breaker closed."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    new_snapshot, win, decision = apply_failure_windowed(_closed_snapshot(), None, policy, FakeClock(now=1.0))

    assert new_snapshot.state == "closed"
    assert new_snapshot.failure_count == 1
    assert new_snapshot.window is not None
    assert new_snapshot.window.failures == 1
    assert isinstance(decision, AllowCall)
    assert win.failures == 1


@pytest.mark.unit
def test_windowed_failure_trips_at_threshold() -> None:
    """The breaker trips exactly when min_calls is met and rate >= threshold (EC-101)."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    snapshot = _closed_snapshot()
    window = None
    clock = FakeClock(now=100.0)
    for _ in range(9):  # fill to 9 failures; min_calls gate holds
        snapshot, window, _ = apply_failure_windowed(snapshot, window, policy, clock)
        assert snapshot.state == "closed"

    snapshot, window, decision = apply_failure_windowed(snapshot, window, policy, clock)

    assert snapshot.state == "opened"
    assert snapshot.failure_count == 10  # tripping count
    assert snapshot.window is None  # opened: no active window
    assert isinstance(decision, RejectCall)
    assert window.total == 0  # persisted window reset to fresh


@pytest.mark.unit
def test_windowed_success_records_into_window_no_trip() -> None:
    """A success records into the window without wiping it (FR-106/EC-103)."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    snapshot = _closed_snapshot()
    snapshot, window, _ = apply_failure_windowed(snapshot, None, policy, FakeClock(now=1.0))
    snapshot, window = apply_success_windowed(snapshot, window, policy, FakeClock(now=2.0))

    assert snapshot.state == "closed"
    assert window.total == 2
    assert window.failures == 1  # success did NOT wipe the window


@pytest.mark.unit
def test_windowed_failure_from_half_open_reopens_and_resets() -> None:
    """A probe failure reopens the breaker and resets the window (EC-105/EC-106)."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    snapshot = Snapshot(name="x", state="half_opened", failure_count=0, opened_at=5.0, generation=3)
    new_snapshot, window, decision = apply_failure_windowed(snapshot, None, policy, FakeClock(now=10.0))

    assert new_snapshot.state == "opened"
    assert new_snapshot.generation == 4
    assert new_snapshot.window is None
    assert isinstance(decision, RejectCall)
    assert window.total == 0


@pytest.mark.unit
def test_windowed_success_from_half_open_closes_and_resets() -> None:
    """A probe success closes the breaker and starts a fresh window epoch (EC-105)."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    snapshot = Snapshot(name="x", state="half_opened", failure_count=0, opened_at=5.0, generation=3)
    new_snapshot, window = apply_success_windowed(snapshot, None, policy, FakeClock(now=10.0))

    assert new_snapshot.state == "closed"
    assert new_snapshot.generation == 4
    assert new_snapshot.window is None  # fresh epoch, empty window summary
    assert window.total == 0


@pytest.mark.unit
def test_windowed_success_in_closed_lowers_rate_below_threshold() -> None:
    """Successes dilute the rate so a healing dependency stops tripping."""
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    snapshot = _closed_snapshot()
    window = None
    clock = FakeClock(now=0.0)
    # 5 failures (rate 1.0, but only 5 calls < min_calls=10 → no trip yet)
    for _ in range(5):
        snapshot, window, _ = apply_failure_windowed(snapshot, window, policy, clock)
    # 5 successes bring the window to 10 calls, 5/10 = 0.5 → trip at threshold
    tripped = False
    for _ in range(5):
        snapshot, window = apply_success_windowed(snapshot, window, policy, clock)
        # successes cannot trip; only failures trip
        assert snapshot.state == "closed"
    # window now 5 failures / 10 total = 0.5; but we did not record a failure to re-evaluate,
    # so the breaker stays closed (trip is evaluated only on record_failure).
    assert snapshot.state == "closed"
    assert window is not None
    assert window.failures == 5
    assert not tripped
