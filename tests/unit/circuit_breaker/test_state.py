"""Unit tests for circuit-breaker state value objects and FakeClock primitives.

Covers FR-008 (Clock Protocol contract) and FR-013 (Snapshot/BreakerStatus
shape). The tests inject ``FakeClock`` to assert deterministic behaviour and
verify the immutability invariants required by the sansio core.

Notes
-----
These tests live alongside the integration suite under
``tests/resilience/circuit_breaker/`` and inherit the directory-level
``conftest.py`` autouse Redis fixture. They themselves do not exercise Redis
state — only pure value objects and the in-process Clock implementations.
"""

import dataclasses
import time

import pytest

from hypervigilant.circuit_breaker.clock import FakeClock, MonotonicClock, SystemClock
from hypervigilant.circuit_breaker.state import (
    BreakerStatus,
    Snapshot,
    Window,
    WindowSummary,
)


@pytest.mark.unit
def test_snapshot_default_construction() -> None:
    """Snapshot accepts the five canonical fields and stores them verbatim."""
    snapshot = Snapshot(
        name="upstream",
        state="closed",
        failure_count=0,
        opened_at=0.0,
        generation=0,
    )

    assert snapshot.name == "upstream"
    assert snapshot.state == "closed"
    assert snapshot.failure_count == 0
    assert snapshot.opened_at == 0.0
    assert snapshot.generation == 0


@pytest.mark.unit
def test_snapshot_is_frozen() -> None:
    """Snapshot is a frozen dataclass -- assignment raises FrozenInstanceError."""
    snapshot = Snapshot(
        name="x",
        state="closed",
        failure_count=0,
        opened_at=0.0,
        generation=0,
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        # ``setattr`` exercises the dataclass __setattr__ guard the same way
        # an attribute assignment does, but keeps the line statically-typed.
        setattr(snapshot, "failure_count", 1)  # noqa: B010


@pytest.mark.unit
def test_snapshot_uses_slots() -> None:
    """Snapshot defines ``__slots__`` listing only the declared fields."""
    snapshot = Snapshot(
        name="x",
        state="closed",
        failure_count=0,
        opened_at=0.0,
        generation=0,
    )

    assert hasattr(Snapshot, "__slots__")
    assert tuple(Snapshot.__slots__) == (
        "name",
        "state",
        "failure_count",
        "opened_at",
        "generation",
        "is_authoritative",
        "window",
    )
    assert not hasattr(snapshot, "__dict__")


@pytest.mark.unit
def test_snapshot_value_equality() -> None:
    """Snapshots with identical fields compare equal and hash equal."""
    a = Snapshot(name="x", state="closed", failure_count=0, opened_at=0.0, generation=0)
    b = Snapshot(name="x", state="closed", failure_count=0, opened_at=0.0, generation=0)

    assert a == b
    assert hash(a) == hash(b)


@pytest.mark.unit
def test_snapshot_value_inequality() -> None:
    """Snapshots disagreeing on any single field compare not-equal."""
    a = Snapshot(name="x", state="closed", failure_count=0, opened_at=0.0, generation=0)
    b = Snapshot(name="x", state="opened", failure_count=0, opened_at=0.0, generation=1)

    assert a != b


@pytest.mark.unit
def test_breaker_status_includes_retry_after() -> None:
    """BreakerStatus exposes retry_after on top of the Snapshot fields."""
    status = BreakerStatus(
        name="x",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=2,
        retry_after=25.0,
    )

    assert status.retry_after == pytest.approx(25.0)
    assert status.opened_at == pytest.approx(100.0)
    assert status.state == "opened"


@pytest.mark.unit
def test_breaker_status_is_frozen() -> None:
    """BreakerStatus is a frozen dataclass -- assignment raises FrozenInstanceError."""
    status = BreakerStatus(
        name="x",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=2,
        retry_after=25.0,
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(status, "retry_after", 0.0)  # noqa: B010


@pytest.mark.unit
def test_breaker_status_uses_slots() -> None:
    """BreakerStatus defines ``__slots__`` listing only the declared fields."""
    status = BreakerStatus(
        name="x",
        state="opened",
        failure_count=5,
        opened_at=100.0,
        generation=2,
        retry_after=25.0,
    )

    assert hasattr(BreakerStatus, "__slots__")
    assert tuple(BreakerStatus.__slots__) == (
        "name",
        "state",
        "failure_count",
        "opened_at",
        "generation",
        "retry_after",
        "failure_rate",
    )
    assert not hasattr(status, "__dict__")


@pytest.mark.unit
def test_fake_clock_default_now() -> None:
    """FakeClock starts at 0.0 by default."""
    clock = FakeClock()

    assert clock.now() == pytest.approx(0.0)


@pytest.mark.unit
def test_fake_clock_initial_now_argument() -> None:
    """FakeClock honours the constructor ``now`` argument."""
    clock = FakeClock(now=42.5)

    assert clock.now() == pytest.approx(42.5)


@pytest.mark.unit
def test_fake_clock_advance() -> None:
    """advance() bumps the in-memory clock by the given delta (FR-008)."""
    clock = FakeClock(now=0.0)

    clock.advance(35.0)

    assert clock.now() == pytest.approx(35.0)


@pytest.mark.unit
def test_fake_clock_advance_is_additive() -> None:
    """Repeated advance() calls accumulate."""
    clock = FakeClock(now=10.0)

    clock.advance(2.5)
    clock.advance(7.5)

    assert clock.now() == pytest.approx(20.0)


@pytest.mark.unit
def test_fake_clock_rejects_negative_advance() -> None:
    """FakeClock.advance refuses negative deltas (monotonicity invariant)."""
    clock = FakeClock(now=10.0)

    with pytest.raises(ValueError, match="non-negative"):
        clock.advance(-1.0)


@pytest.mark.unit
def test_monotonic_clock_does_not_go_backwards() -> None:
    """MonotonicClock is non-decreasing across two reads (FR-008, EC-004)."""
    clock = MonotonicClock()

    t1 = clock.now()
    time.sleep(0.005)
    t2 = clock.now()

    assert t2 >= t1


@pytest.mark.unit
def test_system_clock_returns_float() -> None:
    """SystemClock returns the current wall-clock time as a float (FR-008)."""
    clock = SystemClock()

    value = clock.now()

    assert isinstance(value, float)
    assert value > 0.0


# ---------------------------------------------------------------------------
# Sliding-window value objects (DRAFT-0002)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_window_is_frozen_slotted_dataclass() -> None:
    """Window is a frozen slotted value object (FR-104)."""
    win = Window(size=4, bits=0, write_index=0, total=0, failures=0)

    assert dataclasses.is_dataclass(win)
    assert hasattr(Window, "__slots__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(win, "failures", 99)  # noqa: B010


@pytest.mark.unit
def test_window_summary_carries_rate() -> None:
    """WindowSummary holds the derived rate alongside the raw counts."""
    ws = WindowSummary(size=10, failures=3, total=10, rate=0.3)

    assert ws.failures == 3
    assert ws.total == 10
    assert ws.rate == pytest.approx(0.3)


@pytest.mark.unit
def test_snapshot_window_defaults_none() -> None:
    """Snapshot.window defaults to None (consecutive mode) (FR-107)."""
    snap = Snapshot(name="x", state="closed", failure_count=0, opened_at=0.0, generation=0)
    assert snap.window is None


@pytest.mark.unit
def test_snapshot_carries_window_summary() -> None:
    """Snapshot carries an optional WindowSummary in sliding mode (FR-107)."""
    ws = WindowSummary(size=10, failures=3, total=10, rate=0.3)
    snap = Snapshot(name="x", state="closed", failure_count=3, opened_at=0.0, generation=0, window=ws)
    assert snap.window == ws


@pytest.mark.unit
def test_breaker_status_failure_rate_defaults_none() -> None:
    """BreakerStatus.failure_rate defaults to None (FR-107)."""
    status = BreakerStatus(name="x", state="closed", failure_count=0, opened_at=0.0, generation=0, retry_after=0.0)
    assert status.failure_rate is None
