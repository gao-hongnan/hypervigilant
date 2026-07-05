"""AC-204: the sliding-window policy catches sustained partial failure that the
consecutive policy cannot.

Drives both counting strategies with the SAME seeded outcome stream at a 30%
failure rate and asserts the sliding breaker trips while the consecutive breaker
does not. Operates directly on the sans-io core (no I/O, no event loop), so it
runs deterministically in microseconds. This is the measurable proof that
DRAFT-0002 closes the slow-burn blind spot of DRAFT-0001's consecutive counter.
"""

import random

import pytest

from hypervigilant.circuit_breaker.breaker import (
    apply_failure,
    apply_failure_windowed,
    apply_success,
    apply_success_windowed,
)
from hypervigilant.circuit_breaker.clock import FakeClock
from hypervigilant.circuit_breaker.config import BreakerConfig, CountingPolicy
from hypervigilant.circuit_breaker.state import Snapshot

_FAILURE_RATE = 0.3
_CALLS = 1000
_SEED = 1234


def _drive_sliding(p: float, n: int, seed: int) -> int:
    """Return closed→opened trip count for a sliding breaker over n calls."""
    policy = CountingPolicy("sliding_window", 100, 0.25, 20)
    snap = Snapshot(name="s", state="closed", failure_count=0, opened_at=0.0, generation=0)
    window = None
    now = 0.0
    rng = random.Random(seed)
    trips = 0
    for _ in range(n):
        now += 1.0
        clock = FakeClock(now=now)
        if rng.random() < p:
            snap, window, _ = apply_failure_windowed(snap, window, policy, clock)
        else:
            snap, window = apply_success_windowed(snap, window, policy, clock)
        if snap.state == "opened":
            trips += 1
            # recover into a fresh closed epoch to keep counting
            snap = Snapshot(
                name="s",
                state="half_opened",
                failure_count=0,
                opened_at=now,
                generation=snap.generation,
            )
            snap, window = apply_success_windowed(snap, window, policy, clock)
    return trips


def _drive_consecutive(p: float, n: int, seed: int) -> int:
    """Return closed→opened trip count for a consecutive breaker over n calls."""
    cfg = BreakerConfig(threshold=10)
    snap = Snapshot(name="c", state="closed", failure_count=0, opened_at=0.0, generation=0)
    now = 0.0
    rng = random.Random(seed)
    trips = 0
    for _ in range(n):
        now += 1.0
        clock = FakeClock(now=now)
        if rng.random() < p:
            snap, _ = apply_failure(snap, cfg, clock)
        else:
            snap = apply_success(snap, cfg, clock)
        if snap.state == "opened":
            trips += 1
            snap = Snapshot(
                name="c",
                state="half_opened",
                failure_count=0,
                opened_at=now,
                generation=snap.generation,
            )
            snap = apply_success(snap, cfg, clock)
    return trips


@pytest.mark.unit
def test_ac204_sliding_trips_consecutive_does_not() -> None:
    """At a sustained 30% failure rate, sliding trips; consecutive does not (AC-204)."""
    sliding_trips = _drive_sliding(_FAILURE_RATE, _CALLS, _SEED)
    consecutive_trips = _drive_consecutive(_FAILURE_RATE, _CALLS, _SEED)

    assert sliding_trips >= 1, "sliding breaker MUST trip under sustained 30% failures"
    assert consecutive_trips == 0, "consecutive breaker MUST NOT trip under sustained 30% failures"
