"""Sansio core: pure-Python state-machine projection over a Snapshot.

This module exposes three deterministic, side-effect-free functions that
together describe the entire circuit-breaker state machine:

* :func:`project_decision` -- given a Snapshot, BreakerConfig, and Clock,
  return the :class:`Decision` the runtime layer SHOULD apply.
* :func:`apply_failure` -- transition the Snapshot in response to a failure
  observed by the protected coroutine; return the new Snapshot and the
  Decision callers should observe.
* :func:`apply_success` -- transition the Snapshot in response to a success;
  return the new Snapshot.

No function in this module performs I/O. None of them are coroutines. Every
transition is deterministic given (Snapshot, Config, Clock); injecting a
:class:`hypervigilant.circuit_breaker.clock.FakeClock` makes every
behaviour testable in microseconds without an event loop.

References
----------
- FR-004 (sansio core).
- AC-001..004 (sansio drives the user-visible acceptance).
- Decision 1 (sansio split).

Examples
--------
>>> from hypervigilant.circuit_breaker.clock import FakeClock
>>> from hypervigilant.circuit_breaker.config import BreakerConfig
>>> from hypervigilant.circuit_breaker.state import Snapshot
>>> snap = Snapshot(name='x', state='closed', failure_count=0, opened_at=0.0, generation=0)
>>> decision = project_decision(snap, BreakerConfig(), FakeClock(now=0.0))
>>> type(decision).__name__
'AllowCall'
"""

from typing import assert_never

from hypervigilant.circuit_breaker.clock import Clock
from hypervigilant.circuit_breaker.config import BreakerConfig, CountingPolicy
from hypervigilant.circuit_breaker.policy import (
    AllowCall,
    Decision,
    ProbeCall,
    RejectCall,
)
from hypervigilant.circuit_breaker.state import Snapshot, Window, WindowSummary

__all__ = [
    "apply_failure",
    "apply_failure_windowed",
    "apply_success",
    "apply_success_windowed",
    "project_decision",
    "window_record",
    "window_should_trip",
]


def project_decision(
    snapshot: Snapshot,
    config: BreakerConfig,
    clock: Clock,
) -> Decision:
    """Project a Decision from the current Snapshot.

    Parameters
    ----------
    snapshot
        Current circuit state.
    config
        Tuning knobs (``ttl``, ``half_open_lease_seconds`` consumed here).
    clock
        Time source. Only :meth:`Clock.now` is invoked.

    Returns
    -------
    Decision
        :class:`AllowCall` when ``state == "closed"``;
        :class:`RejectCall` when ``state == "opened"`` and within ttl, or
        when ``state == "half_opened"`` (single-flight reject for newcomers);
        :class:`ProbeCall` when ``state == "opened"`` and ttl has elapsed.

    Examples
    --------
    >>> from hypervigilant.circuit_breaker.clock import FakeClock
    >>> from hypervigilant.circuit_breaker.config import BreakerConfig
    >>> from hypervigilant.circuit_breaker.state import Snapshot
    >>> snap = Snapshot(name='x', state='closed', failure_count=0, opened_at=0.0, generation=0)
    >>> isinstance(project_decision(snap, BreakerConfig(), FakeClock()), AllowCall)
    True
    """
    match snapshot.state:
        case "closed":
            return AllowCall()
        case "opened":
            now = clock.now()
            elapsed = now - snapshot.opened_at
            if elapsed >= config.ttl:
                return ProbeCall(lease_until=now + config.half_open_lease_seconds)
            retry_after = max(config.ttl - elapsed, 0.0)
            return RejectCall(opened_at=snapshot.opened_at, retry_after=retry_after)
        case "half_opened":
            now = clock.now()
            elapsed = now - snapshot.opened_at
            retry_after = max(config.ttl - elapsed, 0.0)
            return RejectCall(opened_at=snapshot.opened_at, retry_after=retry_after)
        case _:
            assert_never(snapshot.state)


def _fresh_window(size: int) -> Window:
    """Return an empty window of ``size`` slots."""
    return Window(size=size, bits=0, write_index=0, total=0, failures=0)


def _window_summary(win: Window) -> WindowSummary:
    """Project a :class:`Window` to its :class:`WindowSummary`."""
    rate = win.failures / win.total if win.total else 0.0
    return WindowSummary(size=win.size, failures=win.failures, total=win.total, rate=rate)


def window_record(win: Window, outcome: bool) -> Window:
    """Return a new :class:`Window` with ``outcome`` recorded at the write pointer.

    Evicts the oldest slot when the window is full, advances ``write_index``
    modulo ``size``, and updates ``total`` (capped) and ``failures``. Total and
    side-effect-free (FR-105).

    Examples
    --------
    >>> w = Window(size=4, bits=0, write_index=0, total=0, failures=0)
    >>> w = window_record(w, True)
    >>> (w.failures, w.total, w.write_index)
    (1, 1, 1)
    """
    mask = 1 << win.write_index
    old_bit = 1 if (win.bits & mask) else 0
    new_bit = 1 if outcome else 0
    return Window(
        size=win.size,
        bits=(win.bits & ~mask) | (mask if outcome else 0),
        write_index=(win.write_index + 1) % win.size,
        total=min(win.total + 1, win.size),
        failures=win.failures - old_bit + new_bit,
    )


def window_should_trip(win: Window, policy: CountingPolicy) -> bool:
    """Return True when the window has met ``minimum_number_of_calls`` and the
    failure rate is at/above ``failure_rate_threshold`` (FR-106)."""
    if win.total < policy.minimum_number_of_calls or win.total == 0:
        return False
    return (win.failures / win.total) >= policy.failure_rate_threshold


def apply_failure(
    snapshot: Snapshot,
    config: BreakerConfig,
    clock: Clock,
) -> tuple[Snapshot, Decision]:
    """Transition the snapshot for an observed failure.

    Three transition cases:

    * ``state == "closed"`` -- increment ``failure_count`` and, on threshold
      crossing, transition to ``opened`` with a single ``generation``
      increment. Returns ``(new_snapshot, AllowCall())`` when the breaker
      stays closed; returns ``(new_snapshot, RejectCall(...))`` on the
      threshold crossing.
    * ``state == "opened"`` -- the failure was already counted at the
      original threshold crossing; the snapshot is returned unchanged plus a
      RejectCall reflecting the existing window.
    * ``state == "half_opened"`` -- the probe failed; transition back to
      ``opened`` with ``generation += 1`` and ``opened_at = clock.now()``.

    Parameters
    ----------
    snapshot
        Current state.
    config
        Tuning knobs (``threshold``, ``ttl``).
    clock
        Time source.

    Returns
    -------
    tuple[Snapshot, Decision]
        Post-transition Snapshot and the Decision the caller would observe
        if it queried :func:`project_decision` immediately afterwards.

    Examples
    --------
    >>> from hypervigilant.circuit_breaker.clock import FakeClock
    >>> from hypervigilant.circuit_breaker.config import BreakerConfig
    >>> from hypervigilant.circuit_breaker.state import Snapshot
    >>> snap = Snapshot(name='x', state='closed', failure_count=4, opened_at=0.0, generation=7)
    >>> new, _ = apply_failure(snap, BreakerConfig(threshold=5), FakeClock(now=100.0))
    >>> (new.state, new.failure_count, new.generation, new.opened_at)
    ('opened', 5, 8, 100.0)
    """
    match snapshot.state:
        case "closed":
            new_failure_count = snapshot.failure_count + 1
            if new_failure_count >= config.threshold:
                now = clock.now()
                new_snapshot = Snapshot(
                    name=snapshot.name,
                    state="opened",
                    failure_count=config.threshold,
                    opened_at=now,
                    generation=snapshot.generation + 1,
                )
                return (
                    new_snapshot,
                    RejectCall(opened_at=now, retry_after=config.ttl),
                )
            new_snapshot = Snapshot(
                name=snapshot.name,
                state="closed",
                failure_count=new_failure_count,
                opened_at=snapshot.opened_at,
                generation=snapshot.generation,
            )
            return new_snapshot, AllowCall()
        case "opened":
            decision = project_decision(snapshot, config, clock)
            return snapshot, decision
        case "half_opened":
            now = clock.now()
            new_snapshot = Snapshot(
                name=snapshot.name,
                state="opened",
                failure_count=max(snapshot.failure_count, 1),
                opened_at=now,
                generation=snapshot.generation + 1,
            )
            return (
                new_snapshot,
                RejectCall(opened_at=now, retry_after=config.ttl),
            )
        case _:
            assert_never(snapshot.state)


def apply_success(
    snapshot: Snapshot,
    config: BreakerConfig,  # noqa: ARG001 -- reserved for future telemetry
    clock: Clock,  # noqa: ARG001 -- reserved for future telemetry
) -> Snapshot:
    """Transition the snapshot for an observed success.

    Three transition cases:

    * ``state == "closed"`` -- reset ``failure_count`` to ``0``; leave
      ``generation`` unchanged.
    * ``state == "half_opened"`` -- the probe succeeded; transition to
      ``closed`` with ``failure_count == 0`` and ``generation += 1``.
    * ``state == "opened"`` -- a success arriving while the breaker is open
      MUST NOT silently move the breaker into closed; the snapshot is
      returned unchanged. (Operationally, this branch is unreachable through
      the runtime layer because ``project_decision`` would return
      :class:`RejectCall` and the runtime would raise
      :class:`BreakerOpenError` before the user's coroutine ran.)

    Parameters
    ----------
    snapshot
        Current state.
    config
        Tuning knobs. Reserved for future telemetry.
    clock
        Time source. Reserved for future telemetry.

    Returns
    -------
    Snapshot
        Post-transition Snapshot.

    Examples
    --------
    >>> from hypervigilant.circuit_breaker.clock import FakeClock
    >>> from hypervigilant.circuit_breaker.config import BreakerConfig
    >>> from hypervigilant.circuit_breaker.state import Snapshot
    >>> snap = Snapshot(name='x', state='half_opened', failure_count=0, opened_at=100.0, generation=10)
    >>> new = apply_success(snap, BreakerConfig(), FakeClock(now=150.0))
    >>> (new.state, new.failure_count, new.generation)
    ('closed', 0, 11)
    """
    match snapshot.state:
        case "closed":
            return Snapshot(
                name=snapshot.name,
                state="closed",
                failure_count=0,
                opened_at=snapshot.opened_at,
                generation=snapshot.generation,
            )
        case "half_opened":
            return Snapshot(
                name=snapshot.name,
                state="closed",
                failure_count=0,
                opened_at=snapshot.opened_at,
                generation=snapshot.generation + 1,
            )
        case "opened":
            return snapshot
        case _:
            assert_never(snapshot.state)


def apply_failure_windowed(
    snapshot: Snapshot,
    window: Window | None,
    policy: CountingPolicy,
    clock: Clock,
) -> tuple[Snapshot, Window, Decision]:
    """Sliding-window failure transition (FR-106).

    Returns ``(new_snapshot, persisted_window, decision)``. ``window`` may be
    ``None`` (fresh epoch) and is materialised as an empty window. The persisted
    window is reset to fresh on any trip or half-open transition (epoch
    boundary, EC-105); ``Snapshot.window`` is ``None`` whenever the breaker is
    not in an actively-windowed ``closed`` state.

    Examples
    --------
    >>> from hypervigilant.circuit_breaker.clock import FakeClock
    >>> snap = Snapshot(name='x', state='closed', failure_count=0, opened_at=0.0, generation=0)
    >>> new, win, _ = apply_failure_windowed(
    ...     snap, None, CountingPolicy('sliding_window', 10, 0.5, 10), FakeClock(now=1.0)
    ... )
    >>> (new.state, new.failure_count, win.failures)
    ('closed', 1, 1)
    """
    match snapshot.state:
        case "closed":
            win = window if window is not None else _fresh_window(policy.sliding_window_size)
            win = window_record(win, True)
            if window_should_trip(win, policy):
                now = clock.now()
                new_snapshot = Snapshot(
                    name=snapshot.name,
                    state="opened",
                    failure_count=win.failures,
                    opened_at=now,
                    generation=snapshot.generation + 1,
                    window=None,
                )
                return (
                    new_snapshot,
                    _fresh_window(policy.sliding_window_size),
                    RejectCall(opened_at=now, retry_after=0.0),
                )
            new_snapshot = Snapshot(
                name=snapshot.name,
                state="closed",
                failure_count=win.failures,
                opened_at=snapshot.opened_at,
                generation=snapshot.generation,
                window=_window_summary(win),
            )
            return new_snapshot, win, AllowCall()
        case "opened":
            return (
                snapshot,
                _fresh_window(policy.sliding_window_size),
                RejectCall(opened_at=snapshot.opened_at, retry_after=0.0),
            )
        case "half_opened":
            now = clock.now()
            new_snapshot = Snapshot(
                name=snapshot.name,
                state="opened",
                failure_count=max(snapshot.failure_count, 1),
                opened_at=now,
                generation=snapshot.generation + 1,
                window=None,
            )
            return (
                new_snapshot,
                _fresh_window(policy.sliding_window_size),
                RejectCall(opened_at=now, retry_after=0.0),
            )
        case _:
            assert_never(snapshot.state)


def apply_success_windowed(
    snapshot: Snapshot,
    window: Window | None,
    policy: CountingPolicy,
    clock: Clock,  # noqa: ARG001 -- reserved for symmetry with apply_failure_windowed
) -> tuple[Snapshot, Window]:
    """Sliding-window success transition (FR-106).

    A success in ``closed`` state is recorded into the window (it does NOT wipe
    it — EC-103); a success in ``half_opened`` state closes the breaker and
    starts a fresh window epoch.

    Examples
    --------
    >>> from hypervigilant.circuit_breaker.clock import FakeClock
    >>> snap = Snapshot(name='x', state='half_opened', failure_count=0, opened_at=5.0, generation=3)
    >>> new, win = apply_success_windowed(
    ...     snap, None, CountingPolicy('sliding_window', 10, 0.5, 10), FakeClock(now=10.0)
    ... )
    >>> (new.state, new.generation, win.total)
    ('closed', 4, 0)
    """
    match snapshot.state:
        case "closed":
            win = window if window is not None else _fresh_window(policy.sliding_window_size)
            win = window_record(win, False)
            new_snapshot = Snapshot(
                name=snapshot.name,
                state="closed",
                failure_count=win.failures,
                opened_at=snapshot.opened_at,
                generation=snapshot.generation,
                window=_window_summary(win),
            )
            return new_snapshot, win
        case "half_opened":
            new_snapshot = Snapshot(
                name=snapshot.name,
                state="closed",
                failure_count=0,
                opened_at=snapshot.opened_at,
                generation=snapshot.generation + 1,
                window=None,
            )
            return new_snapshot, _fresh_window(policy.sliding_window_size)
        case "opened":
            return snapshot, _fresh_window(policy.sliding_window_size)
        case _:
            assert_never(snapshot.state)
