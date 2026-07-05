"""Frozen value objects shared across the circuit-breaker module.

This module provides the two pure data carriers consumed by the sansio core
and the runtime layer:

* :class:`Snapshot` -- the atomic state of a circuit at a point in time.
* :class:`BreakerStatus` -- the public-facing snapshot returned by
  ``await breaker.snapshot()``; identical to :class:`Snapshot` plus the
  computed ``retry_after`` window.

Both dataclasses are frozen with ``slots=True`` so they remain hashable, cheap
to construct, and immune to attribute drift. The ``state`` field uses a
``Literal`` of underscore-spelled state names (``"closed"``, ``"opened"``,
``"half_opened"``) per FR-013 — the rewrite uses underscores where the
vendored ``purgatory`` library used hyphens.

References
----------
- FR-013 (Snapshot/BreakerStatus shape and underscore convention).
- Decision 1 (sansio core consumes Snapshot).
- Decision 7 (BreakerStatus value object).

Examples
--------
>>> from hypervigilant.circuit_breaker.state import BreakerStatus, Snapshot
>>> snap = Snapshot(name='upstream', state='closed', failure_count=0, opened_at=0.0, generation=0)
>>> snap.state
'closed'
>>> status = BreakerStatus(
...     name='upstream', state='opened', failure_count=5,
...     opened_at=100.0, generation=2, retry_after=25.0,
... )
>>> status.retry_after
25.0
"""

from dataclasses import dataclass
from typing import Literal

__all__ = ["BreakerState", "BreakerStatus", "Snapshot", "Window", "WindowSummary"]


type BreakerState = Literal["closed", "opened", "half_opened"]
"""Type alias for the three discrete circuit states (FR-013).

The rewrite uses underscore-spelled identifiers (``"half_opened"``) where the
vendored ``purgatory`` library used a hyphen (``"half-opened"``); the literal
names are the wire format for Redis-stored ``state`` field values.
"""


@dataclass(frozen=True, slots=True)
class Window:
    """Sliding-window ring state for one circuit's ``closed`` epoch (FR-104).

    ``bits`` is a ring bitmask of the last ``size`` outcomes (1 = failure);
    ``write_index`` is the next write position in ``[0, size)``; ``total`` is the
    number of slots filled (capped at ``size``); ``failures`` is the cached
    popcount of ``bits``.

    Examples
    --------
    >>> w = Window(size=4, bits=0, write_index=0, total=0, failures=0)
    >>> w.size
    4
    """

    size: int
    bits: int
    write_index: int
    total: int
    failures: int


@dataclass(frozen=True, slots=True)
class WindowSummary:
    """Read-only projection of a :class:`Window` for observability (FR-104).

    Examples
    --------
    >>> ws = WindowSummary(size=10, failures=3, total=10, rate=0.3)
    >>> ws.rate
    0.3
    """

    size: int
    failures: int
    total: int
    rate: float


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Atomic, immutable view of a circuit's state at a point in time.

    Returned from :class:`hypervigilant.circuit_breaker.stores.base.BreakerStore`
    mutation methods and consumed by the sansio core's ``project_decision``
    function. Carries enough information for the projection layer to derive
    the next :class:`Decision` without re-reading the store.

    Parameters
    ----------
    name
        Human-readable circuit name; used in events, logs, and error messages.
    state
        Discrete circuit state. Underscore-spelled per FR-013.
    failure_count
        Consecutive failures observed in the current
        ``closed``/``half_opened`` window. Clamped at
        :attr:`BreakerConfig.threshold` once the breaker opens.
    opened_at
        Epoch second (or store-side wall clock) at which the breaker
        transitioned to ``opened``. ``0.0`` when the circuit has never opened.
    generation
        Monotonic counter incremented on every state transition. Tests use
        ``generation`` deltas to assert atomicity (e.g., "exactly one
        ``closed -> opened`` transition" => ``post.generation - pre.generation
        == 1``).

    Notes
    -----
    The dataclass is frozen with ``slots=True``: instances are hashable and
    cannot grow unintended attributes. Mutating an existing instance raises
    :exc:`dataclasses.FrozenInstanceError`.

    Examples
    --------
    >>> snap = Snapshot(name='x', state='closed', failure_count=0, opened_at=0.0, generation=0)
    >>> snap.failure_count
    0
    >>> snap == Snapshot(name='x', state='closed', failure_count=0, opened_at=0.0, generation=0)
    True
    """

    name: str
    state: BreakerState
    failure_count: int
    opened_at: float
    generation: int
    is_authoritative: bool = True
    """``False`` when the snapshot was synthesised during a storage outage.

    The runtime layer suppresses ``BreakerStateChanged`` /
    ``BreakerRecovered`` emission for non-authoritative snapshots so
    a cache fallback does not produce spurious "transition" events
    when the store could not actually mutate the underlying state.
    """
    window: WindowSummary | None = None
    """Sliding-window summary when ``counting.strategy == "sliding_window"``.

    ``None`` in consecutive mode and in any non-``closed`` state (the window is
    only active during a closed epoch). When present, ``failure_count`` mirrors
    ``window.failures``.
    """


@dataclass(frozen=True, slots=True)
class BreakerStatus:
    """Public-facing snapshot returned by ``await breaker.snapshot()``.

    Adds the ``retry_after`` window to the fields of :class:`Snapshot` so
    callers can decide how long to wait before issuing the next probe.
    Frozen with ``slots=True``; callers cannot mutate.

    Parameters
    ----------
    name
        Circuit name.
    state
        Discrete circuit state.
    failure_count
        Consecutive failures in the current window.
    opened_at
        Epoch second at which the breaker transitioned to ``opened``.
    generation
        Monotonic counter for state transitions.
    retry_after
        Seconds the caller should wait before retrying. ``0.0`` when the
        circuit is closed; otherwise ``ttl - elapsed`` (clamped at ``0.0``).

    Examples
    --------
    >>> status = BreakerStatus(
    ...     name='x', state='opened', failure_count=5,
    ...     opened_at=100.0, generation=2, retry_after=25.0,
    ... )
    >>> status.retry_after
    25.0
    """

    name: str
    state: BreakerState
    failure_count: int
    opened_at: float
    generation: int
    retry_after: float
    failure_rate: float | None = None
    """Failure rate over the sliding window (``None`` in consecutive mode) (FR-107)."""
