"""Clock Protocol and concrete implementations used across the breaker module.

Per FR-008, time is injected through a :class:`Clock` Protocol so the rewrite
never calls :func:`time.time` or :func:`time.monotonic` outside this module.
Three production implementations ship:

* :class:`SystemClock` -- wraps :func:`time.time`. Used wherever wall-clock
  semantics are required (e.g., comparing client-side cache freshness against
  Redis-stored ``opened_at`` values produced by ``redis.call('TIME')``).
* :class:`MonotonicClock` -- wraps :func:`time.monotonic`. Used by
  :class:`InMemoryStore` and is the default registry clock; insulates
  in-process state from NTP slew (EC-004).
* :class:`FakeClock` -- deterministic test double. Stores its own ``now`` and
  exposes :meth:`FakeClock.advance` for property-based and unit tests.

The :class:`Clock` Protocol is :func:`@runtime_checkable
<typing.runtime_checkable>` so contract tests can assert
``isinstance(custom_clock, Clock)``.

References
----------
- FR-008 (Clock Protocol contract).
- EC-004 (NTP backward slew must not flip the breaker state).
- Decision 1 (sansio core depends on Clock injection).

Examples
--------
>>> clock = FakeClock(now=10.0)
>>> clock.advance(5.0)
>>> clock.now()
15.0
"""

import time
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "FakeClock", "MonotonicClock", "SystemClock"]


@runtime_checkable
class Clock(Protocol):
    """Source of monotonic-or-wall-clock time used by the breaker module.

    Implementations MUST return a float-valued reading of the current time in
    seconds. The unit (epoch seconds vs. monotonic seconds) is
    implementation-defined; callers MUST treat the value as opaque and only
    compute deltas between two consecutive reads of the same clock.

    Notes
    -----
    The Protocol is decorated with :func:`typing.runtime_checkable` to enable
    structural ``isinstance`` checks in contract tests. This is safe here
    because the Protocol exposes a single nullary method.

    Examples
    --------
    >>> from hypervigilant.circuit_breaker.clock import Clock, MonotonicClock
    >>> isinstance(MonotonicClock(), Clock)
    True
    """

    def now(self) -> float:
        """Return the current time as a float."""
        ...


class SystemClock:
    """Wall-clock implementation backed by :func:`time.time`.

    Used wherever the rewrite needs an epoch-second reading -- typically for
    client-side cache freshness checks against Redis-side ``opened_at``
    values produced by ``redis.call('TIME')``.

    Examples
    --------
    >>> clock = SystemClock()
    >>> reading = clock.now()
    >>> isinstance(reading, float)
    True
    """

    __slots__ = ()

    def now(self) -> float:
        """Return :func:`time.time` as a float."""
        return time.time()


class MonotonicClock:
    """Monotonic-second implementation backed by :func:`time.monotonic`.

    Default for :class:`InMemoryStore` and the registry. Insulates in-process
    breaker state from NTP slew (EC-004): a monotonic clock never runs
    backwards, so an ``opened_at`` reading taken at ``t0`` cannot appear to
    have moved into the future after a wall-clock NTP correction.

    Examples
    --------
    >>> clock = MonotonicClock()
    >>> a = clock.now()
    >>> b = clock.now()
    >>> b >= a
    True
    """

    __slots__ = ()

    def now(self) -> float:
        """Return :func:`time.monotonic` as a float."""
        return time.monotonic()


class FakeClock:
    """Deterministic clock used in tests; never imports the real time module.

    Stores a single ``_now`` attribute and exposes :meth:`advance` to bump it
    forward. ``advance`` rejects negative deltas to preserve monotonicity --
    a backward-slew test SHOULD construct a fresh :class:`FakeClock` rather
    than try to rewind an existing one.

    Parameters
    ----------
    now
        Initial reading. Defaults to ``0.0``.

    Examples
    --------
    >>> clock = FakeClock(now=100.0)
    >>> clock.advance(35.0)
    >>> clock.now()
    135.0
    """

    __slots__ = ("_now",)

    def __init__(self, now: float = 0.0) -> None:
        self._now = float(now)

    def now(self) -> float:
        """Return the in-memory time."""
        return self._now

    def advance(self, dt: float) -> None:
        """Advance the in-memory clock by ``dt`` seconds.

        Parameters
        ----------
        dt
            Non-negative delta in seconds.

        Raises
        ------
        ValueError
            If ``dt`` is negative -- monotonicity is required.

        Examples
        --------
        >>> clock = FakeClock()
        >>> clock.advance(2.5)
        >>> clock.now()
        2.5
        """
        if dt < 0.0:
            msg = f"FakeClock.advance requires a non-negative delta; got {dt!r}."
            raise ValueError(msg)
        self._now += float(dt)
