"""Readiness probing that answers correctly under saturation.

The ordering here is the whole design. :meth:`PoolHealthProbe.check` reads pool
statistics **first**, without checking out a connection. A saturated pool is already
the answer, and queueing the probe behind real traffic to discover it is how a
readiness endpoint comes to report "healthy" for ``pool_timeout`` seconds after the
service stopped being able to serve anything -- and then reports unhealthy on every
instance at once. Only when the pool has headroom does the probe spend a connection
on ``SELECT 1``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import QueuePool

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

__all__ = ["HealthProbe", "HealthReport", "PoolHealthProbe", "PoolStats"]

_PROBE_STATEMENT = text("SELECT 1")


@dataclass(frozen=True, slots=True)
class PoolStats:
    """A point-in-time read of pool occupancy.

    Attributes
    ----------
    size
        Configured pool size, excluding overflow.
    checked_out
        Connections currently held by callers.
    overflow
        Connections open beyond :attr:`size`. Negative while the pool is still
        filling, which is SQLAlchemy's own accounting and is preserved rather than
        clamped.
    saturated
        Whether every connection, including overflow, is checked out.

    Examples
    --------
    >>> PoolStats(size=5, checked_out=5, overflow=10, saturated=True).saturated
    True
    """

    size: int
    checked_out: int
    overflow: int
    saturated: bool


@dataclass(frozen=True, slots=True)
class HealthReport:
    """The answer to "should this instance take traffic".

    Attributes
    ----------
    ok
        Whether the database is usable right now.
    detail
        Short human-readable reason, suitable for a log line or a 503 body.
    latency_ms
        Round-trip time of the probe statement, or :data:`None` when no statement
        was run because the pool was already saturated.
    pool
        Occupancy at probe time, or :data:`None` when the engine uses a pool that
        does not report statistics.

    Examples
    --------
    >>> HealthReport(ok=True, detail="ready", latency_ms=1.2, pool=None).ok
    True
    """

    ok: bool
    detail: str
    latency_ms: float | None
    pool: PoolStats | None


@runtime_checkable
class HealthProbe(Protocol):
    """Reports whether the database is usable."""

    async def check(self) -> HealthReport:
        """Probe, without raising. Failure is reported in the return value."""
        ...


class PoolHealthProbe:
    """The real probe: pool statistics first, then one round trip.

    Parameters
    ----------
    engine
        The engine to probe.
    operation
        Label used in the report detail. Keyword-only.
    """

    __slots__ = ("_engine", "_operation")

    def __init__(self, engine: AsyncEngine, *, operation: str = "db.health") -> None:
        self._engine = engine
        self._operation = operation

    def _pool_stats(self) -> PoolStats | None:
        """Read occupancy, or ``None`` for pools that do not track it (e.g. ``NullPool``)."""
        pool = self._engine.pool
        if not isinstance(pool, QueuePool):
            return None
        size = pool.size()
        checked_out = pool.checkedout()
        overflow = pool.overflow()
        return PoolStats(
            size=size,
            checked_out=checked_out,
            overflow=overflow,
            saturated=checked_out >= size + max(pool._max_overflow, 0),  # noqa: SLF001
        )

    async def check(self) -> HealthReport:
        """Return the current readiness answer.

        Never raises: a probe that raises turns a readiness endpoint into a 500 and
        loses the reason.

        Examples
        --------
        >>> import inspect
        >>> inspect.iscoroutinefunction(PoolHealthProbe.check)
        True
        """
        stats = self._pool_stats()
        if stats is not None and stats.saturated:
            return HealthReport(
                ok=False,
                detail=f"{self._operation}: pool saturated ({stats.checked_out} checked out)",
                latency_ms=None,
                pool=stats,
            )
        started = time.perf_counter()
        try:
            async with self._engine.connect() as connection:
                await connection.execute(_PROBE_STATEMENT)
        except SQLAlchemyError as exc:
            return HealthReport(
                ok=False,
                detail=f"{self._operation}: {type(exc).__name__}: {exc}",
                latency_ms=None,
                pool=stats,
            )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return HealthReport(ok=True, detail=f"{self._operation}: ready", latency_ms=elapsed_ms, pool=stats)
