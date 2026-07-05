"""In-memory :class:`BreakerStore` implementation backed by an ``asyncio.Lock``.

Process-local storage suitable for single-worker hypervigilant deployments and tests.
For multi-process deployments use the Redis-backed store instead — the
in-memory store does NOT share state across event loops or processes.

The implementation serialises every mutation through a per-circuit
:class:`asyncio.Lock`; the dictionary that maps names to cells is itself
guarded by a top-level lock so the lazy ``_get_or_create_cell`` step is also
race-free.

The store delegates every state-machine transition to the sansio core
(:func:`hypervigilant.circuit_breaker.breaker.project_decision`,
:func:`apply_failure`, :func:`apply_success`). The OPEN → HALF_OPEN transition
that ``acquire`` triggers when the TTL has elapsed is the only piece of
transition logic the store applies directly, because the sansio core's
``project_decision`` is intentionally read-only.

References
----------
- FR-005 (asymmetric ``BreakerStore`` contract).
- FR-008 (Clock injection).
- FR-016 (StoreObserver telemetry).
- AC-001..AC-004 (state-machine acceptance through the public surface).
- Decision 1 (sansio split).
- Decision 4 (asymmetric Protocol).

Examples
--------
>>> import asyncio
>>> from hypervigilant.circuit_breaker.stores.memory import InMemoryStore
>>> async def demo() -> str:
...     store = InMemoryStore()
...     decision, _snapshot = await store.acquire('svc', threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
...     return type(decision).__name__
>>> asyncio.run(demo())
'AllowCall'
"""

import asyncio
import time
from dataclasses import dataclass, field

from hypervigilant.circuit_breaker.breaker import (
    apply_failure,
    apply_failure_windowed,
    apply_success,
    apply_success_windowed,
    project_decision,
)
from hypervigilant.circuit_breaker.clock import Clock, MonotonicClock
from hypervigilant.circuit_breaker.config import BreakerConfig, CountingPolicy
from hypervigilant.circuit_breaker.hooks import NoOpObserver, StoreObserver
from hypervigilant.circuit_breaker.policy import (
    Decision,
    ProbeCall,
)
from hypervigilant.circuit_breaker.state import Snapshot, Window

__all__ = ["InMemoryStore"]


@dataclass(slots=True)
class _Cell:
    """Internal per-circuit cell guarded by a single :class:`asyncio.Lock`.

    Carries the current :class:`Snapshot` and the lock that serialises every
    mutation against the cell. Not exported; ``InMemoryStore`` is the only
    legitimate caller. ``probe_lease_until`` is reserved for a future
    half-open lease-expiry recovery path; the current implementation enforces
    single-flight via the snapshot ``state == "half_opened"`` guard.
    """

    snapshot: Snapshot
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    probe_lease_until: float | None = None
    window: Window | None = None


class InMemoryStore:
    """Asymmetric :class:`BreakerStore` implementation backed by a process-local dict.

    Every public method acquires a per-circuit :class:`asyncio.Lock` before
    mutating state. The internal dictionary that maps names to cells is
    guarded by a top-level lock so cell creation is also race-free.

    Parameters
    ----------
    clock
        Time source. Defaults to :class:`MonotonicClock` to insulate against
        NTP slew (EC-004).
    observer
        Telemetry hook. Defaults to :class:`NoOpObserver`.

    Notes
    -----
    The store is **process-local**. Cross-process or cross-worker
    coordination requires the Redis-backed store.

    Examples
    --------
    >>> import asyncio
    >>> from hypervigilant.circuit_breaker.stores.memory import InMemoryStore
    >>> async def demo() -> int:
    ...     store = InMemoryStore()
    ...     snap = await store.record_failure('svc', threshold=5, ttl_seconds=30.0)
    ...     return snap.failure_count
    >>> asyncio.run(demo())
    1
    """

    __slots__ = ("_cells", "_clock", "_dict_lock", "_observer")

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        observer: StoreObserver | None = None,
    ) -> None:
        self._clock: Clock = clock if clock is not None else MonotonicClock()
        self._observer: StoreObserver = observer if observer is not None else NoOpObserver()
        self._cells: dict[str, _Cell] = {}
        self._dict_lock = asyncio.Lock()

    async def _get_or_create_cell(self, name: str) -> _Cell:
        """Return the cell for ``name``, creating it on first reference."""
        async with self._dict_lock:
            cell = self._cells.get(name)
            if cell is None:
                cell = _Cell(
                    snapshot=Snapshot(
                        name=name,
                        state="closed",
                        failure_count=0,
                        opened_at=0.0,
                        generation=0,
                    ),
                )
                self._cells[name] = cell
            return cell

    async def acquire(
        self,
        name: str,
        *,
        threshold: int,
        ttl_seconds: float,
        lease_seconds: float,
    ) -> tuple[Decision, Snapshot]:
        """Project the next :class:`Decision` and apply OPEN → HALF_OPEN if TTL elapsed.

        See :class:`BreakerStore.acquire` for the contract.
        """
        cell = await self._get_or_create_cell(name)
        config = BreakerConfig(
            threshold=threshold,
            ttl=ttl_seconds,
            half_open_lease_seconds=lease_seconds,
        )
        start = time.perf_counter()
        async with cell.lock:
            decision = project_decision(cell.snapshot, config, self._clock)
            if isinstance(decision, ProbeCall) and cell.snapshot.state == "opened":
                cell.snapshot = Snapshot(
                    name=name,
                    state="half_opened",
                    failure_count=0,
                    opened_at=cell.snapshot.opened_at,
                    generation=cell.snapshot.generation + 1,
                )
                cell.probe_lease_until = decision.lease_until
            elif (
                cell.snapshot.state == "half_opened"
                and cell.probe_lease_until is not None
                and cell.probe_lease_until <= self._clock.now()
            ):
                # Stale half-open lease: re-issue the probe so the breaker
                # does not wedge after a crashed probe coroutine.
                lease_until = self._clock.now() + lease_seconds
                cell.snapshot = Snapshot(
                    name=name,
                    state="half_opened",
                    failure_count=0,
                    opened_at=cell.snapshot.opened_at,
                    generation=cell.snapshot.generation + 1,
                )
                cell.probe_lease_until = lease_until
                decision = ProbeCall(lease_until=lease_until)
            post_snapshot = cell.snapshot
        duration_ms = (time.perf_counter() - start) * 1000.0
        self._observer.on_call(op="acquire", name=name, duration_ms=duration_ms)
        self._observer.on_decision(
            name=name,
            snapshot=post_snapshot,
            decision=decision,
        )
        return decision, post_snapshot

    async def record_failure(
        self,
        name: str,
        *,
        threshold: int,
        ttl_seconds: float,
        counting: CountingPolicy | None = None,
    ) -> Snapshot:
        """Atomically apply a failure transition; see :class:`BreakerStore.record_failure`."""
        cell = await self._get_or_create_cell(name)
        start = time.perf_counter()
        async with cell.lock:
            if counting is not None and counting.strategy == "sliding_window":
                new_snapshot, cell.window, _ = apply_failure_windowed(cell.snapshot, cell.window, counting, self._clock)
            else:
                config = BreakerConfig(threshold=threshold, ttl=ttl_seconds)
                new_snapshot, _ = apply_failure(cell.snapshot, config, self._clock)
                cell.window = None
            cell.snapshot = new_snapshot
            if new_snapshot.state != "half_opened":
                cell.probe_lease_until = None
        duration_ms = (time.perf_counter() - start) * 1000.0
        self._observer.on_call(op="record_failure", name=name, duration_ms=duration_ms)
        return new_snapshot

    async def record_success(
        self,
        name: str,
        *,
        counting: CountingPolicy | None = None,
    ) -> Snapshot:
        """Atomically apply a success transition; see :class:`BreakerStore.record_success`."""
        cell = await self._get_or_create_cell(name)
        start = time.perf_counter()
        async with cell.lock:
            if counting is not None and counting.strategy == "sliding_window":
                new_snapshot, cell.window = apply_success_windowed(cell.snapshot, cell.window, counting, self._clock)
            else:
                # ``apply_success`` ignores ``config`` and ``clock`` today, but the
                # sansio contract still requires both arguments. Use cheap defaults.
                config = BreakerConfig()
                new_snapshot = apply_success(cell.snapshot, config, self._clock)
                cell.window = None
            cell.snapshot = new_snapshot
            cell.probe_lease_until = None
        duration_ms = (time.perf_counter() - start) * 1000.0
        self._observer.on_call(op="record_success", name=name, duration_ms=duration_ms)
        return new_snapshot

    async def peek(self, name: str) -> Snapshot | None:
        """Return the current snapshot without mutating state."""
        async with self._dict_lock:
            cell = self._cells.get(name)
        if cell is None:
            return None
        async with cell.lock:
            return cell.snapshot

    async def reset(self, name: str | None = None) -> None:
        """Discard breaker state. ``name=None`` clears every circuit."""
        async with self._dict_lock:
            if name is None:
                self._cells.clear()
            else:
                self._cells.pop(name, None)

    async def aclose(self) -> None:
        """No-op: the in-memory store owns no external resources."""
        await self.reset(None)

    async def initialize(self) -> None:
        """No-op: the in-memory store has no Lua scripts to load."""

    def clock_now(self) -> float:
        """Return ``self._clock.now()`` for the runtime's ``retry_after`` math."""
        return self._clock.now()
