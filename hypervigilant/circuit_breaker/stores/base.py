"""``BreakerStore`` Protocol — asymmetric storage contract for the circuit module.

The Protocol exposes high-level *decision primitives*, not CRUD. Two return
shapes coexist (Decision 4 / FR-005):

* :meth:`BreakerStore.acquire` returns a :class:`Decision` directly — its job
  is to decide whether the call can proceed, and to atomically transition
  ``state == "opened"`` to ``state == "half_opened"`` when the TTL has elapsed.
* :meth:`BreakerStore.record_failure` and :meth:`BreakerStore.record_success`
  return only the post-mutation :class:`Snapshot`; the caller (sansio
  ``breaker.py``) projects the next Decision in pure Python.

Implementations MUST NOT expose lower-level ``get`` / ``set`` / ``update``
primitives that callers could compose non-atomically — that asymmetry is the
direct fix for the read-modify-write race at
``pixiu/_vendor/purgatory/service/_async/repository.py:115-126``.

The Protocol is :func:`@runtime_checkable <typing.runtime_checkable>` so
contract tests can assert structural conformance without inheritance.

References
----------
- FR-005 (asymmetric Protocol shape).
- AC-001..002 (acquire returns Decision; record_* returns Snapshot).
- Decision 4 (asymmetric store contract).

Examples
--------
>>> from hypervigilant.circuit_breaker.stores.base import BreakerStore
>>> from hypervigilant.circuit_breaker.stores.memory import InMemoryStore
>>> isinstance(InMemoryStore(), BreakerStore)
True
"""

from typing import Protocol, runtime_checkable

from hypervigilant.circuit_breaker.config import CountingPolicy
from hypervigilant.circuit_breaker.policy import Decision
from hypervigilant.circuit_breaker.state import Snapshot

__all__ = ["BreakerStore"]


@runtime_checkable
class BreakerStore(Protocol):
    """Storage contract consumed by the runtime layer (``AsyncCircuitBreaker``).

    Implementations persist a :class:`Snapshot` per circuit name and project
    Decisions through the sansio core when callers ``acquire``. Mutating
    operations (``record_failure``, ``record_success``) MUST be atomic; the
    Lua-backed Redis implementation guarantees this by running each mutation
    inside a single ``EVALSHA`` round-trip, while the in-memory implementation
    serialises through a per-circuit :class:`asyncio.Lock`.

    Notes
    -----
    Only :meth:`acquire` triggers the ``opened`` → ``half_opened`` transition.
    Subsequent concurrent callers during the half-open window observe a
    :class:`hypervigilant.circuit_breaker.policy.RejectCall` (single-flight
    by default; ``BreakerConfig.half_open_max_calls = 1``).

    Examples
    --------
    >>> from hypervigilant.circuit_breaker.stores.memory import InMemoryStore
    >>> store: BreakerStore = InMemoryStore()
    >>> store.__class__.__name__
    'InMemoryStore'
    """

    async def acquire(
        self,
        name: str,
        *,
        threshold: int,
        ttl_seconds: float,
        lease_seconds: float,
    ) -> tuple[Decision, Snapshot]:
        """Project the next :class:`Decision` for ``name`` and return the post-mutation snapshot.

        Atomically applies the ``opened`` → ``half_opened`` transition when
        the TTL has elapsed. The snapshot returned is the post-acquire state,
        so the runtime layer does not need to issue a follow-up ``peek``.

        Parameters
        ----------
        name
            Circuit name. The store creates a fresh ``Snapshot`` lazily on
            first reference.
        threshold
            Failure threshold (passed through to ``BreakerConfig``).
        ttl_seconds
            ``opened`` window duration in seconds.
        lease_seconds
            Probe lease duration applied when transitioning to ``half_opened``.

        Returns
        -------
        tuple[Decision, Snapshot]
            The Decision projected for this acquire call, and the
            post-mutation snapshot. ``Decision`` variants:
            :class:`AllowCall` while ``state == "closed"``;
            :class:`RejectCall` while ``state == "opened"`` and within ``ttl``,
            or while ``state == "half_opened"`` (single-flight reject for
            newcomers); :class:`ProbeCall` exactly once when ``state ==
            "opened"`` and ``ttl`` has elapsed (this call also transitions
            ``state`` to ``"half_opened"``).
        """
        ...

    async def record_failure(
        self,
        name: str,
        *,
        threshold: int,
        ttl_seconds: float,
        counting: CountingPolicy | None = None,
    ) -> Snapshot:
        """Atomically increment the failure counter (or trip the breaker).

        Parameters
        ----------
        name
            Circuit name.
        threshold
            Failure threshold (passed through to ``BreakerConfig``).
        ttl_seconds
            ``opened`` window duration in seconds.

        Returns
        -------
        Snapshot
            Post-mutation snapshot. Callers project the next Decision via
            :func:`hypervigilant.circuit_breaker.breaker.project_decision`.
        """
        ...

    async def record_success(
        self,
        name: str,
        *,
        counting: CountingPolicy | None = None,
    ) -> Snapshot:
        """Atomically reset the failure counter (or close the breaker after a probe).

        Parameters
        ----------
        name
            Circuit name.

        Returns
        -------
        Snapshot
            Post-mutation snapshot.
        """
        ...

    async def peek(self, name: str) -> Snapshot | None:
        """Read the current snapshot without mutating state.

        Parameters
        ----------
        name
            Circuit name.

        Returns
        -------
        Snapshot or None
            The current snapshot, or ``None`` if the circuit has never been
            referenced.
        """

    async def reset(self, name: str | None = None) -> None:
        """Discard breaker state.

        Parameters
        ----------
        name
            Circuit name to reset; ``None`` resets every circuit known to the
            store.
        """

    async def aclose(self) -> None:
        """Release any resources owned by the store (connection pool, etc.)."""

    async def initialize(self) -> None:
        """Eager-initialise the store (no-op for in-memory; loads Lua for Redis).

        Idempotent: callers may invoke it multiple times. The runtime layer
        calls this from ``AsyncBreakerRegistry.initialize`` to amortise
        SCRIPT LOAD over the registry's lifespan rather than the first
        protected call.
        """
        ...

    def clock_now(self) -> float:
        """Return the current time in the store's clock domain.

        Used by the runtime layer to compute ``retry_after`` consistently
        with ``Snapshot.opened_at`` (which the store stamps using the same
        clock). The Redis store uses a wall-clock domain (``SystemClock``,
        matching ``redis.call('TIME')``); the in-memory store uses a
        monotonic domain by default.
        """
        ...
