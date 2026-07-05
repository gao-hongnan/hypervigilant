"""Async runtime: :class:`AsyncCircuitBreaker` + :class:`AsyncBreakerRegistry`.

The runtime layer wires the sansio core (``breaker.py``) and the storage
backends (``stores/``) into a user-facing async surface:

* :class:`AsyncCircuitBreaker` is an async context manager that calls
  :meth:`BreakerStore.acquire` on enter, raises
  :exc:`BreakerOpenError` on a :class:`RejectCall` decision, runs the
  protected coroutine on :class:`AllowCall` / :class:`ProbeCall`, and
  records the failure or success on exit.
* :class:`AsyncBreakerRegistry` is an Identity Map (Fowler PEAA) that
  hands out per-name :class:`AsyncCircuitBreaker` instances and exposes
  :meth:`__call__` for decorator usage and :meth:`on` for typed event
  subscription.

References
----------
- FR-001 (AsyncCircuitBreaker), FR-002 (AsyncBreakerRegistry).
- FR-013 (snapshot() value object), FR-016 (StoreObserver).
- AC-001..AC-008.
- Decisions 1, 4, 7, 8, 9.
"""

import asyncio
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from functools import wraps
from types import TracebackType
from typing import ParamSpec, Self, TypeVar

from hypervigilant.circuit_breaker.config import BreakerConfig
from hypervigilant.circuit_breaker.errors import BreakerOpenError, CircuitStorageError
from hypervigilant.circuit_breaker.events import (
    BreakerCreated,
    BreakerEvent,
    BreakerFailed,
    BreakerRecovered,
    BreakerStateChanged,
    EventDispatcher,
)
from hypervigilant.circuit_breaker.hooks import NoOpObserver, StoreObserver
from hypervigilant.circuit_breaker.policy import RejectCall
from hypervigilant.circuit_breaker.state import BreakerStatus, Snapshot
from hypervigilant.circuit_breaker.stores.base import BreakerStore
from hypervigilant.circuit_breaker.stores.memory import InMemoryStore

__all__ = ["AsyncBreakerRegistry", "AsyncCircuitBreaker"]


_pre_snapshot_stack: ContextVar[tuple[Snapshot, ...]] = ContextVar(
    "hypervigilant_circuit_breaker_pre_snapshot_stack",
    default=(),
)
"""Task-scoped LIFO stack of pre-acquire snapshots.

Each ``async with breaker:`` push happens on entry (only when the body runs)
and the corresponding pop happens on exit. ``ContextVar`` semantics make the
stack per-task in asyncio, so concurrent ``async with`` against the same
:class:`AsyncCircuitBreaker` instance cannot clobber each other's pre-state.
The tuple is immutable; every push/pop creates a new value to avoid sharing
mutable references across tasks that copied a parent context.
"""


class AsyncCircuitBreaker:
    """Async context manager that protects a coroutine via a :class:`BreakerStore`.

    The breaker is a thin orchestration layer over a sansio core; every
    state transition is computed by ``breaker.py`` and persisted by the
    store. ``__aenter__`` calls :meth:`BreakerStore.acquire` and either
    enters the body (``AllowCall`` / ``ProbeCall``) or raises
    :exc:`BreakerOpenError` (``RejectCall``). ``__aexit__`` records the
    outcome and dispatches the relevant event(s).
    """

    __slots__ = ("_config", "_dispatcher", "_name", "_store")

    def __init__(
        self,
        *,
        name: str,
        config: BreakerConfig,
        store: BreakerStore,
        dispatcher: EventDispatcher,
    ) -> None:
        self._name = name
        self._config = config
        self._store = store
        self._dispatcher = dispatcher

    @property
    def name(self) -> str:
        """Breaker name, set at registry construction."""
        return self._name

    @property
    def config(self) -> BreakerConfig:
        """Immutable :class:`BreakerConfig` set at registry construction."""
        return self._config

    async def snapshot(self) -> BreakerStatus:
        """Return an immutable :class:`BreakerStatus` (single Redis round-trip).

        The runtime computes ``retry_after`` from the snapshot's
        ``opened_at`` and the configured ``ttl``; ``state == "closed"``
        always reports ``retry_after = 0.0``.
        """
        snap = await self._store.peek(self._name)
        if snap is None:
            return BreakerStatus(
                name=self._name,
                state="closed",
                failure_count=0,
                opened_at=0.0,
                generation=0,
                retry_after=0.0,
            )
        retry_after = self._compute_retry_after(snap)
        return BreakerStatus(
            name=snap.name,
            state=snap.state,
            failure_count=snap.failure_count,
            opened_at=snap.opened_at,
            generation=snap.generation,
            retry_after=retry_after,
        )

    def _compute_retry_after(self, snap: Snapshot) -> float:
        """Project ``retry_after`` from a snapshot.

        ``ttl - elapsed`` clamped at ``0.0``. ``elapsed`` is computed in the
        store's clock domain so the math is consistent with
        ``snap.opened_at`` (which the store stamps using the same clock).
        """
        if snap.state == "closed":
            return 0.0
        if snap.opened_at <= 0.0:
            return self._config.ttl
        elapsed = self._store.clock_now() - snap.opened_at
        return max(self._config.ttl - elapsed, 0.0)

    async def __aenter__(self) -> Self:
        decision, post_snapshot = await self._store.acquire(
            self._name,
            threshold=self._config.threshold,
            ttl_seconds=self._config.ttl,
            lease_seconds=self._config.half_open_lease_seconds,
        )
        if isinstance(decision, RejectCall):
            raise BreakerOpenError(
                name=self._name,
                opened_at=decision.opened_at,
                retry_after=decision.retry_after,
            )
        _pre_snapshot_stack.set((*_pre_snapshot_stack.get(), post_snapshot))
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        del exc_type, _tb
        stack = _pre_snapshot_stack.get()
        if not stack:
            return
        pre_snapshot = stack[-1]
        _pre_snapshot_stack.set(stack[:-1])
        if exc is None:
            new_snap = await self._store.record_success(self._name, counting=self._config.counting)
            await self._maybe_emit_recovery(pre_snapshot, new_snap)
            await self._maybe_emit_state_change(pre_snapshot, new_snap)
            return
        if not self._is_failure_recordable(exc):
            return
        if isinstance(exc, BreakerOpenError):
            return
        # The user exception (`exc`) is in flight. A `CircuitStorageError`
        # raised by `record_failure` would replace it via `__aexit__`'s
        # exception-replacement semantics, hiding the real cause from the
        # caller's `except` clause. The store's observer was already
        # notified of the storage failure via `on_storage_failure`, so we
        # suppress the wrapper here and let the user exception propagate.
        try:
            new_snap = await self._store.record_failure(
                self._name,
                threshold=self._config.threshold,
                ttl_seconds=self._config.ttl,
                counting=self._config.counting,
            )
        except CircuitStorageError:
            return
        exc_type_obj = type(exc)
        await self._dispatcher.dispatch(
            BreakerFailed(
                name=self._name,
                exception_repr=repr(exc),
                failure_count=new_snap.failure_count,
                exception_type=exc_type_obj.__name__,
                exception_module=exc_type_obj.__module__,
                failure_rate=new_snap.window.rate if new_snap.window is not None else None,
            ),
        )
        await self._maybe_emit_state_change(pre_snapshot, new_snap)

    def _is_failure_recordable(self, exc: BaseException) -> bool:
        """``BreakerConfig.exclude`` and ``CancelledError`` short-circuit failure recording."""
        if isinstance(exc, asyncio.CancelledError):
            return False
        if not self._config.exclude:
            return True
        return not isinstance(exc, self._config.exclude)

    async def _maybe_emit_recovery(
        self,
        pre_snapshot: Snapshot,
        new_snap: Snapshot,
    ) -> None:
        """Emit :class:`BreakerRecovered` when the breaker just closed from half-open."""
        if not new_snap.is_authoritative:
            return
        if pre_snapshot.state == "half_opened" and new_snap.state == "closed":
            await self._dispatcher.dispatch(
                BreakerRecovered(name=self._name, generation=new_snap.generation),
            )

    async def _maybe_emit_state_change(
        self,
        pre_snapshot: Snapshot,
        new_snap: Snapshot,
    ) -> None:
        """Emit :class:`BreakerStateChanged` when state transitioned during this acquire."""
        if not new_snap.is_authoritative:
            return
        if pre_snapshot.state == new_snap.state:
            return
        await self._dispatcher.dispatch(
            BreakerStateChanged(
                name=self._name,
                from_state=pre_snapshot.state,
                to_state=new_snap.state,
                generation=new_snap.generation,
            ),
        )


P = ParamSpec("P")
R = TypeVar("R")
_E = TypeVar("_E", bound=BreakerEvent)


class AsyncBreakerRegistry:
    """Identity Map of :class:`AsyncCircuitBreaker` instances + decorator + events.

    ``get(name)`` returns the same :class:`AsyncCircuitBreaker` instance
    every time the registry sees that name; ``__call__(name)`` returns a
    decorator that wraps an async function in a fresh ``async with``;
    ``on(event_type, handler)`` subscribes ``handler`` to events of type
    ``event_type``.
    """

    __slots__ = (
        "_breakers",
        "_default_config",
        "_dict_lock",
        "_dispatcher",
        "_initialized",
        "_init_lock",
        "_observer",
        "_store",
    )

    def __init__(
        self,
        *,
        default_config: BreakerConfig | None = None,
        store: BreakerStore | None = None,
        observer: StoreObserver | None = None,
    ) -> None:
        self._default_config: BreakerConfig = default_config if default_config is not None else BreakerConfig()
        self._store: BreakerStore = store if store is not None else InMemoryStore()
        self._observer: StoreObserver = observer if observer is not None else NoOpObserver()
        self._dispatcher = EventDispatcher(observer=self._observer)
        self._breakers: dict[str, AsyncCircuitBreaker] = {}
        self._dict_lock = asyncio.Lock()
        self._initialized = False
        self._init_lock = asyncio.Lock()

    @property
    def store(self) -> BreakerStore:
        """The underlying :class:`BreakerStore` (for advanced direct access)."""
        return self._store

    async def initialize(self) -> None:
        """Initialise the underlying store (no-op for in-memory; loads Lua for Redis)."""
        async with self._init_lock:
            if self._initialized:
                return
            await self._store.initialize()
            self._initialized = True

    async def get(
        self,
        name: str,
        *,
        override: BreakerConfig | None = None,
    ) -> AsyncCircuitBreaker:
        """Return the :class:`AsyncCircuitBreaker` for ``name`` (Identity Map)."""
        await self.initialize()
        async with self._dict_lock:
            existing = self._breakers.get(name)
            if existing is not None:
                return existing
            config = override if override is not None else self._default_config
            breaker = AsyncCircuitBreaker(
                name=name,
                config=config,
                store=self._store,
                dispatcher=self._dispatcher,
            )
            self._breakers[name] = breaker
        await self._dispatcher.dispatch(
            BreakerCreated(name=name, config_repr=repr(config)),
        )
        return breaker

    def __call__(
        self,
        name: str,
        *,
        override: BreakerConfig | None = None,
    ) -> Callable[
        [Callable[P, Awaitable[R]]],
        Callable[P, Awaitable[R]],
    ]:
        """Return a decorator that wraps an async function in ``async with self.get(name):``."""

        def _decorator(
            func: Callable[P, Awaitable[R]],
        ) -> Callable[P, Awaitable[R]]:
            @wraps(func)
            async def _wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                breaker = await self.get(name, override=override)
                async with breaker:
                    return await func(*args, **kwargs)

            return _wrapped

        return _decorator

    def on(
        self,
        event_type: type[_E],
        handler: Callable[[_E], None] | Callable[[_E], Awaitable[None]],
    ) -> Callable[[], None]:
        """Subscribe ``handler`` to ``event_type``; returns an unsubscribe callable.

        Generic over ``E`` so callers register handlers typed against the
        specific event subclass (e.g. ``Callable[[BreakerCreated], None]``).
        """
        return self._dispatcher.register(event_type, handler)

    async def aclose(self) -> None:
        """Drain pending async handlers and close the underlying store."""
        await self._dispatcher.aclose()
        await self._store.aclose()

    async def __aenter__(self) -> Self:
        """Lifespan idiom: ``async with AsyncBreakerRegistry(...) as reg:``.

        Initialises the underlying store eagerly so the first user call
        does not pay the SCRIPT LOAD round-trip.
        """
        await self.initialize()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        """Drain pending handler tasks and close the store on lifespan exit."""
        del exc_type, exc, _tb
        await self.aclose()
