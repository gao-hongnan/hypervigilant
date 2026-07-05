"""Public event dataclasses + dispatcher for the circuit-breaker module.

Four frozen :class:`dataclasses.dataclass` events ship in this module
(FR-012), all named ``Breaker*`` to match the ``Breaker*`` types
elsewhere in the package. They replace the vendored
``CircuitBreakerCreated`` / ``ContextChanged`` / ``CircuitBreakerFailed`` /
``CircuitBreakerRecovered`` quartet from
``pixiu/_vendor/purgatory/domain/messages/events.py:1-30`` (which dropped
the ``Circuit`` prefix during the rewrite per refinement R3 →
Decision 12).

:class:`EventDispatcher` implements typed event subscription and fan-out.
Sync handlers run inline inside the dispatch boundary; async handlers
are scheduled via :func:`asyncio.create_task` *after* the user's
coroutine returns from ``__aexit__`` so observability latency never
extends the call path (Decision 8 / FR-010). Handler exceptions are
caught by the dispatcher and routed to
:meth:`StoreObserver.on_error`; handler exceptions never propagate to
user code.

References
----------
- FR-010 (async hooks scheduled post-aexit; exceptions logged).
- FR-012 (event class names; drop the ``Circuit`` prefix).
- AC-008 (hook exception isolation).
- Decisions 8 (hook scheduling), 12 (event names).

Examples
--------
>>> from hypervigilant.circuit_breaker.events import BreakerCreated
>>> evt = BreakerCreated(name='svc', config_repr='BreakerConfig(threshold=5)')
>>> evt.name
'svc'
"""

import asyncio
import contextlib
import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeAlias, TypeVar

from hypervigilant.circuit_breaker.hooks import NoOpObserver, StoreObserver
from hypervigilant.circuit_breaker.state import BreakerState

__all__ = [
    "BreakerCreated",
    "BreakerEvent",
    "BreakerFailed",
    "BreakerRecovered",
    "BreakerStateChanged",
    "EventDispatcher",
    "EventHandler",
]


@dataclass(frozen=True, slots=True)
class BreakerCreated:
    """Emitted exactly once when the registry first instantiates a breaker for ``name``."""

    name: str
    config_repr: str


@dataclass(frozen=True, slots=True)
class BreakerStateChanged:
    """Emitted on every ``closed``/``opened``/``half_opened`` transition."""

    name: str
    from_state: BreakerState
    to_state: BreakerState
    generation: int


@dataclass(frozen=True, slots=True)
class BreakerFailed:
    """Emitted when a protected coroutine raised inside ``__aexit__``.

    Carries both the lossy ``exception_repr`` (for human-readable logs)
    and structured ``exception_type`` / ``exception_module`` fields so
    downstream telemetry (Datadog, Prometheus labels) can tag and
    aggregate without regex-parsing the repr string.
    """

    name: str
    exception_repr: str
    failure_count: int
    exception_type: str = ""
    exception_module: str = ""
    failure_rate: float | None = None
    """Failure rate over the sliding window when ``counting.strategy ==
    'sliding_window'``; ``None`` in consecutive mode (DRAFT-0002)."""


@dataclass(frozen=True, slots=True)
class BreakerRecovered:
    """Emitted when a half-open probe succeeds and the breaker returns to ``closed``."""

    name: str
    generation: int


BreakerEvent: TypeAlias = BreakerCreated | BreakerStateChanged | BreakerFailed | BreakerRecovered
"""Discriminated union of every event the dispatcher ships."""


EventHandler: TypeAlias = Callable[[BreakerEvent], None] | Callable[[BreakerEvent], Awaitable[None]]
"""Acceptable handler signatures: sync ``None``-returning or coroutine-returning.

The alias names the *erased* handler shape used inside the dispatcher's
internal storage. :meth:`EventDispatcher.register` is generic over the
specific event type ``E`` so callers can register handlers typed against
``E`` (e.g. ``BreakerCreated``); the dispatcher routes the right event
to each handler at fan-out time.
"""


_E = TypeVar("_E", bound="BreakerEvent")


class EventDispatcher:
    """Typed event-emitter for the circuit-breaker module.

    Sync handlers fire inline inside :meth:`dispatch`; async handlers are
    scheduled via :func:`asyncio.create_task` so callers see no extra
    latency. Handler exceptions never propagate to user code; they are
    caught (catch ``Exception``, never ``BaseException``) and routed to
    the configured :class:`StoreObserver`.

    The dispatcher is async-only; sync workflows that need event
    subscription should use the registry's sync wrappers (none ship
    today; the rewrite is async-only).

    Examples
    --------
    >>> dispatcher = EventDispatcher()
    >>> received = []
    >>> unsub = dispatcher.register(BreakerCreated, lambda evt: received.append(evt.name))
    >>> import asyncio
    >>> asyncio.run(dispatcher.dispatch(BreakerCreated(name='x', config_repr='cfg')))
    >>> received
    ['x']
    >>> unsub()
    """

    __slots__ = ("_handler_timeout_seconds", "_handlers", "_observer", "_pending")

    def __init__(
        self,
        *,
        observer: StoreObserver | None = None,
        handler_timeout_seconds: float = 5.0,
    ) -> None:
        # Internal storage is loose-typed (``type[Any]`` keys, ``Callable[..., ...]``
        # values) because different event subtypes share the dispatcher; the
        # public ``register`` surface is generic over ``E`` so call-site users
        # get type-safe handler signatures. The runtime invariant that the
        # dispatcher only invokes a handler on instances of its registered
        # event type keeps the structural-erasure step safe.
        self._handlers: dict[
            type,
            list[Callable[..., None] | Callable[..., Awaitable[None]]],
        ] = {}
        self._observer: StoreObserver = observer if observer is not None else NoOpObserver()
        self._pending: set[asyncio.Task[None]] = set()
        self._handler_timeout_seconds = handler_timeout_seconds

    def register(
        self,
        event_type: type[_E],
        handler: Callable[[_E], None] | Callable[[_E], Awaitable[None]],
    ) -> Callable[[], None]:
        """Subscribe ``handler`` to ``event_type``; returns an unsubscribe callable.

        ``register`` is generic over ``E`` so callers can register handlers
        typed against the specific event subclass (e.g.
        ``Callable[[BreakerCreated], None]``); the dispatcher routes the
        right event to each handler at fan-out time. The unsubscribe
        callable is idempotent.
        """
        bucket = self._handlers.setdefault(event_type, [])
        bucket.append(handler)

        def _unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                bucket.remove(handler)

        return _unsubscribe

    async def dispatch(self, event: BreakerEvent) -> None:
        """Fan ``event`` out to every registered handler.

        Sync handlers run inline; async handlers are scheduled via
        :func:`asyncio.create_task` and tracked so :meth:`aclose` can
        await them at shutdown.
        """
        handlers = list(self._handlers.get(type(event), ()))
        for handler in handlers:
            if inspect.iscoroutinefunction(handler):
                task = asyncio.create_task(self._run_async(handler, event))
                self._pending.add(task)
                task.add_done_callback(self._pending.discard)
            else:
                self._run_sync(handler, event)

    def _run_sync(self, handler: EventHandler, event: BreakerEvent) -> None:
        """Invoke a sync handler, isolating its exceptions."""
        try:
            result = handler(event)
        except Exception as exc:  # noqa: BLE001 -- intentional handler isolation
            self._observer.on_error(op="hook_dispatch", name=event.name, exc=exc)
            return
        if isinstance(result, Awaitable):
            # Caller registered a coroutine-returning callable but
            # ``inspect.iscoroutinefunction`` missed it (e.g. ``functools.partial``
            # over an async function). Schedule the awaitable defensively.
            task = asyncio.create_task(self._await_safely(result, event))
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)

    async def _run_async(
        self,
        handler: Callable[[BreakerEvent], Awaitable[None]],
        event: BreakerEvent,
    ) -> None:
        """Invoke an async handler, isolating its exceptions and capping its runtime."""
        try:
            async with asyncio.timeout(self._handler_timeout_seconds):
                await handler(event)
        except Exception as exc:  # noqa: BLE001 -- intentional handler isolation
            self._observer.on_error(op="hook_dispatch", name=event.name, exc=exc)

    async def _await_safely(
        self,
        awaitable: Awaitable[None],
        event: BreakerEvent,
    ) -> None:
        """Drain an awaitable produced by a sync handler that returned a coroutine."""
        try:
            async with asyncio.timeout(self._handler_timeout_seconds):
                await awaitable
        except Exception as exc:  # noqa: BLE001 -- intentional handler isolation
            self._observer.on_error(op="hook_dispatch", name=event.name, exc=exc)

    async def aclose(self) -> None:
        """Wait for every outstanding async handler task to complete."""
        if not self._pending:
            return
        await asyncio.gather(*self._pending, return_exceptions=True)
        self._pending.clear()
