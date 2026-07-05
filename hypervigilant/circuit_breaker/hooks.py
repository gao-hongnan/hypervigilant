"""StoreObserver Protocol, NoOpObserver default, and HookFn type alias.

Two surfaces ship in this module:

* :class:`StoreObserver` -- structural Protocol the Redis-backed store and
  the registry call into for telemetry hooks. The four methods correspond
  to the four observable events: a successful call (with duration), an
  error inside a store operation, a Decision the store returned, and a
  storage-failure fallback. :class:`NoOpObserver` is the safe default that
  swallows every call.
* :data:`HookFn` -- type alias for user-registered event handlers. Accepts
  both synchronous handlers (``Callable[[BreakerEvent], None]``) and
  coroutine-returning handlers
  (``Callable[[BreakerEvent], Awaitable[None]]``). The runtime layer
  schedules async handlers via :func:`asyncio.create_task` after the
  user's coroutine returns.

References
----------
- FR-016 (StoreObserver Protocol contract).
- Decision 8 (hook scheduling consumes Observer).

Examples
--------
>>> obs = NoOpObserver()
>>> obs.on_call(op='acquire', name='svc', duration_ms=1.2) is None
True
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Protocol, runtime_checkable

from hypervigilant.circuit_breaker.config import StorageFailurePolicy
from hypervigilant.circuit_breaker.policy import Decision
from hypervigilant.circuit_breaker.state import Snapshot

__all__ = ["HookFn", "LoggingObserver", "NoOpObserver", "StoreObserver"]


type HookFn = Callable[[object], None] | Callable[[object], Awaitable[None]]
"""Type alias for user-registered event handlers.

Accepts both synchronous and asynchronous (coroutine-returning) callables.
The dispatch layer (PR 4 ``EventDispatcher``) inspects each handler at
registration time via :func:`inspect.iscoroutinefunction` and schedules
async handlers post-``__aexit__``.

The argument is typed as ``object`` rather than a concrete event type so
PR 4 can introduce ``BreakerEvent`` without breaking this alias's identity;
runtime dispatch narrows via ``isinstance`` checks.
"""


@runtime_checkable
class StoreObserver(Protocol):
    """Structural Protocol for store-level telemetry hooks (FR-016).

    The Redis store and the runtime layer call into the four methods below
    at the corresponding observable events. Implementations MUST treat every
    call as advisory; raising from any method MUST NOT propagate to user
    code -- the dispatch boundary catches :class:`Exception` (never
    :class:`BaseException`) and emits its own ``on_error`` follow-up.

    Notes
    -----
    The Protocol is :func:`@runtime_checkable <typing.runtime_checkable>`;
    contract tests can assert ``isinstance(custom_observer, StoreObserver)``
    even when the implementer does not subclass anything.

    Examples
    --------
    >>> isinstance(NoOpObserver(), StoreObserver)
    True
    """

    def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
        """Record a successful store operation timing."""
        ...

    def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
        """Record an exception observed inside a store operation."""
        ...

    def on_decision(self, *, name: str, snapshot: Snapshot, decision: Decision) -> None:
        """Record the Decision returned by ``acquire``."""
        ...

    def on_storage_failure(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        fell_back_to: StorageFailurePolicy,
    ) -> None:
        """Record a storage-layer fallback (FAIL_STATIC / FAIL_OPEN / FAIL_CLOSED)."""
        ...


class NoOpObserver:
    """Default :class:`StoreObserver` implementation -- every method is a no-op.

    The registry wires this up unless the caller supplies their own
    observer (e.g. the opt-in ``LoggingObserver`` shipping in a follow-up).

    Examples
    --------
    >>> NoOpObserver().on_call(op='acquire', name='svc', duration_ms=0.0) is None
    True
    """

    __slots__ = ()

    def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
        """Drop the timing event (no-op)."""
        del op, name, duration_ms

    def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
        """Drop the error event (no-op)."""
        del op, name, exc

    def on_decision(self, *, name: str, snapshot: Snapshot, decision: Decision) -> None:
        """Drop the decision event (no-op)."""
        del name, snapshot, decision

    def on_storage_failure(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        fell_back_to: StorageFailurePolicy,
    ) -> None:
        """Drop the fallback event (no-op)."""
        del op, name, exc, fell_back_to


class LoggingObserver:
    """Stdlib-:mod:`logging`-backed :class:`StoreObserver` for opt-in observability.

    The default registry wires :class:`NoOpObserver`, which silently drops
    every telemetry call. ``LoggingObserver`` ships as the recommended
    starting point for SREs who want visibility without pulling in
    Prometheus / Datadog / OpenTelemetry. Construct with a logger name and
    optional level overrides; pass to
    :class:`AsyncBreakerRegistry(observer=...)`.

    Parameters
    ----------
    logger_name
        Name of the :class:`logging.Logger` to emit through. Default
        ``"hypervigilant.circuit_breaker"``.
    call_level
        Logging level for ``on_call`` (per-operation timings). Default
        :data:`logging.DEBUG` -- timings are noisy.
    error_level
        Logging level for ``on_error``. Default :data:`logging.WARNING`.
    storage_failure_level
        Logging level for ``on_storage_failure``. Default
        :data:`logging.ERROR` -- storage failures are page-worthy.
    decision_level
        Logging level for ``on_decision``. Default :data:`logging.DEBUG`.

    Examples
    --------
    >>> import logging
    >>> obs = LoggingObserver(logger_name="my.app.cb")
    >>> isinstance(obs, StoreObserver)
    True
    """

    __slots__ = (
        "_call_level",
        "_decision_level",
        "_error_level",
        "_logger",
        "_storage_failure_level",
    )

    def __init__(
        self,
        *,
        logger_name: str = "hypervigilant.circuit_breaker",
        call_level: int = logging.DEBUG,
        error_level: int = logging.WARNING,
        storage_failure_level: int = logging.ERROR,
        decision_level: int = logging.DEBUG,
    ) -> None:
        self._logger = logging.getLogger(logger_name)
        self._call_level = call_level
        self._error_level = error_level
        self._storage_failure_level = storage_failure_level
        self._decision_level = decision_level

    def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
        """Log the operation timing at ``call_level``."""
        self._logger.log(
            self._call_level,
            "circuit_breaker.call",
            extra={"op": op, "circuit": name, "duration_ms": duration_ms},
        )

    def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
        """Log the store-side error at ``error_level``."""
        self._logger.log(
            self._error_level,
            "circuit_breaker.error op=%s circuit=%s exc=%r",
            op,
            name,
            exc,
            extra={"op": op, "circuit": name, "exception_type": type(exc).__name__},
        )

    def on_decision(self, *, name: str, snapshot: Snapshot, decision: Decision) -> None:
        """Log the projected Decision at ``decision_level``."""
        self._logger.log(
            self._decision_level,
            "circuit_breaker.decision",
            extra={
                "circuit": name,
                "state": snapshot.state,
                "generation": snapshot.generation,
                "decision": type(decision).__name__,
            },
        )

    def on_storage_failure(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        fell_back_to: StorageFailurePolicy,
    ) -> None:
        """Log the storage fallback at ``storage_failure_level``."""
        self._logger.log(
            self._storage_failure_level,
            "circuit_breaker.storage_failure op=%s circuit=%s fallback=%s exc=%r",
            op,
            name,
            fell_back_to.value,
            exc,
            extra={
                "op": op,
                "circuit": name,
                "fallback": fell_back_to.value,
                "exception_type": type(exc).__name__,
            },
        )
