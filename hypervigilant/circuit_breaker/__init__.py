"""Native hypervigilant circuit-breaker module (DRAFT-0001 rewrite).

The public surface is intentionally small. The recommended entry point is
:func:`circuit_breaker`, which constructs a fully wired
:class:`AsyncBreakerRegistry`. Callers who want finer control can construct
the registry directly with a custom :class:`BreakerStore` (one of
:class:`InMemoryStore` or :class:`RedisStore`) and a :class:`BreakerConfig`.

Internal building blocks (the :class:`Decision` ADT, ``EventDispatcher``,
``HookFn``, the ``Snapshot`` and ``BreakerState`` value-types, and the
clock variants) remain importable from their submodules but are NOT part
of the blessed public API. Rely only on the names listed in ``__all__``.

Examples
--------
>>> from hypervigilant.circuit_breaker import BreakerConfig
>>> BreakerConfig().threshold
5
"""

from .clock import (
    Clock,
    FakeClock,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    MonotonicClock,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    SystemClock,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)
from .config import BreakerConfig, StorageFailurePolicy
from .core import circuit_breaker
from .errors import (
    BreakerOpenError,
    CircuitStorageError,
)
from .events import (
    BreakerCreated,
    BreakerEvent,
    BreakerFailed,
    BreakerRecovered,
    BreakerStateChanged,
    EventDispatcher,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    EventHandler,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)
from .hooks import (
    HookFn,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    NoOpObserver,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    StoreObserver,
)
from .policy import (
    AllowCall,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    Decision,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    ProbeCall,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    RejectCall,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)
from .runtime import (
    AsyncBreakerRegistry,
    AsyncCircuitBreaker,
)
from .state import (
    BreakerState,  # noqa: F401  # pyright: ignore[reportUnusedImport]
    BreakerStatus,
    Snapshot,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)
from .stores import BreakerStore, InMemoryStore, RedisStore

__all__ = [
    "AsyncBreakerRegistry",
    "AsyncCircuitBreaker",
    "BreakerConfig",
    "BreakerCreated",
    "BreakerEvent",
    "BreakerFailed",
    "BreakerOpenError",
    "BreakerRecovered",
    "BreakerStateChanged",
    "BreakerStatus",
    "BreakerStore",
    "CircuitStorageError",
    "Clock",
    "InMemoryStore",
    "RedisStore",
    "StorageFailurePolicy",
    "StoreObserver",
    "circuit_breaker",
]
