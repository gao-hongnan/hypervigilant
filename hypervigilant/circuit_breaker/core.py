"""Public ``circuit_breaker(...)`` factory for the hypervigilant circuit-breaker module.

This is the only call site users typically need. It constructs a fully
initialised :class:`AsyncBreakerRegistry` with sensible defaults plus
caller-supplied tuning knobs and event hooks. The factory signature is
bit-identical to the legacy purgatory-backed wrapper that PR 5
replaces — the same positional and keyword argument names with the same
defaults — so existing call sites do not churn (FR-011).

The ``mode`` parameter survives for source compatibility with callers
that previously passed ``mode="async"``; only the async path is
implemented post-rewrite (Decision 3 dropped the sync tree). Passing
``mode="sync"`` raises :exc:`ValueError`.

References
----------
- FR-011 (factory signature unchanged).
- FR-012 (event names dropped the ``Circuit`` prefix).
- FR-015 (vendor deletion in this PR).
- Decisions 3 (async-only), 9 (Registry naming), 12 (event names).
"""

import inspect
from collections.abc import Callable, Sequence
from typing import Any, Literal

from hypervigilant.circuit_breaker.config import BreakerConfig
from hypervigilant.circuit_breaker.events import (
    BreakerCreated,
    BreakerEvent,
    BreakerFailed,
    BreakerRecovered,
    BreakerStateChanged,
)
from hypervigilant.circuit_breaker.runtime.asyncio import AsyncBreakerRegistry
from hypervigilant.circuit_breaker.stores.base import BreakerStore

__all__ = ["circuit_breaker"]


_LEGACY_EVENT_NAMES: dict[type[BreakerEvent], str] = {
    BreakerCreated: "circuit_breaker_created",
    BreakerStateChanged: "state_changed",
    BreakerFailed: "failed",
    BreakerRecovered: "recovered",
}


type BreakerHook = Callable[[BreakerEvent], None] | Callable[[str, str, BreakerEvent], None]


def _legacy_event_type_str(event: BreakerEvent) -> str:
    """Map a typed :class:`BreakerEvent` to its legacy purgatory event name."""
    return _LEGACY_EVENT_NAMES.get(type(event), type(event).__name__)


def _adapt_hook(
    hook: Callable[..., None],
) -> Callable[[BreakerEvent], None]:
    """Wrap a legacy 3-arg hook ``(name, event_type, event)`` as a 1-arg hook.

    Pre-rewrite consumers passed ``def hook(name: str, event_type: str,
    event: object) -> None``. The native dispatcher calls handlers with a
    single ``BreakerEvent`` argument. Without arity detection a legacy hook
    raises ``TypeError`` on every dispatch; the dispatcher's exception
    isolation routes that error to the observer and the caller sees zero
    telemetry. This adapter detects positional arity via :mod:`inspect`
    and wraps 3-arg hooks transparently; 1-arg hooks pass through.
    """
    try:
        sig = inspect.signature(hook)
    except (TypeError, ValueError):
        # Unintrospectable callable (some C extensions); assume it accepts
        # a single typed event.
        return hook
    positional = [
        param
        for param in sig.parameters.values()
        if param.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    if len(positional) >= 3:
        legacy: Callable[..., None] = hook

        def _wrapped(event: BreakerEvent) -> None:
            legacy(event.name, _legacy_event_type_str(event), event)

        return _wrapped
    return hook


def circuit_breaker(
    mode: Literal["async"] = "async",
    *,
    threshold: int = 5,
    ttl: float = 30.0,
    exclude: Sequence[type[BaseException]] | None = None,
    hooks: Sequence[BreakerHook] | None = None,
    uow: BreakerStore | None = None,
) -> AsyncBreakerRegistry:
    """Construct an :class:`AsyncBreakerRegistry` ready for use.

    Parameters
    ----------
    mode
        Always ``"async"`` post-rewrite (Decision 3 dropped the sync
        tree). Kept for source-compatibility with the legacy wrapper.
    threshold
        Failure threshold; ``BreakerConfig(threshold=...)``.
    ttl
        Open-window duration in seconds.
    exclude
        Exception types that MUST NOT count as failures.
    hooks
        Iterable of sync handlers subscribed to every
        :class:`BreakerEvent`. Each hook fires on every event type --
        callers needing fine-grained subscription should use
        :meth:`AsyncBreakerRegistry.on` directly.
    uow
        Storage backend. Defaults to a process-local
        :class:`InMemoryStore` (constructed by the registry). Pass a
        :class:`RedisStore` for multi-process state.

    Returns
    -------
    AsyncBreakerRegistry
        Initialised registry. Caller MUST ``await registry.initialize()``
        before first use when ``uow`` is a :class:`RedisStore`.

    Raises
    ------
    ValueError
        If ``mode != "async"`` (sync support was removed in the rewrite).

    Examples
    --------
    >>> registry = circuit_breaker(threshold=3, ttl=10.0)
    >>> registry.__class__.__name__
    'AsyncBreakerRegistry'
    """
    del mode  # narrowed to Literal["async"] at type-check time; runtime no-op.
    config = BreakerConfig(
        threshold=threshold,
        ttl=ttl,
        exclude=tuple(exclude) if exclude is not None else (),
    )
    registry = AsyncBreakerRegistry(default_config=config, store=uow)
    if hooks:
        # Each user hook subscribes to every event type so legacy callers
        # that passed a single observer get notified of every transition,
        # mirroring the vendored ``add_listener`` semantics.
        event_classes: tuple[type[BreakerEvent], ...] = (
            BreakerCreated,
            BreakerStateChanged,
            BreakerFailed,
            BreakerRecovered,
        )
        for hook in hooks:
            adapted: Callable[[Any], None] = _adapt_hook(hook)
            for event_class in event_classes:
                registry.on(event_class, adapted)
    return registry
