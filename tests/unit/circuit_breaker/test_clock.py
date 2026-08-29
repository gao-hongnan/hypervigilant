"""Tests for clock implementations, hooks contract, and module __all__ exports.

Completes the Wave-1 foundation test surface: covers FR-016 (StoreObserver
Protocol contract + NoOpObserver default + HookFn type alias) and the public
``__all__`` export check that anchors every later PR's import list.

Notes
-----
``StoreObserver`` is :func:`@runtime_checkable
<typing.runtime_checkable>` so contract tests can assert structural
conformance. ``NoOpObserver`` is the safe default the registry wires up
when no observer is supplied.
"""

import asyncio
import inspect
import time
from collections.abc import Awaitable, Callable
from typing import get_type_hints

import pytest

import hypervigilant.circuit_breaker as module
from hypervigilant.circuit_breaker import (
    AllowCall,
    BreakerConfig,
    BreakerOpenError,
    BreakerStatus,
    CircuitStorageError,
    Clock,
    Decision,  # noqa: F401 -- imported to assert presence in __all__
    FakeClock,
    HookFn,  # noqa: F401 -- imported to assert presence in __all__
    MonotonicClock,
    NoOpObserver,
    ProbeCall,
    RejectCall,
    Snapshot,
    StorageFailurePolicy,
    StoreObserver,
    SystemClock,
)
from hypervigilant.circuit_breaker.policy import AllowCall as PolicyAllowCall


@pytest.mark.unit
def test_monotonic_clock_invariant() -> None:
    """MonotonicClock readings are non-decreasing across consecutive calls."""
    clock = MonotonicClock()

    readings = [clock.now() for _ in range(20)]

    assert readings == sorted(readings)


@pytest.mark.unit
def test_monotonic_clock_advances_with_real_sleep() -> None:
    """MonotonicClock advances across a small ``time.sleep`` interval."""
    clock = MonotonicClock()

    t0 = clock.now()
    time.sleep(0.01)
    t1 = clock.now()

    assert t1 > t0


@pytest.mark.unit
def test_system_clock_returns_positive_float() -> None:
    """SystemClock returns the current epoch second as a positive float."""
    clock = SystemClock()

    value = clock.now()

    assert isinstance(value, float)
    assert value > 0.0


@pytest.mark.unit
def test_fake_clock_isolated_from_real_time() -> None:
    """FakeClock readings stay constant across real-time delays."""
    clock = FakeClock(now=42.0)

    initial = clock.now()
    time.sleep(0.01)
    final = clock.now()

    assert initial == final == pytest.approx(42.0)


@pytest.mark.unit
def test_clock_protocol_isinstance_check() -> None:
    """All three clock implementations satisfy the runtime-checkable Clock Protocol."""
    assert isinstance(SystemClock(), Clock)
    assert isinstance(MonotonicClock(), Clock)
    assert isinstance(FakeClock(), Clock)


@pytest.mark.unit
def test_noop_observer_methods_callable() -> None:
    """NoOpObserver implements every StoreObserver method and returns None."""
    observer = NoOpObserver()
    snapshot = Snapshot(name="x", state="closed", failure_count=0, opened_at=0.0, generation=0)
    decision: Decision = PolicyAllowCall()

    assert observer.on_call(op="acquire", name="x", duration_ms=1.0) is None
    assert observer.on_error(op="acquire", name="x", exc=RuntimeError("boom")) is None
    assert observer.on_decision(name="x", snapshot=snapshot, decision=decision) is None
    assert (
        observer.on_storage_failure(
            op="acquire",
            name="x",
            exc=RuntimeError("boom"),
            fell_back_to=StorageFailurePolicy.FAIL_OPEN,
        )
        is None
    )


@pytest.mark.unit
def test_store_observer_is_runtime_checkable_protocol() -> None:
    """A class implementing all four methods satisfies StoreObserver structurally."""

    class _CustomObserver:
        def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
            del op, name, duration_ms

        def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
            del op, name, exc

        def on_decision(self, *, name: str, snapshot: Snapshot, decision: Decision) -> None:
            del name, snapshot, decision

        def on_storage_failure(
            self,
            *,
            op: str,
            name: str,
            exc: BaseException,
            fell_back_to: StorageFailurePolicy,
        ) -> None:
            del op, name, exc, fell_back_to

    assert isinstance(_CustomObserver(), StoreObserver)


@pytest.mark.unit
def test_store_observer_runtime_check_rejects_partial_implementations() -> None:
    """A class missing a required method does NOT satisfy StoreObserver."""

    class _Partial:
        def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
            del op, name, duration_ms

    assert not isinstance(_Partial(), StoreObserver)


@pytest.mark.unit
def test_hook_fn_accepts_sync_handlers() -> None:
    """HookFn is satisfied by a plain ``Callable[[BreakerEvent], None]``."""
    from hypervigilant.circuit_breaker.hooks import HookFn as HookAlias

    def sync_handler(event: object) -> None:
        del event

    handler: HookAlias = sync_handler
    assert callable(handler)


@pytest.mark.unit
def test_hook_fn_accepts_async_handlers() -> None:
    """HookFn is satisfied by a coroutine-returning callable."""
    from hypervigilant.circuit_breaker.hooks import HookFn as HookAlias

    async def async_handler(event: object) -> None:
        del event
        await asyncio.sleep(0)

    handler: HookAlias = async_handler
    assert inspect.iscoroutinefunction(handler)


@pytest.mark.unit
def test_module_all_exports_are_importable() -> None:
    """Every name in ``__all__`` resolves on the package (smoke test).

    Replaces the previous tautology test that hand-listed the same set
    twice (in code and in test). The assertion that matters is that the
    blessed public surface is actually importable -- the membership of
    that surface is owned by ``__init__.py`` alone.
    """
    for name in module.__all__:
        assert hasattr(module, name), f"missing export: {name!r}"


@pytest.mark.unit
def test_module_top_level_imports_match_modules() -> None:
    """Sanity check: re-exports at the package root identify the same objects."""
    assert AllowCall is module.AllowCall
    assert BreakerConfig is module.BreakerConfig
    assert BreakerOpenError is module.BreakerOpenError
    assert BreakerStatus is module.BreakerStatus
    assert CircuitStorageError is module.CircuitStorageError
    assert Clock is module.Clock
    assert FakeClock is module.FakeClock
    assert MonotonicClock is module.MonotonicClock
    assert NoOpObserver is module.NoOpObserver
    assert ProbeCall is module.ProbeCall
    assert RejectCall is module.RejectCall
    assert Snapshot is module.Snapshot
    assert StorageFailurePolicy is module.StorageFailurePolicy
    assert StoreObserver is module.StoreObserver
    assert SystemClock is module.SystemClock


@pytest.mark.unit
def test_hookfn_alias_exists() -> None:
    """HookFn is publicly importable as a type alias."""
    from hypervigilant.circuit_breaker.hooks import HookFn as HookAlias

    # PEP 695 type aliases are TypeAliasType instances; we only assert the
    # alias is not None and is referenced from the public module.
    assert HookAlias is not None
    assert hasattr(module, "HookFn")


@pytest.mark.unit
def test_protocol_member_signatures_are_documented() -> None:
    """StoreObserver methods carry type annotations for FR-016 documentation."""
    expected_members = ("on_call", "on_error", "on_decision", "on_storage_failure")

    for member in expected_members:
        method = getattr(StoreObserver, member)
        annotations = get_type_hints(method)
        assert annotations, f"{member} missing type annotations"


@pytest.mark.unit
def test_callable_alias_imports_resolve() -> None:
    """Sanity: Callable / Awaitable are importable for downstream code."""

    def _sync(_evt: object) -> None:
        return None

    sync_alias: Callable[[object], None] = _sync
    assert callable(sync_alias)

    async def _coro(_evt: object) -> None:
        await asyncio.sleep(0)

    awaitable_alias: Callable[[object], Awaitable[None]] = _coro
    assert callable(awaitable_alias)
