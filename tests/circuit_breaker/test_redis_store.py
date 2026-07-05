"""Integration tests for ``RedisStore`` (PR 3 / task 3B).

Exercises the asymmetric Protocol shape end-to-end against testcontainers
Redis. Covers the happy-path mutation flow, the ``FAIL_STATIC`` fallback
modes (cache hit / miss with both secondary policies), and the NOSCRIPT
reload-and-retry path that fires when Redis is restarted mid-session.

References
----------
- FR-005 (asymmetric BreakerStore Protocol).
- FR-006 (Lua + EVALSHA + NOSCRIPT retry).
- FR-009 (FAIL_STATIC default + secondary policy).
- AC-002, AC-005, AC-009.
- EC-002, EC-006, EC-007.
"""

import asyncio
from typing import TYPE_CHECKING

import pytest

from hypervigilant.circuit_breaker import (
    AllowCall,
    BreakerStore,
    ProbeCall,
    RedisStore,
    RejectCall,
    Snapshot,
    StorageFailurePolicy,
)
from hypervigilant.circuit_breaker.config import CountingPolicy
from hypervigilant.circuit_breaker.errors import CircuitStorageError
from hypervigilant.circuit_breaker.policy import Decision

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


@pytest.fixture
async def store(redis_url: str) -> "AsyncGenerator[RedisStore]":
    """A ``RedisStore`` connected to the test container Redis."""
    instance = RedisStore.from_url(redis_url)
    await instance.initialize()
    yield instance
    await instance.aclose()


class _Capture:
    """Minimal capturing observer for the integration tests."""

    __slots__ = ("calls", "decisions", "errors", "fallbacks")

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, float]] = []
        self.errors: list[tuple[str, str, BaseException]] = []
        self.decisions: list[tuple[str, Snapshot, Decision]] = []
        self.fallbacks: list[tuple[str, str, BaseException, StorageFailurePolicy]] = []

    def on_call(self, *, op: str, name: str, duration_ms: float) -> None:
        self.calls.append((op, name, duration_ms))

    def on_error(self, *, op: str, name: str, exc: BaseException) -> None:
        self.errors.append((op, name, exc))

    def on_decision(self, *, name: str, snapshot: Snapshot, decision: Decision) -> None:
        self.decisions.append((name, snapshot, decision))

    def on_storage_failure(
        self,
        *,
        op: str,
        name: str,
        exc: BaseException,
        fell_back_to: StorageFailurePolicy,
    ) -> None:
        self.fallbacks.append((op, name, exc, fell_back_to))


# ---------------------------------------------------------------------------
# Construction-time validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_secondary_policy_fail_static_is_rejected_at_construction() -> None:
    """``secondary_policy`` cannot be ``FAIL_STATIC`` (would recurse on cold cache)."""
    from redis.asyncio import Redis

    with pytest.raises(ValueError, match="secondary_policy"):
        RedisStore(
            client=Redis(),
            secondary_policy=StorageFailurePolicy.FAIL_STATIC,
        )


@pytest.mark.unit
def test_invalid_cache_size_raises() -> None:
    """``cache_size < 1`` is rejected at construction."""
    from redis.asyncio import Redis

    with pytest.raises(ValueError, match="cache_size"):
        RedisStore(client=Redis(), cache_size=0)


@pytest.mark.unit
def test_invalid_request_timeout_raises() -> None:
    """``request_timeout_seconds <= 0`` is rejected at construction."""
    from redis.asyncio import Redis

    with pytest.raises(ValueError, match="request_timeout_seconds"):
        RedisStore(client=Redis(), request_timeout_seconds=0.0)


@pytest.mark.unit
async def test_request_timeout_raises_circuit_storage_error_on_slow_client() -> None:
    """H5 regression: a slow Redis client raises ``CircuitStorageError`` within the timeout window.

    The breaker must not contribute to the very latency it is meant to
    prevent. Without ``asyncio.timeout`` a hung TCP connection can block
    every protected call for tens of seconds.
    """
    import asyncio as _asyncio

    class _SlowClient:
        async def script_load(self, source: str) -> bytes:  # noqa: ARG002
            await _asyncio.sleep(10.0)
            return b"sha"

        async def evalsha(self, *_args: object, **_kwargs: object) -> object:
            await _asyncio.sleep(10.0)
            return []

        async def aclose(self) -> None:
            pass

    store = RedisStore(client=_SlowClient(), request_timeout_seconds=0.05)  # type: ignore[arg-type]
    elapsed_start = _asyncio.get_event_loop().time()
    with pytest.raises(CircuitStorageError):
        await store.acquire(
            "svc",
            threshold=5,
            ttl_seconds=30.0,
            lease_seconds=5.0,
        )
    elapsed = _asyncio.get_event_loop().time() - elapsed_start
    assert elapsed < 1.0, (
        f"Expected fast failure within request_timeout_seconds=0.05; "
        f"actually waited {elapsed:.3f}s. Timeout not honoured."
    )


@pytest.mark.unit
async def test_from_client_does_not_close_caller_supplied_client() -> None:
    """H3 regression: ``from_client`` defaults to ``owns_client=False`` so the
    store's ``aclose`` does NOT call ``aclose`` on the caller-supplied client.

    Sharing a Redis client across multiple components (cache, rate-limiter,
    circuit breaker) is a normal pattern; the store must not pull the rug
    out from under the other consumers when its lifespan ends.
    """
    aclose_calls: list[None] = []

    class _MockClient:
        async def aclose(self) -> None:
            aclose_calls.append(None)

    client = _MockClient()
    store = RedisStore.from_client(client)  # type: ignore[arg-type]
    await store.aclose()
    assert aclose_calls == [], (
        f"from_client default (owns_client=False) must NOT close the supplied "
        f"client; aclose was called {len(aclose_calls)} time(s)."
    )


@pytest.mark.unit
async def test_from_client_owns_client_true_closes_supplied_client() -> None:
    """H3: ``from_client(owns_client=True)`` does close the supplied client."""
    aclose_calls: list[None] = []

    class _MockClient:
        async def aclose(self) -> None:
            aclose_calls.append(None)

    client = _MockClient()
    store = RedisStore.from_client(client, owns_client=True)  # type: ignore[arg-type]
    await store.aclose()
    assert aclose_calls == [None]


@pytest.mark.unit
async def test_from_url_closes_owned_client() -> None:
    """H3: ``from_url`` sets ``owns_client=True`` so ``aclose`` closes the pool."""
    aclose_calls: list[None] = []

    class _MockClient:
        async def aclose(self) -> None:
            aclose_calls.append(None)

    # Construct via __init__ directly with owns_client=True (mirrors what
    # from_url does) -- avoids the redis.asyncio.Redis import path.
    store = RedisStore(client=_MockClient(), owns_client=True)  # type: ignore[arg-type]
    await store.aclose()
    assert aclose_calls == [None]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_redis_store_implements_protocol(store: RedisStore) -> None:
    """``isinstance`` recognises ``RedisStore`` as a ``BreakerStore``."""
    assert isinstance(store, BreakerStore)


@pytest.mark.integration
async def test_acquire_on_fresh_circuit_returns_allow(store: RedisStore) -> None:
    """A circuit Redis has never seen returns AllowCall (state=closed)."""
    decision, _ = await store.acquire(
        "fresh",
        threshold=5,
        ttl_seconds=30.0,
        lease_seconds=5.0,
    )
    assert isinstance(decision, AllowCall)


@pytest.mark.integration
async def test_record_failure_increments_count_and_persists(store: RedisStore) -> None:
    """A single failure persists into Redis and is observable via peek."""
    snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    assert snap.state == "closed"
    assert snap.failure_count == 1
    seen = await store.peek("svc")
    assert seen is not None
    assert seen.failure_count == 1


@pytest.mark.integration
async def test_threshold_crossing_transitions_to_opened_with_generation_increment(
    store: RedisStore,
) -> None:
    """Crossing the threshold flips state to opened with generation+=1 atomically."""
    pre = await store.peek("svc") or Snapshot(
        name="svc",
        state="closed",
        failure_count=0,
        opened_at=0.0,
        generation=0,
    )
    for _ in range(4):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    final = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    assert final.state == "opened"
    assert final.failure_count == 5
    assert final.generation == pre.generation + 1


@pytest.mark.integration
async def test_record_success_resets_count_in_closed_state(store: RedisStore) -> None:
    """Success in closed state resets failure_count to zero."""
    await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    snap = await store.record_success("svc")
    assert snap.state == "closed"
    assert snap.failure_count == 0


@pytest.mark.integration
async def test_acquire_after_ttl_returns_probe_and_transitions_state(
    store: RedisStore,
) -> None:
    """After TTL elapses, acquire returns ProbeCall and persists half_opened."""
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=0.5)
    import asyncio

    await asyncio.sleep(0.6)
    decision, _ = await store.acquire(
        "svc",
        threshold=5,
        ttl_seconds=0.5,
        lease_seconds=5.0,
    )
    assert isinstance(decision, ProbeCall)
    snap = await store.peek("svc")
    assert snap is not None
    assert snap.state == "half_opened"


@pytest.mark.integration
async def test_record_success_during_half_open_closes_breaker(
    store: RedisStore,
) -> None:
    """A successful probe transitions half_opened to closed with generation+=1."""
    import asyncio

    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=0.5)
    await asyncio.sleep(0.6)
    await store.acquire("svc", threshold=5, ttl_seconds=0.5, lease_seconds=5.0)
    pre = await store.peek("svc")
    assert pre is not None
    assert pre.state == "half_opened"
    snap = await store.record_success("svc")
    assert snap.state == "closed"
    assert snap.failure_count == 0
    assert snap.generation == pre.generation + 1


@pytest.mark.integration
async def test_reset_clears_named_circuit(store: RedisStore) -> None:
    """``reset(name)`` deletes both state and probe keys."""
    await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    await store.reset("svc")
    seen = await store.peek("svc")
    assert seen is None


# ---------------------------------------------------------------------------
# FAIL_STATIC behaviour (monkey-patched to avoid disturbing the autouse fixture)
# ---------------------------------------------------------------------------


def _install_failing_evalsha(store: RedisStore) -> None:
    """Replace ``store._client.evalsha`` with a coroutine that raises ConnectionError.

    Used by the FAIL_STATIC tests to simulate Redis becoming unreachable
    after the cache has been warmed by an earlier successful call. Stopping
    the test-container directly disrupts the directory-level autouse
    ``clean_redis`` fixture that runs in test teardown.
    """
    from redis.exceptions import ConnectionError as RedisConnectionError

    async def _raise(*_args: object, **_kwargs: object) -> object:
        msg = "Simulated Redis outage"
        raise RedisConnectionError(msg)

    store._client.evalsha = _raise  # noqa: SLF001 -- test-only injection


@pytest.mark.integration
async def test_fail_static_cached_closed_allows_during_redis_outage(
    store: RedisStore,
) -> None:
    """Cached state==closed permits the call while emitting a structured warning."""
    observer = _Capture()
    store._observer = observer  # noqa: SLF001 -- swap observer to capture fallback
    await store.record_success("svc")
    _install_failing_evalsha(store)
    decision, _ = await store.acquire(
        "svc",
        threshold=5,
        ttl_seconds=30.0,
        lease_seconds=5.0,
    )
    assert isinstance(decision, AllowCall)
    assert any(fb[3] is StorageFailurePolicy.FAIL_STATIC for fb in observer.fallbacks)


@pytest.mark.integration
async def test_fail_static_cached_open_denies_during_redis_outage(
    store: RedisStore,
) -> None:
    """Cached state==opened denies via RejectCall while Redis is unreachable."""
    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
    pre = await store.peek("svc")
    assert pre is not None
    assert pre.state == "opened"
    _install_failing_evalsha(store)
    decision, _ = await store.acquire(
        "svc",
        threshold=5,
        ttl_seconds=30.0,
        lease_seconds=5.0,
    )
    assert isinstance(decision, RejectCall)


@pytest.mark.integration
async def test_fail_static_cold_cache_falls_through_to_secondary_open(
    redis_url: str,
) -> None:
    """An empty cache + Redis outage falls through to FAIL_OPEN by default."""
    observer = _Capture()
    store = RedisStore.from_url(redis_url, observer=observer)
    await store.initialize()
    _install_failing_evalsha(store)
    try:
        decision, _ = await store.acquire(
            "never-seen",
            threshold=5,
            ttl_seconds=30.0,
            lease_seconds=5.0,
        )
        assert isinstance(decision, AllowCall)
        assert any(fb[3] is StorageFailurePolicy.FAIL_OPEN for fb in observer.fallbacks)
    finally:
        await store.aclose()


@pytest.mark.integration
async def test_fail_static_cold_cache_with_secondary_closed_denies(
    redis_url: str,
) -> None:
    """An empty cache + Redis outage + ``secondary=FAIL_CLOSED`` denies the call."""
    observer = _Capture()
    store = RedisStore.from_url(
        redis_url,
        secondary_policy=StorageFailurePolicy.FAIL_CLOSED,
        observer=observer,
    )
    await store.initialize()
    _install_failing_evalsha(store)
    try:
        decision, _ = await store.acquire(
            "never-seen",
            threshold=5,
            ttl_seconds=30.0,
            lease_seconds=5.0,
        )
        assert isinstance(decision, RejectCall)
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# B1: failure_policy primary parameter (FAIL_OPEN / FAIL_CLOSED branches)
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_failure_policy_fail_open_acquire_returns_allow_during_outage(
    redis_url: str,
) -> None:
    """``failure_policy=FAIL_OPEN`` allows the call without consulting the cache.

    Even when a cached ``opened`` snapshot would have caused FAIL_STATIC to
    return ``RejectCall``, FAIL_OPEN unconditionally returns ``AllowCall``.
    """
    observer = _Capture()
    store = RedisStore.from_url(
        redis_url,
        failure_policy=StorageFailurePolicy.FAIL_OPEN,
        observer=observer,
    )
    await store.initialize()
    try:
        # Seed cache with an opened snapshot so we can prove FAIL_OPEN
        # bypasses the cached projection.
        for _ in range(5):
            await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
        cached = await store.peek("svc")
        assert cached is not None
        assert cached.state == "opened"

        _install_failing_evalsha(store)
        decision, _ = await store.acquire(
            "svc",
            threshold=5,
            ttl_seconds=30.0,
            lease_seconds=5.0,
        )
        assert isinstance(decision, AllowCall)
        assert any(fb[3] is StorageFailurePolicy.FAIL_OPEN for fb in observer.fallbacks)
    finally:
        await store.aclose()


@pytest.mark.integration
async def test_failure_policy_fail_closed_acquire_returns_reject_during_outage(
    redis_url: str,
) -> None:
    """``failure_policy=FAIL_CLOSED`` rejects the call without consulting the cache.

    Even when a cached ``closed`` snapshot would have caused FAIL_STATIC to
    return ``AllowCall``, FAIL_CLOSED unconditionally returns ``RejectCall``.
    """
    observer = _Capture()
    store = RedisStore.from_url(
        redis_url,
        failure_policy=StorageFailurePolicy.FAIL_CLOSED,
        observer=observer,
    )
    await store.initialize()
    try:
        await store.record_success("svc")
        cached = await store.peek("svc")
        assert cached is not None
        assert cached.state == "closed"

        _install_failing_evalsha(store)
        decision, _ = await store.acquire(
            "svc",
            threshold=5,
            ttl_seconds=30.0,
            lease_seconds=5.0,
        )
        assert isinstance(decision, RejectCall)
        assert any(fb[3] is StorageFailurePolicy.FAIL_CLOSED for fb in observer.fallbacks)
    finally:
        await store.aclose()


@pytest.mark.integration
async def test_failure_policy_fail_open_record_failure_returns_synthesized_snapshot(
    redis_url: str,
) -> None:
    """``failure_policy=FAIL_OPEN`` makes ``record_failure`` return a default closed
    snapshot on cold cache instead of raising ``CircuitStorageError``."""
    store = RedisStore.from_url(
        redis_url,
        failure_policy=StorageFailurePolicy.FAIL_OPEN,
    )
    await store.initialize()
    _install_failing_evalsha(store)
    try:
        snap = await store.record_failure(
            "never-seen",
            threshold=5,
            ttl_seconds=30.0,
        )
        assert snap.state == "closed"
        assert snap.failure_count == 0
    finally:
        await store.aclose()


@pytest.mark.integration
async def test_failure_policy_fail_closed_record_failure_returns_opened_snapshot(
    redis_url: str,
) -> None:
    """``failure_policy=FAIL_CLOSED`` makes ``record_failure`` return a synthesised
    opened snapshot on cold cache instead of raising ``CircuitStorageError``."""
    store = RedisStore.from_url(
        redis_url,
        failure_policy=StorageFailurePolicy.FAIL_CLOSED,
    )
    await store.initialize()
    _install_failing_evalsha(store)
    try:
        snap = await store.record_failure(
            "never-seen",
            threshold=5,
            ttl_seconds=30.0,
        )
        assert snap.state == "opened"
    finally:
        await store.aclose()


@pytest.mark.integration
async def test_acquire_with_stale_half_open_lease_reissues_probe(
    store: RedisStore,
) -> None:
    """H2 regression: a half-open breaker with an expired probe lease re-issues a probe.

    Simulates a probe coroutine that crashed before ``record_failure`` /
    ``record_success`` ran. Without the fix, ``acquire.lua`` had no
    ``state == 'half_opened'`` branch and the breaker stayed wedged in
    ``reject`` for ``key_ttl_seconds`` (24h default).
    """
    import asyncio

    for _ in range(5):
        await store.record_failure("svc", threshold=5, ttl_seconds=0.5)
    await asyncio.sleep(0.6)
    first, _ = await store.acquire(
        "svc",
        threshold=5,
        ttl_seconds=0.5,
        lease_seconds=0.2,
    )
    assert isinstance(first, ProbeCall)

    # Probe coroutine crashes: lease expires without record_*.
    await asyncio.sleep(0.3)
    second, _ = await store.acquire(
        "svc",
        threshold=5,
        ttl_seconds=0.5,
        lease_seconds=0.2,
    )
    assert isinstance(second, ProbeCall), "Stale half-open lease must re-issue the probe rather than wedge in reject."


# ---------------------------------------------------------------------------
# H8: peek distinguishes absent vs storage failure
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_peek_returns_none_for_absent_key_when_redis_healthy(
    store: RedisStore,
) -> None:
    """``peek`` returns ``None`` when Redis is reachable and the key does not exist."""
    assert await store.peek("never-touched") is None


@pytest.mark.integration
async def test_peek_raises_circuit_storage_error_on_outage_with_cold_cache(
    store: RedisStore,
) -> None:
    """H8 regression: ``peek`` MUST distinguish "no key" from "Redis unreachable, cache cold".

    Returning ``None`` for both makes monitoring lie -- a circuit that
    is actually opened in Redis but unreachable + uncached would appear
    closed in observability. The fix raises ``CircuitStorageError`` so
    the caller can detect the storage failure.
    """
    _install_failing_evalsha(store)
    # Replace hgetall too to simulate full outage.
    from redis.exceptions import ConnectionError as RedisConnectionError

    async def _fail_hgetall(*_args: object, **_kwargs: object) -> object:
        msg = "Simulated Redis outage during hgetall"
        raise RedisConnectionError(msg)

    store._client.hgetall = _fail_hgetall  # noqa: SLF001 -- test injection

    with pytest.raises(CircuitStorageError):
        await store.peek("never-cached")


@pytest.mark.integration
async def test_peek_returns_cached_snapshot_on_outage_when_cache_warm(
    store: RedisStore,
) -> None:
    """H8: ``peek`` returns the cached snapshot when Redis is unreachable but
    the snapshot is in the local TTL cache (graceful degradation).
    """
    from redis.exceptions import ConnectionError as RedisConnectionError

    await store.record_success("svc")
    cached_before = await store.peek("svc")
    assert cached_before is not None

    async def _fail_hgetall(*_args: object, **_kwargs: object) -> object:
        msg = "Simulated Redis outage during hgetall"
        raise RedisConnectionError(msg)

    store._client.hgetall = _fail_hgetall  # noqa: SLF001 -- test injection
    snap = await store.peek("svc")
    assert snap is not None
    assert snap.state == cached_before.state


@pytest.mark.integration
async def test_record_failure_during_outage_with_cold_cache_raises(
    redis_url: str,
) -> None:
    """``record_failure`` with no cached snapshot raises ``CircuitStorageError``."""
    store = RedisStore.from_url(redis_url)
    await store.initialize()
    _install_failing_evalsha(store)
    try:
        with pytest.raises(CircuitStorageError):
            await store.record_failure(
                "never-seen",
                threshold=5,
                ttl_seconds=30.0,
            )
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# NOSCRIPT reload-and-retry
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_noscript_error_triggers_reload_and_retry(
    redis_url: str,
) -> None:
    """``SCRIPT FLUSH`` drops the script cache; the next EVALSHA reloads + retries."""
    store = RedisStore.from_url(redis_url)
    await store.initialize()
    try:
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
        # Drop the Redis-side script cache to force the NOSCRIPT path.
        from redis.asyncio import Redis

        admin: object = Redis.from_url(redis_url)
        try:
            flush = getattr(admin, "script_flush", None)
            if flush is not None:
                await flush()
        finally:
            closer = getattr(admin, "aclose", None) or getattr(admin, "close", None)
            if closer is not None:
                await closer()
        snap = await store.record_failure("svc", threshold=5, ttl_seconds=30.0)
        assert snap.failure_count == 2
    finally:
        await store.aclose()


# ---------------------------------------------------------------------------
# Sliding-window counting on Redis (DRAFT-0002)
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_redis_sliding_trips_at_rate(redis_url: str) -> None:
    """A sliding breaker trips on Redis once the window fills past min_calls."""
    store = RedisStore.from_url(redis_url)
    await store.initialize()
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    try:
        for _ in range(9):
            snap = await store.record_failure("sliding", threshold=5, ttl_seconds=30.0, counting=policy)
            assert snap.state == "closed"
        snap = await store.record_failure("sliding", threshold=5, ttl_seconds=30.0, counting=policy)
        assert snap.state == "opened"
        assert snap.window is None  # opened: no active window
    finally:
        await store.aclose()


@pytest.mark.integration
async def test_redis_sliding_success_records_into_window(redis_url: str) -> None:
    """A success on Redis records into the sliding window without wiping it (EC-103)."""
    store = RedisStore.from_url(redis_url)
    await store.initialize()
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    try:
        await store.record_failure("svc", threshold=5, ttl_seconds=30.0, counting=policy)
        snap = await store.record_success("svc", counting=policy)
        assert snap.state == "closed"
        assert snap.window is not None
        assert snap.window.total == 2
        assert snap.window.failures == 1
    finally:
        await store.aclose()


@pytest.mark.integration
async def test_redis_sliding_concurrent_single_trip(redis_url: str) -> None:
    """1,000 concurrent record_failure calls produce exactly one trip (EC-107)."""
    store = RedisStore.from_url(redis_url)
    await store.initialize()
    policy = CountingPolicy("sliding_window", 10, 0.5, 10)
    try:
        before = await store.peek("blast")
        baseline = before.generation if before is not None else 0
        await asyncio.gather(
            *[store.record_failure("blast", threshold=5, ttl_seconds=30.0, counting=policy) for _ in range(1000)]
        )
        after = await store.peek("blast")
        assert after is not None
        assert after.state == "opened"
        assert after.generation == baseline + 1
    finally:
        await store.aclose()
