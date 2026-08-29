"""``RedisStore`` behaviour that needs no Redis: construction validation and client ownership.

Everything here is decided before a socket is opened -- constructor guards, the
request-timeout ceiling, and whether ``aclose()`` closes a client the caller supplied.
The end-to-end half (Lua, EVALSHA/NOSCRIPT, FAIL_STATIC fallback, sliding windows)
lives in ``tests/integration/circuit_breaker/test_redis_store.py``.

References
----------
- FR-005 (asymmetric BreakerStore Protocol).
- FR-009 (FAIL_STATIC default + secondary policy).
"""

import asyncio

import pytest
from redis.asyncio import Redis

from hypervigilant.circuit_breaker import RedisStore, StorageFailurePolicy
from hypervigilant.circuit_breaker.errors import CircuitStorageError

pytestmark = pytest.mark.unit

_TIMEOUT_SECONDS = 0.05
_SLOW_CLIENT_DELAY_SECONDS = 10.0
_FAST_FAILURE_CEILING_SECONDS = 1.0


def test_secondary_policy_fail_static_is_rejected_at_construction() -> None:
    """``secondary_policy`` cannot be ``FAIL_STATIC`` (would recurse on cold cache)."""
    with pytest.raises(ValueError, match="secondary_policy"):
        RedisStore(client=Redis(), secondary_policy=StorageFailurePolicy.FAIL_STATIC)


def test_invalid_cache_size_raises() -> None:
    """``cache_size < 1`` is rejected at construction."""
    with pytest.raises(ValueError, match="cache_size"):
        RedisStore(client=Redis(), cache_size=0)


def test_invalid_request_timeout_raises() -> None:
    """``request_timeout_seconds <= 0`` is rejected at construction."""
    with pytest.raises(ValueError, match="request_timeout_seconds"):
        RedisStore(client=Redis(), request_timeout_seconds=0.0)


async def test_request_timeout_raises_circuit_storage_error_on_slow_client() -> None:
    """H5 regression: a slow Redis client raises ``CircuitStorageError`` within the timeout window.

    The breaker must not contribute to the very latency it is meant to prevent. Without
    ``asyncio.timeout`` a hung TCP connection can block every protected call for tens of
    seconds.
    """

    class _SlowClient:
        async def script_load(self, source: str) -> bytes:  # noqa: ARG002
            await asyncio.sleep(_SLOW_CLIENT_DELAY_SECONDS)
            return b"sha"

        async def evalsha(self, *_args: object, **_kwargs: object) -> object:
            await asyncio.sleep(_SLOW_CLIENT_DELAY_SECONDS)
            return []

        async def aclose(self) -> None:
            pass

    store = RedisStore(client=_SlowClient(), request_timeout_seconds=_TIMEOUT_SECONDS)  # type: ignore[arg-type]
    started = asyncio.get_running_loop().time()
    with pytest.raises(CircuitStorageError):
        await store.aacquire("svc", threshold=5, ttl_seconds=30.0, lease_seconds=5.0)
    elapsed = asyncio.get_running_loop().time() - started
    assert elapsed < _FAST_FAILURE_CEILING_SECONDS, (
        f"Expected fast failure within request_timeout_seconds={_TIMEOUT_SECONDS}; "
        f"actually waited {elapsed:.3f}s. Timeout not honoured."
    )


async def test_from_client_does_not_close_caller_supplied_client() -> None:
    """H3 regression: ``from_client`` defaults to ``owns_client=False``.

    Sharing a Redis client across components (cache, rate-limiter, circuit breaker) is a
    normal pattern; the store must not pull the rug out from under the other consumers
    when its own lifespan ends.
    """
    aclose_calls: list[None] = []

    class _MockClient:
        async def aclose(self) -> None:
            aclose_calls.append(None)

    store = RedisStore.from_client(_MockClient())  # type: ignore[arg-type]
    await store.aclose()
    assert aclose_calls == [], (
        f"from_client default (owns_client=False) must NOT close the supplied "
        f"client; aclose was called {len(aclose_calls)} time(s)."
    )


async def test_from_client_owns_client_true_closes_supplied_client() -> None:
    """H3: ``from_client(owns_client=True)`` does close the supplied client."""
    aclose_calls: list[None] = []

    class _MockClient:
        async def aclose(self) -> None:
            aclose_calls.append(None)

    store = RedisStore.from_client(_MockClient(), owns_client=True)  # type: ignore[arg-type]
    await store.aclose()
    assert aclose_calls == [None]


async def test_from_url_closes_owned_client() -> None:
    """H3: ``from_url`` sets ``owns_client=True`` so ``aclose`` closes the pool.

    Constructed via ``__init__`` with ``owns_client=True`` -- which is what ``from_url``
    does -- so the assertion does not need a reachable Redis to open a pool against.
    """
    aclose_calls: list[None] = []

    class _MockClient:
        async def aclose(self) -> None:
            aclose_calls.append(None)

    store = RedisStore(client=_MockClient(), owns_client=True)  # type: ignore[arg-type]
    await store.aclose()
    assert aclose_calls == [None]
