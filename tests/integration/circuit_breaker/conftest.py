"""Fixtures for the Redis-backed circuit-breaker suite: one container per module.

Scoped to this directory on purpose. The autouse ``clean_redis`` fixture below reaches
a live Redis before every test it covers, so anything sharing a conftest with it needs
a Docker daemon whether or not it touches Redis. Keeping it under ``tests/integration``
is what lets the pure-logic breaker tests in ``tests/unit/circuit_breaker`` run on a
checkout with no Docker at all.

- Module-scoped container: one Redis per test file.
- Function-scoped ``flushdb()``: each test starts and ends on clean state.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from testcontainers.community.redis import RedisContainer

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

    from redis.asyncio import Redis

_IMAGE = "redis:7-alpine"
_PORT = 6379


@pytest.fixture(scope="module")
def redis_container() -> Generator[RedisContainer]:
    """One Redis container per test module.

    An unreachable daemon is a *skip*, not an error. Without the guard a contributor
    with no Docker sees this suite error out rather than report skips, which makes a
    green checkout look broken.
    """
    try:
        container = RedisContainer(_IMAGE)
        container.start()
    except Exception as exc:  # noqa: BLE001 - any docker failure is the same answer: skip
        pytest.skip(f"needs a running Docker daemon: {type(exc).__name__}: {exc}")
    try:
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="module")
def redis_url(redis_container: RedisContainer) -> str:
    """The URL of the module's container."""
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(_PORT)
    return f"redis://{host}:{port}/0"


@pytest.fixture
async def redis_client(redis_url: str) -> AsyncGenerator[Redis]:
    """Async Redis client for direct state inspection."""
    from redis.asyncio import Redis as AsyncRedis

    client: Redis = AsyncRedis.from_url(redis_url)
    yield client
    await client.aclose()


@pytest.fixture(autouse=True)
async def clean_redis(redis_client: Redis) -> AsyncGenerator[None]:
    """Flush before and after each test, so no test can observe another's keys."""
    await redis_client.flushdb()
    yield
    await redis_client.flushdb()
