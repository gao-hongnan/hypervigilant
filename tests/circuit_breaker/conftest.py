"""Pytest fixtures for circuit breaker tests with Redis TestContainers.

Industry standard pattern:
- Module-scoped container: Container starts once per test file (fast)
- Function-scoped cleanup: flushdb() before each test (isolated)
- Finalizer pattern: Ensures cleanup even on test failures
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from testcontainers.redis import RedisContainer

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator

    from redis.asyncio import Redis


@pytest.fixture(scope="module")
def redis_container() -> Generator[RedisContainer]:
    """Module-scoped Redis container.

    Uses yield pattern for automatic cleanup on fixture teardown.
    """
    container = RedisContainer("redis:7-alpine")
    container.start()
    yield container
    container.stop()


@pytest.fixture(scope="module")
def redis_url(redis_container: RedisContainer) -> str:
    """Get Redis URL from container."""
    host = redis_container.get_container_host_ip()
    port = redis_container.get_exposed_port(6379)
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
    """Clean Redis before and after each test (autouse=True).

    Industry standard: autouse ensures every test starts with clean state.
    """
    await redis_client.flushdb()
    yield
    await redis_client.flushdb()
