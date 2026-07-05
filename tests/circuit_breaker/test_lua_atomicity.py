"""Strict-atomicity test for the Redis-backed Lua scripts (PR 3 / task 3B).

This is the load-bearing correctness test of the rewrite. Per SC-003,
1,000 concurrent ``record_failure`` calls on a fresh circuit with
``threshold=10`` MUST produce exactly one ``closed`` → ``opened`` transition,
observable as a single ``generation`` increment on ``peek``. Lua is
single-threaded inside Redis, so the assertion is deterministic by
construction; running it 100 consecutive times in CI is the rigour
requirement.

Limitation (review item M9, deferred):
The current fan-out uses ``asyncio.gather`` against a single redis-py
asyncio client (with ``pool_max=200``). The asyncio scheduler is
co-operative; this proves Lua-script atomicity (each EVALSHA runs
single-threaded server-side) but does NOT exercise true cross-process
contention. A genuine race-condition regression in the Lua scripts
would be caught here because Lua serialises everything inside one
EVALSHA, but a Python-side framing bug that only surfaces under
multi-process load would slip through. Multi-process fan-out (each
process owning its own redis-py client) is a follow-up improvement
that requires careful test infrastructure (process-pool fixture,
shared assertion barrier).

References
----------
- FR-006 (Lua atomicity).
- FR-007 (.lua files at stores/lua/).
- AC-002 (1,000 concurrent → exactly one transition).
- EC-001 (concurrent threshold crossing).
- SC-003 (zero flakes across 100 runs).
"""

import asyncio
from typing import TYPE_CHECKING

import pytest

from hypervigilant.circuit_breaker import RedisStore, Snapshot

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


@pytest.fixture
async def atomicity_store(redis_url: str) -> "AsyncGenerator[RedisStore]":
    """A ``RedisStore`` with a generous pool tuned for the 1,000-fan-out test."""
    store = RedisStore.from_url(redis_url, pool_max=200)
    await store.initialize()
    yield store
    await store.aclose()


@pytest.mark.integration
async def test_record_failure_strict_atomicity_under_concurrent_load(
    atomicity_store: RedisStore,
) -> None:
    """1,000 concurrent record_failure → exactly one generation increment.

    The assertion structure is deliberately simple: snapshot pre and post,
    confirm ``state == "opened"``, ``failure_count == 10`` (clamped at the
    threshold), and ``generation == pre.generation + 1`` (exactly one
    transition). Lua runs single-threaded server-side, so any other result
    is a real correctness regression — never a flake.
    """
    name = "atomicity_test"
    threshold = 10
    pre = await atomicity_store.peek(name) or Snapshot(
        name=name,
        state="closed",
        failure_count=0,
        opened_at=0.0,
        generation=0,
    )
    coros = [
        atomicity_store.record_failure(
            name,
            threshold=threshold,
            ttl_seconds=30.0,
        )
        for _ in range(1000)
    ]
    await asyncio.gather(*coros)
    post = await atomicity_store.peek(name)
    assert post is not None
    assert post.state == "opened"
    assert post.failure_count == threshold
    assert post.generation == pre.generation + 1


@pytest.mark.integration
async def test_concurrent_failures_below_threshold_stay_closed(
    atomicity_store: RedisStore,
) -> None:
    """N=5 concurrent failures with threshold=10 keep the breaker closed.

    Sanity check: the same fan-out pattern below threshold MUST NOT flip
    the breaker. The atomic increment is correct regardless of whether the
    threshold is reached.
    """
    name = "below_threshold"
    threshold = 10
    pre = await atomicity_store.peek(name) or Snapshot(
        name=name,
        state="closed",
        failure_count=0,
        opened_at=0.0,
        generation=0,
    )
    coros = [
        atomicity_store.record_failure(
            name,
            threshold=threshold,
            ttl_seconds=30.0,
        )
        for _ in range(5)
    ]
    await asyncio.gather(*coros)
    post = await atomicity_store.peek(name)
    assert post is not None
    assert post.state == "closed"
    assert post.failure_count == 5
    assert post.generation == pre.generation
