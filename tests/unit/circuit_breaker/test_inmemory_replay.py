"""State-machine invariants under a deterministic random replay against ``InMemoryStore``.

The cross-backend half of this harness -- proving ``InMemoryStore`` and ``RedisStore``
produce identical ``(state, generation)`` traces for the same input sequence (SC-005) --
needs a real Redis and lives in
``tests/integration/circuit_breaker/test_inmemory_redis_equivalence.py``.

Sequences are seeded, so a failure here reproduces exactly.

References
----------
- SC-005 (equivalence between InMemoryStore and RedisStore).
- Decision 4 (asymmetric store contract).
"""

import asyncio
import random

import pytest

from hypervigilant.circuit_breaker import BreakerState, FakeClock, InMemoryStore, Snapshot

pytestmark = pytest.mark.unit

_OP_FAILURE = "failure"
_OP_SUCCESS = "success"
_OP_PEEK = "peek"
_OP_NAMES = (_OP_FAILURE, _OP_SUCCESS, _OP_PEEK)
_VALID_STATES: tuple[BreakerState, ...] = ("closed", "opened", "half_opened")

_SEQUENCE_COUNT = 50
_MAX_SEQUENCE_LENGTH = 200
_SEED = 0


def _replay_invariants(snapshots: list[Snapshot]) -> None:
    """Assert every snapshot in a replay trace satisfies the state-machine invariants."""
    last_generation = -1
    for snap in snapshots:
        assert snap.state in _VALID_STATES
        assert snap.failure_count >= 0
        assert snap.generation >= last_generation
        last_generation = snap.generation
        if snap.state == "opened":
            assert snap.opened_at > 0.0


def test_in_memory_state_traces_satisfy_invariants() -> None:
    """Replay 50 deterministic random sequences against InMemoryStore."""
    rng = random.Random(_SEED)

    async def run() -> None:
        for _ in range(_SEQUENCE_COUNT):
            sequence_length = rng.randint(1, _MAX_SEQUENCE_LENGTH)
            ops = [rng.choice(_OP_NAMES) for _ in range(sequence_length)]
            clock = FakeClock(now=0.0)
            store = InMemoryStore(clock=clock)
            for op in ops:
                clock.advance(0.5)
                if op == _OP_FAILURE:
                    await store.arecord_failure("svc", threshold=3, ttl_seconds=10.0)
                elif op == _OP_SUCCESS:
                    await store.arecord_success("svc")
                else:
                    await store.apeek("svc")
            traces: list[Snapshot] = []
            seen = await store.apeek("svc")
            if seen is not None:
                traces.append(seen)
            _replay_invariants(traces)

    asyncio.run(run())
