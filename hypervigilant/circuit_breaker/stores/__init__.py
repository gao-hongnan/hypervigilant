"""Storage backends for the circuit-breaker module.

Two implementations ship in the rewrite:

* :class:`InMemoryStore` (PR 2) — process-local, suitable for single-worker
  deployments and tests.
* :class:`RedisStore` (PR 3) — multi-worker, multi-process; backed by Lua
  scripts dispatched via ``EVALSHA``.

Both implement the asymmetric :class:`BreakerStore` Protocol (FR-005,
Decision 4).

Examples
--------
>>> from hypervigilant.circuit_breaker.stores import BreakerStore, InMemoryStore
>>> isinstance(InMemoryStore(), BreakerStore)
True
"""

from hypervigilant.circuit_breaker.stores.base import BreakerStore
from hypervigilant.circuit_breaker.stores.memory import InMemoryStore
from hypervigilant.circuit_breaker.stores.redis import RedisStore

__all__ = ["BreakerStore", "InMemoryStore", "RedisStore"]
