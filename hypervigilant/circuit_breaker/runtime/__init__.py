"""Runtime layer for the circuit-breaker module.

Houses :class:`AsyncCircuitBreaker` (async context manager) and
:class:`AsyncBreakerRegistry` (Identity Map + decorator + event registry).
The runtime layer is the only place I/O occurs; the sansio core
(:mod:`hypervigilant.circuit_breaker.breaker`) and the storage backends
remain I/O-free or I/O-bounded respectively.
"""

from hypervigilant.circuit_breaker.runtime.asyncio import (
    AsyncBreakerRegistry,
    AsyncCircuitBreaker,
)

__all__ = ["AsyncBreakerRegistry", "AsyncCircuitBreaker"]
