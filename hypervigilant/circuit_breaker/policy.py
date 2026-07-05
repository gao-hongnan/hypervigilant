"""Decision algebraic data type produced by the sansio core.

Three frozen dataclasses model the three possible outcomes of projecting a
:class:`Snapshot` through ``(BreakerConfig, Clock)``:

* :class:`AllowCall` -- the protected call MAY proceed.
* :class:`RejectCall(opened_at, retry_after)` -- the breaker is open; the
  caller SHOULD NOT issue the call. The runtime layer raises
  :class:`BreakerOpenError` from this variant.
* :class:`ProbeCall(lease_until)` -- the breaker is in single-flight probe
  mode; the caller MAY proceed but the runtime layer must record the lease
  expiry so a subsequent failure deterministically bumps the generation.

The variants are unioned via :data:`Decision`. Match against them using
structural pattern matching (or :func:`isinstance`) -- there is no shared
base class; the variants are deliberately disjoint.

References
----------
- FR-004 (sansio core projects a Decision).
- AC-001..004 (Decision-driven acceptance).
- Decision 1 (sansio split).
- Decision 4 (asymmetric Protocol consumes Decision).

Examples
--------
>>> reject = RejectCall(opened_at=100.0, retry_after=5.0)
>>> reject.retry_after
5.0
>>> probe = ProbeCall(lease_until=110.0)
>>> probe.lease_until
110.0
"""

from dataclasses import dataclass

__all__ = ["AllowCall", "Decision", "ProbeCall", "RejectCall"]


@dataclass(frozen=True, slots=True)
class AllowCall:
    """Decision: the protected call MAY proceed.

    Carries no payload -- the runtime layer simply forwards control to the
    user's coroutine.

    Examples
    --------
    >>> AllowCall() == AllowCall()
    True
    """


@dataclass(frozen=True, slots=True)
class RejectCall:
    """Decision: the breaker is open; the call SHOULD NOT proceed.

    Parameters
    ----------
    opened_at
        Epoch second at which the breaker first transitioned to ``opened`` in
        the current generation. Surfaced on
        :class:`hypervigilant.circuit_breaker.errors.BreakerOpenError`.
    retry_after
        Seconds the caller SHOULD wait before retrying. Computed by the
        sansio core as ``ttl - elapsed`` (clamped at ``0.0``).

    Examples
    --------
    >>> reject = RejectCall(opened_at=100.0, retry_after=5.0)
    >>> reject.opened_at
    100.0
    """

    opened_at: float
    retry_after: float


@dataclass(frozen=True, slots=True)
class ProbeCall:
    """Decision: the breaker is in single-flight probe mode.

    Parameters
    ----------
    lease_until
        Epoch second at which the probe lease expires. The runtime layer
        compares the lease expiry against ``Clock.now()`` to decide whether a
        subsequent failure should re-open the breaker.

    Examples
    --------
    >>> probe = ProbeCall(lease_until=110.0)
    >>> probe.lease_until
    110.0
    """

    lease_until: float


type Decision = AllowCall | RejectCall | ProbeCall
"""Algebraic union of the three projection outcomes."""
