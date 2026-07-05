"""Public exception types raised by the circuit-breaker module.

Two distinct types ship -- one for the circuit-rejection event, one for the
storage-layer failure -- and exactly nothing more. Configuration validation
raises stdlib :exc:`ValueError` from :class:`BreakerConfig.__post_init__`;
no ``CircuitBreakerError`` base class is provided, per Decision 2.

Notes
-----
The flat hierarchy (no shared base) is a deliberate trade-off:

* Pro: every consumer reads `except BreakerOpenError` or
  `except CircuitStorageError` and knows exactly what they're catching.
* Con: callers wanting to map "any breaker condition" to e.g. HTTP 503
  must write `except (BreakerOpenError, CircuitStorageError)`.

If the project later introduces a `HarnessError` / `PixiuError` root for
all module exceptions (currently inconsistent across resilience and
related modules), or introduces a sealed `BreakerError` base to enable
single-clause catches without breaking existing call sites, that change
should land in a separate RFC and propagate consistently across the
codebase. Deferred from the DRAFT-0001 review (LOW-severity findings
L4 and L5).

* :class:`BreakerOpenError` -- raised on circuit rejection. Carries
  structured fields (``name``, ``opened_at``, ``retry_after``) plus a
  human-readable message; users discriminate on the type, not on a
  hierarchy.
* :class:`CircuitStorageError` -- wraps the underlying
  :exc:`redis.RedisError` (or any other storage failure) via
  ``raise CircuitStorageError(...) from underlying``. ``__cause__`` holds
  the wrapped exception.

References
----------
- FR-003 (single rejection error type + storage error type).
- Decision 2 (no hierarchy proliferation).

Examples
--------
>>> err = BreakerOpenError(name='upstream', opened_at=100.0, retry_after=5.0)
>>> err.name
'upstream'
>>> err.retry_after
5.0
"""

__all__ = ["BreakerOpenError", "CircuitStorageError"]


class BreakerOpenError(Exception):
    """Raised when the breaker rejects a call (state ``opened`` or busy probe).

    Carries the three structured fields users need to render an HTTP 503
    response, log the rejection, or schedule a retry.

    Parameters
    ----------
    name
        Circuit name. Keyword-only.
    opened_at
        Epoch second (or store-side wall clock) at which the breaker first
        opened in this generation. Keyword-only.
    retry_after
        Seconds the caller SHOULD wait before retrying. Keyword-only.

    Examples
    --------
    >>> try:
    ...     raise BreakerOpenError(name='svc', opened_at=100.0, retry_after=2.5)
    ... except BreakerOpenError as exc:
    ...     (exc.name, exc.retry_after)
    ('svc', 2.5)
    """

    __slots__ = ("name", "opened_at", "retry_after")

    name: str
    opened_at: float
    retry_after: float

    def __init__(self, *, name: str, opened_at: float, retry_after: float) -> None:
        message = f"Circuit '{name}' is open; opened_at={opened_at:.3f}, retry_after={retry_after:.3f}s."
        super().__init__(message)
        self.name = name
        self.opened_at = opened_at
        self.retry_after = retry_after


class CircuitStorageError(Exception):
    """Raised when the storage backend (Redis) cannot service a request.

    Wraps the underlying error via ``raise CircuitStorageError(...) from exc``;
    the original cause is available as ``__cause__``. Use this type to
    discriminate "the circuit said no" (:class:`BreakerOpenError`) from
    "the storage layer said no" (this).

    Examples
    --------
    >>> underlying = RuntimeError('redis disconnect')
    >>> try:
    ...     raise CircuitStorageError('lua script dispatch failed') from underlying
    ... except CircuitStorageError as exc:
    ...     exc.__cause__ is underlying
    True
    """

    __slots__ = ()
