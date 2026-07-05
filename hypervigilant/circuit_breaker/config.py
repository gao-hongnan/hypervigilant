"""Configuration data structures for the circuit-breaker module.

Two public symbols ship in this module:

* :class:`BreakerConfig` -- frozen dataclass with ``slots=True`` carrying the
  six tuning knobs documented in FR-014. ``__post_init__`` raises
  :exc:`ValueError` for any out-of-range value.
* :class:`StorageFailurePolicy` -- :class:`enum.StrEnum` with the three
  policies the registry / store layer can apply when Redis becomes
  unreachable (FR-009).

References
----------
- FR-014 (BreakerConfig defaults and validation contract).
- FR-009 (StorageFailurePolicy values).
- Decision 2 (configuration validation raises stdlib ``ValueError``;
  no custom subclass).

Examples
--------
>>> from hypervigilant.circuit_breaker.config import BreakerConfig, StorageFailurePolicy
>>> config = BreakerConfig()
>>> config.threshold
5
>>> StorageFailurePolicy.FAIL_STATIC.value
'fail_static'
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, Self, cast

__all__ = ["BreakerConfig", "CountingPolicy", "StorageFailurePolicy"]


class StorageFailurePolicy(StrEnum):
    """Behaviour when the underlying storage backend (Redis) is unreachable.

    The default registry policy is :attr:`FAIL_STATIC`; the secondary policy
    (used on a cold cache miss) defaults to :attr:`FAIL_OPEN`.

    Attributes
    ----------
    FAIL_STATIC
        Consult a local TTL cache of recent snapshots; fall through to the
        secondary policy on a cache miss. Wire value: ``"fail_static"``.
    FAIL_OPEN
        Permit the call and emit a warning. Wire value: ``"fail_open"``.
    FAIL_CLOSED
        Reject the call and emit a warning. Wire value: ``"fail_closed"``.

    Examples
    --------
    >>> StorageFailurePolicy("fail_static") is StorageFailurePolicy.FAIL_STATIC
    True
    """

    FAIL_STATIC = "fail_static"
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


@dataclass(frozen=True, slots=True)
class CountingPolicy:
    """Selectable failure-counting strategy for a circuit (FR-101).

    ``"consecutive"`` (default) reproduces DRAFT-0001 byte-for-byte: any success
    in the ``closed`` state resets the failure counter to zero.
    ``"sliding_window"`` trips on a failure rate over a count-based window of the
    last ``sliding_window_size`` outcomes, gated by ``minimum_number_of_calls``.

    Knob names mirror Resilience4j so operators familiar with Spring Cloud
    recognise them. Defaults: ``size=10``, ``rate=0.5``, ``min_calls=10``.

    Examples
    --------
    >>> CountingPolicy().strategy
    'consecutive'
    >>> CountingPolicy("sliding_window", 100, 0.25, 20).failure_rate_threshold
    0.25
    """

    strategy: Literal["consecutive", "sliding_window"] = "consecutive"
    sliding_window_size: int = 10
    failure_rate_threshold: float = 0.5
    minimum_number_of_calls: int = 10

    def __post_init__(self) -> None:
        valid = {"consecutive", "sliding_window"}
        if self.strategy not in valid:
            msg = f"CountingPolicy.strategy must be one of {sorted(valid)}; got {self.strategy!r}."
            raise ValueError(msg)
        if self.sliding_window_size < 1:
            msg = f"CountingPolicy.sliding_window_size must be >= 1; got {self.sliding_window_size}."
            raise ValueError(msg)
        if not (0.0 < self.failure_rate_threshold <= 1.0):
            msg = f"CountingPolicy.failure_rate_threshold must be in (0.0, 1.0]; got {self.failure_rate_threshold}."
            raise ValueError(msg)
        if self.minimum_number_of_calls < 1:
            msg = f"CountingPolicy.minimum_number_of_calls must be >= 1; got {self.minimum_number_of_calls}."
            raise ValueError(msg)
        if self.minimum_number_of_calls > self.sliding_window_size:
            msg = (
                f"CountingPolicy.minimum_number_of_calls "
                f"({self.minimum_number_of_calls}) must be <= "
                f"sliding_window_size ({self.sliding_window_size})."
            )
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class BreakerConfig:
    """Tuning knobs for a single circuit (FR-014).

    Frozen with ``slots=True`` so an instance is hashable, immutable, and
    cheap to construct. ``__post_init__`` enforces the validation table at
    FR-014; every invalid combination raises :exc:`ValueError` with a
    descriptive message naming the offending field.

    Parameters
    ----------
    threshold
        Consecutive failures (within ``ttl`` seconds) required to trip the
        breaker. Must be ``>= 1``. Default ``5``.
    ttl
        Seconds the breaker stays in ``opened`` before transitioning to
        ``half_opened``. Must be ``> 0``. Default ``30.0``.
    half_open_max_calls
        Maximum concurrent probe calls allowed in the ``half_opened``
        window. Default ``1`` (single-flight). Must be ``>= 1``.
    half_open_lease_seconds
        Lease duration on the ``cb:{name}:probe`` key. Must be ``> 0``.
        Default ``5.0``.
    key_ttl_seconds
        TTL applied to the underlying storage key (Redis hash). Must be
        ``> 0``. Default ``86400`` (one day).
    exclude
        Tuple of exception types that MUST NOT count as circuit failures
        when raised inside the protected coroutine. Default ``()``.

    Raises
    ------
    ValueError
        If any field is outside its valid range.

    Examples
    --------
    >>> config = BreakerConfig(threshold=10, ttl=15.0)
    >>> config.threshold
    10
    >>> BreakerConfig(threshold=0)
    Traceback (most recent call last):
        ...
    ValueError: BreakerConfig.threshold must be >= 1; got 0.
    """

    threshold: int = 5
    ttl: float = 30.0
    half_open_max_calls: int = 1
    half_open_lease_seconds: float = 5.0
    key_ttl_seconds: int = 86400
    exclude: tuple[type[BaseException], ...] = field(default_factory=tuple)
    counting: CountingPolicy = field(default_factory=CountingPolicy)

    def __post_init__(self) -> None:
        if self.threshold < 1:
            msg = f"BreakerConfig.threshold must be >= 1; got {self.threshold}."
            raise ValueError(msg)
        if self.ttl <= 0.0:
            msg = f"BreakerConfig.ttl must be > 0; got {self.ttl}."
            raise ValueError(msg)
        if self.half_open_max_calls < 1:
            msg = f"BreakerConfig.half_open_max_calls must be >= 1; got {self.half_open_max_calls}."
            raise ValueError(msg)
        if self.half_open_lease_seconds <= 0.0:
            msg = f"BreakerConfig.half_open_lease_seconds must be > 0; got {self.half_open_lease_seconds}."
            raise ValueError(msg)
        if self.key_ttl_seconds <= 0:
            msg = f"BreakerConfig.key_ttl_seconds must be > 0; got {self.key_ttl_seconds}."
            raise ValueError(msg)
        for index, item in enumerate(cast("tuple[object, ...]", self.exclude)):
            if not isinstance(item, type) or not issubclass(item, BaseException):
                msg = (
                    f"BreakerConfig.exclude[{index}] must be a class derived from "
                    f"BaseException; got {item!r} ({type(item).__name__})."
                )
                raise TypeError(msg)

    @classmethod
    def rate_based(
        cls: type[Self],
        *,
        size: int = 10,
        rate: float = 0.5,
        min_calls: int = 10,
        ttl: float = 30.0,
        half_open_max_calls: int = 1,
        half_open_lease_seconds: float = 5.0,
        key_ttl_seconds: int = 86400,
        exclude: tuple[type[BaseException], ...] = (),
    ) -> Self:
        """Build a config that trips on failure rate over a sliding window.

        ``threshold`` is retained from the default (5) but is **ignored** when
        ``counting.strategy == "sliding_window"``; it remains only so the
        ``acquire`` / ``record_failure`` ``threshold=`` kwargs do not churn.

        Examples
        --------
        >>> cfg = BreakerConfig.rate_based(size=100, rate=0.25, min_calls=20)
        >>> cfg.counting.strategy
        'sliding_window'
        """
        return cls(
            threshold=5,
            ttl=ttl,
            half_open_max_calls=half_open_max_calls,
            half_open_lease_seconds=half_open_lease_seconds,
            key_ttl_seconds=key_ttl_seconds,
            exclude=exclude,
            counting=CountingPolicy("sliding_window", size, rate, min_calls),
        )
