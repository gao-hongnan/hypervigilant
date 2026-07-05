"""Unit tests for BreakerConfig defaults, validation, and exception types.

Covers FR-014 (BreakerConfig frozen dataclass + __post_init__ validation),
FR-009 (StorageFailurePolicy StrEnum), and FR-003 (BreakerOpenError +
CircuitStorageError).

Notes
-----
The error tests construct synthesised :class:`redis.RedisError` instances; we
do not require a live Redis connection here — only that ``__cause__``
chaining works the way the FR-009 fallback path will rely on.
"""

import dataclasses

import pytest

from hypervigilant.circuit_breaker.config import (
    BreakerConfig,
    CountingPolicy,
    StorageFailurePolicy,
)
from hypervigilant.circuit_breaker.errors import BreakerOpenError, CircuitStorageError


@pytest.mark.unit
def test_breaker_config_defaults() -> None:
    """BreakerConfig() yields the FR-014 default values."""
    config = BreakerConfig()

    assert config.threshold == 5
    assert config.ttl == pytest.approx(30.0)
    assert config.half_open_max_calls == 1
    assert config.half_open_lease_seconds == pytest.approx(5.0)
    assert config.key_ttl_seconds == 86400
    assert config.exclude == ()


@pytest.mark.unit
def test_breaker_config_is_frozen_dataclass_with_slots() -> None:
    """BreakerConfig is frozen + slotted."""
    config = BreakerConfig()

    assert dataclasses.is_dataclass(config)
    assert hasattr(BreakerConfig, "__slots__")
    assert not hasattr(config, "__dict__")
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(config, "threshold", 99)  # noqa: B010


@pytest.mark.unit
def test_breaker_config_accepts_custom_values() -> None:
    """BreakerConfig accepts fully-specified custom values."""

    class TimeoutLike(Exception):
        pass

    config = BreakerConfig(
        threshold=10,
        ttl=120.0,
        half_open_max_calls=3,
        half_open_lease_seconds=10.0,
        key_ttl_seconds=300,
        exclude=(TimeoutLike,),
    )

    assert config.threshold == 10
    assert config.ttl == pytest.approx(120.0)
    assert config.half_open_max_calls == 3
    assert config.half_open_lease_seconds == pytest.approx(10.0)
    assert config.key_ttl_seconds == 300
    assert config.exclude == (TimeoutLike,)


@pytest.mark.unit
def test_breaker_config_rejects_threshold_below_one() -> None:
    """threshold must be >= 1 (FR-014)."""
    with pytest.raises(ValueError, match="threshold"):
        BreakerConfig(threshold=0)


@pytest.mark.unit
def test_breaker_config_rejects_negative_threshold() -> None:
    """negative threshold raises ValueError."""
    with pytest.raises(ValueError, match="threshold"):
        BreakerConfig(threshold=-3)


@pytest.mark.unit
def test_breaker_config_rejects_non_positive_ttl() -> None:
    """ttl must be > 0 (FR-014)."""
    with pytest.raises(ValueError, match="ttl"):
        BreakerConfig(ttl=0.0)


@pytest.mark.unit
def test_breaker_config_rejects_negative_ttl() -> None:
    """negative ttl raises ValueError."""
    with pytest.raises(ValueError, match="ttl"):
        BreakerConfig(ttl=-1.0)


@pytest.mark.unit
def test_breaker_config_rejects_half_open_max_calls_below_one() -> None:
    """half_open_max_calls must be >= 1."""
    with pytest.raises(ValueError, match="half_open_max_calls"):
        BreakerConfig(half_open_max_calls=0)


@pytest.mark.unit
def test_breaker_config_rejects_non_positive_half_open_lease_seconds() -> None:
    """half_open_lease_seconds must be > 0."""
    with pytest.raises(ValueError, match="half_open_lease_seconds"):
        BreakerConfig(half_open_lease_seconds=0.0)


@pytest.mark.unit
def test_breaker_config_rejects_non_positive_key_ttl_seconds() -> None:
    """key_ttl_seconds must be > 0."""
    with pytest.raises(ValueError, match="key_ttl_seconds"):
        BreakerConfig(key_ttl_seconds=0)


@pytest.mark.unit
def test_breaker_open_error_structured_fields() -> None:
    """BreakerOpenError exposes name, opened_at, retry_after fields (FR-003)."""
    err = BreakerOpenError(name="x", opened_at=100.0, retry_after=5.0)

    assert err.name == "x"
    assert err.opened_at == pytest.approx(100.0)
    assert err.retry_after == pytest.approx(5.0)
    assert isinstance(err, Exception)


@pytest.mark.unit
def test_breaker_open_error_human_readable_message() -> None:
    """str(BreakerOpenError) contains the circuit name and retry window."""
    err = BreakerOpenError(name="upstream_api", opened_at=100.0, retry_after=12.5)

    rendered = str(err)

    assert "upstream_api" in rendered
    assert "12.5" in rendered


@pytest.mark.unit
def test_breaker_open_error_requires_keyword_arguments() -> None:
    """All BreakerOpenError fields are keyword-only."""
    with pytest.raises(TypeError):
        BreakerOpenError("x", 100.0, 5.0)  # type: ignore[misc]


@pytest.mark.unit
def test_circuit_storage_error_chains_cause() -> None:
    """CircuitStorageError chains the underlying exception via __cause__."""
    underlying = RuntimeError("redis disconnect")

    err: CircuitStorageError
    try:
        raise CircuitStorageError("acquire failed") from underlying
    except CircuitStorageError as exc:
        err = exc

    assert isinstance(err, Exception)
    assert err.__cause__ is underlying


@pytest.mark.unit
def test_storage_failure_policy_strenum_values() -> None:
    """StorageFailurePolicy is a string enum with the canonical wire values (FR-009)."""
    assert StorageFailurePolicy.FAIL_STATIC.value == "fail_static"
    assert StorageFailurePolicy.FAIL_OPEN.value == "fail_open"
    assert StorageFailurePolicy.FAIL_CLOSED.value == "fail_closed"


@pytest.mark.unit
def test_storage_failure_policy_is_str_subclass() -> None:
    """StorageFailurePolicy members are str instances (StrEnum semantics)."""
    assert isinstance(StorageFailurePolicy.FAIL_STATIC, str)
    assert StorageFailurePolicy.FAIL_STATIC.value == "fail_static"


# ---------------------------------------------------------------------------
# CountingPolicy + BreakerConfig.rate_based (DRAFT-0002)
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_counting_policy_defaults_to_consecutive() -> None:
    """CountingPolicy() yields the consecutive strategy with Resilience4j defaults."""
    policy = CountingPolicy()

    assert policy.strategy == "consecutive"
    assert policy.sliding_window_size == 10
    assert policy.failure_rate_threshold == pytest.approx(0.5)
    assert policy.minimum_number_of_calls == 10


@pytest.mark.unit
def test_counting_policy_sliding_construction() -> None:
    """CountingPolicy accepts a sliding_window configuration."""
    policy = CountingPolicy("sliding_window", 100, 0.25, 20)

    assert policy.strategy == "sliding_window"
    assert policy.sliding_window_size == 100
    assert policy.failure_rate_threshold == pytest.approx(0.25)
    assert policy.minimum_number_of_calls == 20


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kwargs", "msg_field"),
    [
        ({"strategy": "bogus"}, "strategy"),
        ({"sliding_window_size": 0}, "sliding_window_size"),
        ({"failure_rate_threshold": 0.0}, "failure_rate_threshold"),
        ({"failure_rate_threshold": 1.5}, "failure_rate_threshold"),
        ({"minimum_number_of_calls": 0}, "minimum_number_of_calls"),
        ({"sliding_window_size": 5, "minimum_number_of_calls": 10}, "minimum_number_of_calls"),
    ],
)
def test_counting_policy_rejects_invalid(kwargs: dict[str, object], msg_field: str) -> None:
    """CountingPolicy.__post_init__ rejects every out-of-range combination (FR-101)."""
    with pytest.raises(ValueError, match=msg_field):
        CountingPolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.unit
def test_breaker_config_default_is_consecutive_parity() -> None:
    """BreakerConfig() defaults to consecutive counting (NFR-101 parity)."""
    assert BreakerConfig().counting.strategy == "consecutive"


@pytest.mark.unit
def test_rate_based_preset_defaults() -> None:
    """BreakerConfig.rate_based() yields sliding_window with Resilience4j defaults."""
    config = BreakerConfig.rate_based()

    assert config.counting.strategy == "sliding_window"
    assert config.counting.sliding_window_size == 10
    assert config.counting.failure_rate_threshold == pytest.approx(0.5)
    assert config.counting.minimum_number_of_calls == 10
    # carried-over knobs keep their defaults
    assert config.ttl == pytest.approx(30.0)
    assert config.half_open_lease_seconds == pytest.approx(5.0)


@pytest.mark.unit
def test_rate_based_preset_override() -> None:
    """BreakerConfig.rate_based forwards window knobs + carried-over config."""
    config = BreakerConfig.rate_based(size=100, rate=0.25, min_calls=20, ttl=15.0)

    assert config.counting.sliding_window_size == 100
    assert config.counting.failure_rate_threshold == pytest.approx(0.25)
    assert config.counting.minimum_number_of_calls == 20
    assert config.ttl == pytest.approx(15.0)


@pytest.mark.unit
def test_rate_based_preset_validates_window_knobs() -> None:
    """rate_based forwards invalid window knobs to CountingPolicy validation."""
    with pytest.raises(ValueError, match="failure_rate_threshold"):
        BreakerConfig.rate_based(rate=0.0)
