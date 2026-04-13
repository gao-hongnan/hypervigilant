"""Retry configuration with Pydantic validation."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field


class RetryConfig(BaseModel):
    """Configuration for retry decorator with exponential backoff and jitter.

    Implements Google SRE Full Jitter algorithm for distributed systems resilience.
    See: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    max_attempts: int = Field(default=3, ge=1, description="Maximum retry attempts")
    wait_min: float = Field(default=1.0, ge=0, description="Minimum wait time in seconds")
    wait_max: float = Field(default=60.0, ge=0, description="Maximum wait time in seconds")
    multiplier: float = Field(default=1.0, ge=0, description="Wait multiplier (tenacity default: 1.0)")
    exp_base: float = Field(default=2.0, ge=1, description="Exponential base (Google SRE default: 2.0)")

    retry_on_exceptions: tuple[type[Exception], ...] | None = Field(
        default=None,
        description="Exception types that trigger retry (None = all exceptions)",
    )

    never_retry_on: tuple[type[Exception], ...] | None = Field(
        default=None,
        description="Exception types that should never be retried (takes precedence over retry_on_exceptions)",
    )

    retry_if: Callable[[BaseException], bool] | None = Field(
        default=None,
        description="Custom predicate for retry decision. Takes precedence over retry_on_exceptions.",
    )

    reraise: bool = Field(default=True, description="Reraise exception after all retries fail")
