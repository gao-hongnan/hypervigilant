"""Focused unit tests for database transaction retry policy mapping."""

from tenacity import wait_random_exponential

from hypervigilant.db.transaction import _retrying
from hypervigilant.retry import RetryConfig


def test_retrying_maps_wait_min_independently_from_multiplier() -> None:
    policy = RetryConfig(wait_min=0.75, wait_max=10.0, multiplier=0.25)

    controller = _retrying(policy)

    assert isinstance(controller.wait, wait_random_exponential)
    assert controller.wait.min == 0.75
