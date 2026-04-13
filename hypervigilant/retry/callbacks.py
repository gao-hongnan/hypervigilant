"""Built-in retry callbacks for observability."""

import logging

from tenacity import RetryCallState

logger = logging.getLogger(__name__)


def _log_retry(retry_state: RetryCallState) -> None:  # pyright: ignore[reportUnusedFunction]
    """Log retry attempt failures at WARNING level."""
    exception = retry_state.outcome.exception() if retry_state.outcome else None
    logger.warning("Retry attempt %d failed: %s", retry_state.attempt_number, exception)
