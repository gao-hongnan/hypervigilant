from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from structlog.types import EventDict, WrappedLogger


_otel_available: bool | None = None


def is_otel_available() -> bool:
    global _otel_available
    if _otel_available is None:
        try:
            from opentelemetry import trace  # type: ignore[import-not-found]

            _ = trace.get_current_span
            _otel_available = True
        except ImportError:
            _otel_available = False
    return _otel_available


def add_otel_trace_context(
    _logger: WrappedLogger,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    if not is_otel_available():
        return event_dict

    from opentelemetry import trace  # type: ignore[import-not-found]

    current_span = trace.get_current_span()
    if current_span.is_recording():
        span_context = current_span.get_span_context()
        event_dict["trace_id"] = format(span_context.trace_id, "032x")
        event_dict["span_id"] = format(span_context.span_id, "016x")

    return event_dict


def get_otel_processor() -> Any | None:
    if is_otel_available():
        return add_otel_trace_context
    return None
