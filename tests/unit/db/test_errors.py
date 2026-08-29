"""The SQLSTATE translation table and the two-axis retryability design."""

from __future__ import annotations

import pytest
from sqlalchemy.exc import SQLAlchemyError

from hypervigilant.db.errors import (
    DatabaseError,
    DatabaseUnavailableError,
    IntegrityViolationError,
    TransactionConflictError,
    UnclassifiedDatabaseError,
    translate_error,
)

pytestmark = pytest.mark.unit


class _DriverError(Exception):
    """Stands in for the asyncpg exception SQLAlchemy wraps: it carries the metadata."""

    def __init__(self, sqlstate: str | None, constraint: str | None) -> None:
        super().__init__("boom")
        self.sqlstate = sqlstate
        self.constraint_name = constraint


class _WrappedError(SQLAlchemyError):
    """A SQLAlchemy error exposing its driver exception through ``.orig``, as asyncpg does."""

    def __init__(self, orig: _DriverError) -> None:
        super().__init__("boom")
        self.orig = orig


def _wrapped(sqlstate: str | None, constraint: str | None = None) -> SQLAlchemyError:
    """Build a SQLAlchemy error carrying a driver exception, as asyncpg produces."""
    return _WrappedError(_DriverError(sqlstate, constraint))


@pytest.mark.parametrize(
    ("sqlstate", "expected", "retryable"),
    [
        ("40001", TransactionConflictError, True),
        ("40P01", TransactionConflictError, True),
        ("08006", DatabaseUnavailableError, True),
        ("08000", DatabaseUnavailableError, True),
        ("53300", DatabaseUnavailableError, True),
        ("57P01", DatabaseUnavailableError, True),
        ("23505", IntegrityViolationError, False),
        ("23503", IntegrityViolationError, False),
        ("42601", UnclassifiedDatabaseError, False),
    ],
)
def test_sqlstate_classification(sqlstate: str, expected: type[DatabaseError], retryable: bool) -> None:
    """Every retryable PostgreSQL condition arrives as a bare ``DBAPIError``.

    Classification is therefore by SQLSTATE, not by exception class -- matching on
    ``OperationalError`` (the intuitive choice) retries nothing on asyncpg.
    """
    translated = translate_error(_wrapped(sqlstate), operation="t")
    assert isinstance(translated, expected)
    assert translated.retryable is retryable
    assert translated.sqlstate == sqlstate


def test_unclassified_preserves_the_sqlstate() -> None:
    """The unclassified bucket must be greppable, not a shrug."""
    translated = translate_error(_wrapped("XX000"), operation="t")
    assert isinstance(translated, UnclassifiedDatabaseError)
    assert translated.sqlstate == "XX000"


def test_integrity_carries_the_constraint_name() -> None:
    translated = translate_error(_wrapped("23505", "uq_orders_ref"), operation="orders.place")
    assert isinstance(translated, IntegrityViolationError)
    assert translated.constraint == "uq_orders_ref"
    assert translated.operation == "orders.place"


def test_base_class_cannot_be_raised_directly() -> None:
    """The 'abstract base' is a runtime fact, not a docstring promise."""
    with pytest.raises(TypeError, match="base type"):
        DatabaseError("nope", operation="t")


def test_retryability_is_not_inherited_from_the_hierarchy() -> None:
    """A broad ``except DatabaseError`` catches integrity errors; retry must not."""
    integrity = IntegrityViolationError("dup", operation="t", sqlstate="23505")
    assert isinstance(integrity, DatabaseError)
    assert integrity.retryable is False
