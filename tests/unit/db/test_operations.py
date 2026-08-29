"""Closed vocabulary for package-owned database operation labels."""

from enum import StrEnum

import pytest

import hypervigilant.db as db

pytestmark = pytest.mark.unit


def test_database_operation_is_a_closed_public_str_enum() -> None:
    operation_type = getattr(db, "DatabaseOperation", None)

    assert operation_type is not None
    assert issubclass(operation_type, StrEnum)
    assert {member.name: member.value for member in operation_type} == {
        "STATEMENT": "db.statement",
        "SESSION": "db.session",
        "READER_SESSION": "db.reader_session",
        "TRANSACTION": "db.transaction",
        "INITIALIZE": "db.initialize",
        "INITIALIZE_READER": "db.initialize.reader",
        "HEALTH": "db.health",
        "HEALTH_READER": "db.health.reader",
    }


def test_database_error_normalizes_operation_to_plain_string() -> None:
    error = db.DatabaseUnavailableError("offline", operation=db.DatabaseOperation.SESSION)

    assert error.operation == "db.session"
    assert type(error.operation) is str
