"""Closed vocabulary for package-owned database operation labels."""

from enum import StrEnum

__all__ = ["DatabaseOperation"]


class DatabaseOperation(StrEnum):
    """Stable labels emitted by the database substrate itself."""

    STATEMENT = "db.statement"
    SESSION = "db.session"
    READER_SESSION = "db.reader_session"
    TRANSACTION = "db.transaction"
    INITIALIZE = "db.initialize"
    INITIALIZE_READER = "db.initialize.reader"
    HEALTH = "db.health"
    HEALTH_READER = "db.health.reader"
