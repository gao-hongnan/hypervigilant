"""Public exception types raised by the database module, and the translation boundary.

The module docstring of the transplanted ``db.py`` claimed the SQL toolkit was
"confined" to the substrate. That claim leaks the moment a caller writes
``except IntegrityError``: SQLAlchemy's exception hierarchy becomes part of the
domain's contract by usage, and no lint rule can undo it. Confinement is a
property of *what escapes*, not of what is imported, so nothing SQLAlchemy
raises may cross this package's boundary untranslated.

Two axes, deliberately kept apart
--------------------------------
A hierarchy answers "what kind of failure is this". It must not also answer
"may I run this again" -- conflating the two produces the classic bug where
``except DatabaseError`` inside a retry loop retries a unique-constraint
violation until the budget is gone. So *kind* lives in the class and
*retryability* lives in :attr:`DatabaseError.retryable`, a
:class:`~typing.ClassVar` read directly::

    if isinstance(exc, DatabaseError) and exc.retryable:

Adding a fifth retryable leaf then requires no change at any retry call site.

Departure from ``circuit_breaker/errors.py``
--------------------------------------------
That module argues for a flat hierarchy with no shared base, and for two types
it is right. Four leaves is already a tuple that every consumer's error
middleware must spell, and a fifth turns "map any database failure to 503" into
shotgun surgery across every application depending on this package. So there is
a base here -- but it is never raised directly, and the ``type(self) is``
guard in :meth:`DatabaseError.__init__` makes that a runtime fact rather than a
docstring promise.

Classification is by SQLSTATE, not by exception class
-----------------------------------------------------
Verified against SQLAlchemy 2.0.52 + asyncpg 0.31.0: every genuinely retryable
PostgreSQL condition -- ``40001`` serialization_failure, ``40P01`` deadlock,
``57P01`` admin_shutdown, ``08006`` connection_failure, ``53300``
too_many_connections -- arrives as a *bare* :class:`sqlalchemy.exc.DBAPIError`,
because the asyncpg dialect's translation map narrows only
``IntegrityConstraintViolationError``. Retry logic keyed on
:class:`sqlalchemy.exc.OperationalError` -- the intuitive choice, and what
every psycopg2-era recipe shows -- therefore retries *nothing* on asyncpg.

Examples
--------
>>> err = IntegrityViolationError("duplicate key", operation="orders.place", sqlstate="23505")
>>> err.retryable
False
>>> TransactionConflictError.retryable
True
>>> DatabaseError("nope", operation="x")
Traceback (most recent call last):
    ...
TypeError: DatabaseError is a base type; raise one of its leaves.
"""

from __future__ import annotations

from typing import ClassVar, Final

from sqlalchemy.exc import DBAPIError, InterfaceError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SATimeoutError

__all__ = [
    "DatabaseError",
    "DatabaseUnavailableError",
    "IntegrityViolationError",
    "TransactionConflictError",
    "UnclassifiedDatabaseError",
    "translate_error",
]

_CONNECTION_CLASS: Final = "08"
"""SQLSTATE class 08 -- connection exception. The whole class is retryable."""

_INTEGRITY_CLASS: Final = "23"
"""SQLSTATE class 23 -- integrity constraint violation. Never retryable."""

_CONFLICT_CODES: Final[frozenset[str]] = frozenset({"40001", "40P01"})
"""serialization_failure and deadlock_detected.

Both are retryable, and both are retryable *only* by re-running the entire
transaction -- see :mod:`hypervigilant.db.transaction` for why that is a structural
constraint rather than a convention.
"""

_UNAVAILABLE_CODES: Final[frozenset[str]] = frozenset({"53300", "53400", "57P01", "57P02", "57P03", "55P03"})
"""too_many_connections, configuration_limit_exceeded, the three shutdown codes, lock_not_available."""


class DatabaseError(Exception):
    """Base type for every failure this package reports.

    Never raised directly; the guard in :meth:`__init__` enforces that at
    runtime, because Python has no ``sealed`` and a two-line check is closer
    to one than a comment is.

    Parameters
    ----------
    message
        Human-readable summary. Keyword-free positional, as with any exception.
    operation
        Caller-supplied label naming *which* call failed (``"orders.place"``,
        ``"readyz.ping"``), so a log line is actionable without a traceback.
        Keyword-only.
    sqlstate
        The five-character PostgreSQL SQLSTATE, when one was available.
        Preserved even for :class:`UnclassifiedDatabaseError` so the
        unclassified bucket is greppable and the decision to add a new leaf is
        evidence-driven. Keyword-only.

    Attributes
    ----------
    retryable
        Whether re-running the failed unit of work could succeed. Read by
        :func:`hypervigilant.db.transaction.transactional`; never inferred from the
        class hierarchy.
    """

    __slots__ = ("operation", "sqlstate")

    retryable: ClassVar[bool] = False

    operation: str
    sqlstate: str | None

    def __init__(self, message: str, *, operation: str, sqlstate: str | None = None) -> None:
        if type(self) is DatabaseError:
            reason = "DatabaseError is a base type; raise one of its leaves."
            raise TypeError(reason)
        super().__init__(message)
        self.operation = operation
        self.sqlstate = sqlstate


class DatabaseUnavailableError(DatabaseError):
    """The database could not be reached, or refused to serve the request.

    Covers connection loss, pool-checkout timeout, administrative shutdown and
    connection-limit exhaustion. Retryable, but with a *slow* policy: this
    condition means the database is down or saturated, so retrying quickly is a
    load amplifier.

    Examples
    --------
    >>> DatabaseUnavailableError.retryable
    True
    """

    __slots__ = ()

    retryable: ClassVar[bool] = True


class TransactionConflictError(DatabaseError):
    """The transaction lost a race and must be re-run in full.

    ``40001`` serialization_failure or ``40P01`` deadlock_detected. Retryable
    with a *fast* policy: the contending transaction has already resolved, so
    the right move is to try again in milliseconds. Jitter still matters --
    two transactions that deadlocked will re-collide if they back off in
    lockstep.

    Examples
    --------
    >>> TransactionConflictError.retryable
    True
    """

    __slots__ = ()

    retryable: ClassVar[bool] = True


class IntegrityViolationError(DatabaseError):
    """A constraint rejected the write.

    Not retryable, and this is the leaf whose ``retryable = False`` earns the
    two-axis design: it is a subclass of :class:`DatabaseError`, so a broad
    ``except DatabaseError`` catches it, and a retry loop that reads
    ``exc.retryable`` still declines to burn its budget on it.

    Parameters
    ----------
    constraint
        The violated constraint's name when the driver reported one. Keyword-only.

    Examples
    --------
    >>> err = IntegrityViolationError(
    ...     "duplicate key", operation="orders.place", sqlstate="23505", constraint="uq_orders_ref"
    ... )
    >>> (err.retryable, err.constraint)
    (False, 'uq_orders_ref')
    """

    __slots__ = ("constraint",)

    constraint: str | None

    def __init__(
        self,
        message: str,
        *,
        operation: str,
        sqlstate: str | None = None,
        constraint: str | None = None,
    ) -> None:
        super().__init__(message, operation=operation, sqlstate=sqlstate)
        self.constraint = constraint


class UnclassifiedDatabaseError(DatabaseError):
    """A driver failure outside the classified set.

    Deliberately not a shrug. The SQLSTATE is preserved in a structured field
    and reaches the log record, so the bucket can be grouped by code after a
    month in production and a sixth classification earned with evidence. The
    alternative -- mapping fifty DBAPI classes up front -- is a table nobody
    maintains and everybody trusts.

    Examples
    --------
    >>> UnclassifiedDatabaseError.retryable
    False
    """

    __slots__ = ()

    retryable: ClassVar[bool] = False


def _driver_chain(error: BaseException) -> tuple[BaseException | None, ...]:
    """Return the exceptions that might carry driver metadata, nearest first.

    There are up to three wrappers between the caught exception and the one asyncpg
    actually raised. SQLAlchemy wraps the DBAPI shim in ``exc.IntegrityError`` and
    exposes it as ``.orig``; the shim itself was raised ``from`` the real
    ``asyncpg.exceptions.UniqueViolationError``, which is the only object carrying
    ``constraint_name``. Which layer answers depends on where the error was caught --
    the ``handle_error`` event hands over a different link than a ``try`` around a
    session -- so both are searched rather than guessed.

    Attributes are read dynamically on purpose: narrowing with ``isinstance`` would
    mean importing ``asyncpg`` purely to classify an error, and the driver is an
    optional, swappable component. Both supported PostgreSQL drivers spell these
    attributes the same way.
    """
    orig = getattr(error, "orig", None)
    return (error, orig, getattr(orig, "__cause__", None), error.__cause__)


def _driver_attribute(error: BaseException, name: str) -> str | None:
    """Return the first non-empty ``name`` found along :func:`_driver_chain`."""
    for candidate in _driver_chain(error):
        if candidate is None:
            continue
        value = getattr(candidate, name, None)
        if isinstance(value, str) and value:
            return value
    return None


def _sqlstate_of(error: BaseException) -> str | None:
    """Read the five-character SQLSTATE, wherever in the wrapper chain it sits."""
    return _driver_attribute(error, "sqlstate")


def _constraint_of(error: BaseException) -> str | None:
    """Read the violated constraint name, wherever in the wrapper chain it sits."""
    return _driver_attribute(error, "constraint_name")


def translate_error(error: SQLAlchemyError, *, operation: str) -> DatabaseError:
    """Map a SQLAlchemy failure onto this package's taxonomy.

    Classification is by SQLSTATE *class* -- the first two characters -- because
    that is a small, standard, stable set, whereas DBAPI exception types are
    none of those things. Exception type is consulted only where there is no
    SQLSTATE to read, which is exactly the case where no connection was ever
    established.

    Parameters
    ----------
    error
        The caught SQLAlchemy exception. Keyword-free positional.
    operation
        Label identifying the failing call, carried onto the result. Keyword-only.

    Returns
    -------
        A :class:`DatabaseError` leaf. Never the base class. The caller is
        expected to ``raise ... from error`` so ``__cause__`` retains the
        original for debugging -- available, but not part of the contract.

    Examples
    --------
    >>> from sqlalchemy.exc import SQLAlchemyError
    >>> class _Orig:
    ...     sqlstate = "40001"
    >>> class _Wrapped(SQLAlchemyError):
    ...     orig = _Orig()
    >>> translated = translate_error(_Wrapped("conflict"), operation="orders.place")
    >>> (type(translated).__name__, translated.retryable, translated.sqlstate)
    ('TransactionConflictError', True, '40001')
    """

    sqlstate = _sqlstate_of(error)
    message = str(error)

    if sqlstate is not None:
        if sqlstate in _CONFLICT_CODES:
            return TransactionConflictError(message, operation=operation, sqlstate=sqlstate)
        if sqlstate.startswith(_INTEGRITY_CLASS):
            return IntegrityViolationError(
                message,
                operation=operation,
                sqlstate=sqlstate,
                constraint=_constraint_of(error),
            )
        if sqlstate.startswith(_CONNECTION_CLASS) or sqlstate in _UNAVAILABLE_CODES:
            return DatabaseUnavailableError(message, operation=operation, sqlstate=sqlstate)
        return UnclassifiedDatabaseError(message, operation=operation, sqlstate=sqlstate)

    if isinstance(error, SATimeoutError | InterfaceError):
        return DatabaseUnavailableError(message, operation=operation)
    if isinstance(error, DBAPIError) and error.connection_invalidated:
        return DatabaseUnavailableError(message, operation=operation)
    return UnclassifiedDatabaseError(message, operation=operation)
