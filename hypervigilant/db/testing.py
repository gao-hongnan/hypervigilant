"""Test seams: a real database under a transaction that never commits.

There is deliberately no in-memory fake session here. A fake that does not execute
SQL asserts nothing about the queries under test -- it verifies that the code called
the mock the way the test author expected it to, which is a tautology. The isolation
mechanism is a real connection, a real transaction, and a rollback.

Nor is there a SQLite driver. :class:`~hypervigilant.db.config.AsyncDriver` lists only
PostgreSQL drivers, and that is the point: SQLite has no ``40001``, no ``40P01``,
different constraint-violation messages and no ``JSONB``, so a suite that passes on
SQLite can miss every behaviour in :mod:`hypervigilant.db.errors` and
:mod:`hypervigilant.db.transaction`. Integration tests run against a real PostgreSQL through
testcontainers.

Fixture scoping
---------------
The event-loop fixture's scope must be greater than or equal to the engine fixture's
scope. An engine built on one loop and used on another raises ``got Future attached
to a different loop`` -- and the classic trigger is exactly the combination this
module invites: a session-scoped container with pytest-asyncio's default
function-scoped loop::

    @pytest.fixture(scope="session")
    async def db() -> AsyncGenerator[Database]:
        with PostgresContainer("postgres:17") as container:
            async with Database(config_for(container)) as database:
                yield database

    @pytest.fixture
    async def sessions(db: Database) -> AsyncGenerator[SessionProvider]:
        async with arollback_scope(db) as provider:
            yield provider
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING

from sqlmodel.ext.asyncio.session import AsyncSession

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

    from .health import HealthReport
    from .runtime.asyncio import Database
    from .session import SessionProvider

__all__ = ["StaticHealthProbe", "arollback_scope"]


class _RollbackProvider:
    """A :class:`~hypervigilant.db.session.SessionProvider` bound to one open connection.

    Every session it hands out joins the caller's outer transaction as a savepoint, so
    application code under test may call ``commit()`` normally without escaping
    isolation.
    """

    __slots__ = ("_connection",)

    def __init__(self, connection: AsyncConnection) -> None:
        self._connection = connection

    def session(self) -> AbstractAsyncContextManager[AsyncSession]:
        return AsyncSession(
            bind=self._connection,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        )


@asynccontextmanager
async def arollback_scope(db: Database) -> AsyncGenerator[SessionProvider]:
    """Yield a provider whose every session rolls back when the block exits.

    ``join_transaction_mode="create_savepoint"`` is the SQLAlchemy 2.0 mechanism that
    replaced the old nested-savepoint-plus-event-listener recipe. Without it, the
    first ``session.commit()`` inside a test commits the *outer* transaction and
    isolation is silently gone for every subsequent test -- a failure that presents as
    order-dependent flakiness rather than as an error.

    Parameters
    ----------
    db
        An initialised :class:`~hypervigilant.db.runtime.asyncio.Database`.

    Examples
    --------
    >>> import inspect
    >>> inspect.isasyncgenfunction(arollback_scope.__wrapped__)
    True
    """
    async with db.engine.connect() as connection:
        transaction = await connection.begin()
        try:
            yield _RollbackProvider(connection)
        finally:
            await transaction.rollback()


class StaticHealthProbe:
    """A :class:`~hypervigilant.db.health.HealthProbe` that returns a fixed report.

    The only way to exercise a degraded-readiness path without breaking a real
    database.

    Examples
    --------
    >>> import asyncio
    >>> from hypervigilant.db.health import HealthReport
    >>> probe = StaticHealthProbe(HealthReport(ok=False, detail="down", latency_ms=None, pool=None))
    >>> asyncio.run(probe.acheck()).detail
    'down'
    """

    __slots__ = ("_report",)

    def __init__(self, report: HealthReport) -> None:
        self._report = report

    async def acheck(self) -> HealthReport:
        return self._report
