"""The engine-lifetime owner.

Concrete, not a Protocol: there is exactly one correct way to own an
:class:`~sqlalchemy.ext.asyncio.AsyncEngine`, and naming an abstraction whose only
implementation is the thing itself buys nothing. The useful substitutability exists
anyway, because :class:`Database` satisfies both
:class:`~hypervigilant.db.session.SessionProvider` and
:class:`~hypervigilant.db.health.HealthProbe` structurally.

Lifecycle vocabulary is ``ainitialize`` / ``aclose``, matching
:class:`hypervigilant.circuit_breaker.AsyncBreakerRegistry` rather than obskit's sync
``setup`` / ``shutdown`` :class:`LifecycleStage`. ``AsyncEngine.dispose()`` is a
coroutine and the startup probe is I/O, so the sync protocol could only be satisfied
through a ``run_sync`` shim that buys nothing -- and an application wiring both
subpackages of this distribution should read the same way twice.

No module-level singleton
-------------------------
An engine holds a connection pool, and a module-level one outlives the application
that configured it -- in tests, one suite's pool serving another suite's database. It
also binds the pool to whichever event loop imported the module, and makes
configuration a side effect of import order. Most decisively, it makes the bulkhead
pattern unrepresentable: two :class:`Database` instances with different pool sizes,
one for OLTP and one for reporting, is the shape that keeps a slow analytical query
from starving request traffic.
"""

from __future__ import annotations

import asyncio
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Self

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from ...loggers import get_logger
from ..engine import build_engine, build_session_factory
from ..errors import translate_error
from ..health import PoolHealthProbe
from ..operations import DatabaseOperation
from ..session import asession_scope
from ..transaction import aunit_of_work

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine
    from sqlmodel.ext.asyncio.session import AsyncSession

    from ..config import DBConfig
    from ..health import HealthProbe
    from ..transaction import TransactionScope
    from ..types import SessionFactory

__all__ = ["Database"]

logger = get_logger(__name__)

_STARTUP_PROBE = text("SELECT 1")


@dataclass(frozen=True, slots=True)
class _DatabaseResources:
    """The engine and the two services whose lifetime it owns."""

    engine: AsyncEngine
    sessions: SessionFactory
    health: HealthProbe


async def _build_and_probe(
    config: DBConfig,
    *,
    operation: str,
    health_operation: str = DatabaseOperation.HEALTH,
) -> _DatabaseResources:
    """Build a complete resource bundle after proving its engine is reachable."""
    engine = build_engine(config)
    try:
        async with engine.connect() as connection:
            await connection.execute(_STARTUP_PROBE)
        return _DatabaseResources(
            engine=engine,
            sessions=build_session_factory(engine),
            health=PoolHealthProbe(engine, operation=health_operation),
        )
    except SQLAlchemyError as exc:
        await engine.dispose()
        raise translate_error(exc, operation=operation) from exc
    except BaseException:
        await engine.dispose()
        raise


class Database:
    """Owns one engine, its session factory, and their disposal.

    Construction does no I/O and builds nothing: a constructor that half-initialises
    makes "was this ever started" a question every caller has to ask.

    Parameters
    ----------
    config
        The validated connection configuration.

    Examples
    --------
    >>> from pydantic import SecretStr
    >>> from hypervigilant.db.config import DBConfig
    >>> db = Database(DBConfig(host="db", user="app", password=SecretStr("s"), database="app"))
    >>> db.config.host
    'db'
    >>> db.engine
    Traceback (most recent call last):
        ...
    RuntimeError: Database.ainitialize() has not been awaited; there is no engine yet.

    The repr never renders the URL, so a credential cannot reach a log through it:

    >>> repr(db)
    "Database(driver='postgresql+asyncpg', target='db:5432/app', initialized=False)"
    """

    __slots__ = (
        "_config",
        "_lock",
        "_reader",
        "_writer",
    )

    def __init__(self, config: DBConfig) -> None:
        self._config = config
        self._writer: _DatabaseResources | None = None
        self._reader: _DatabaseResources | None = None
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        target = f"{self._config.host}:{self._config.port}/{self._config.database}"
        return (
            f"Database(driver={self._config.driver.value!r}, target={target!r}, initialized={self._writer is not None})"
        )

    @property
    def config(self) -> DBConfig:
        """The configuration this instance was built from."""
        return self._config

    @property
    def engine(self) -> AsyncEngine:
        """The live engine.

        Public so obskit can instrument it and Alembic's ``env.py`` can borrow it --
        which is how this package stays instrumentable without depending on any
        telemetry library.

        Raises
        ------
        RuntimeError
            Before :meth:`ainitialize`. Returning ``None`` would push an ``is None``
            check into every caller.
        """
        if self._writer is None:
            reason = "Database.ainitialize() has not been awaited; there is no engine yet."
            raise RuntimeError(reason)
        return self._writer.engine

    @property
    def health(self) -> HealthProbe:
        """The readiness probe bound to this engine."""
        if self._writer is None:
            reason = "Database.ainitialize() has not been awaited; there is no health probe yet."
            raise RuntimeError(reason)
        return self._writer.health

    async def ainitialize(self) -> None:
        """Build the engine and prove the database is reachable.

        Idempotent under a lock, so concurrent startup paths cannot race two engines
        into existence. The ``SELECT 1`` is deliberate rather than lazy: a
        misconfigured database should fail at process start, where a deploy can roll
        back, not at the first request.

        Raises
        ------
        DatabaseError
            If the probe cannot complete. The engine is disposed before raising, so a
            failed start leaks no connections.
        """
        async with self._lock:
            if self._writer is not None:
                return
            writer = await _build_and_probe(self._config, operation=DatabaseOperation.INITIALIZE)
            reader: _DatabaseResources | None = None
            try:
                reader_config = self._config.reader_config()
                if reader_config is not None:
                    reader = await _build_and_probe(
                        reader_config,
                        operation=DatabaseOperation.INITIALIZE_READER,
                        health_operation=DatabaseOperation.HEALTH_READER,
                    )
            except BaseException:
                await writer.engine.dispose()
                raise

            self._writer = writer
            self._reader = reader

            logger.info("database ready", db=self._config.model_dump(mode="json"))

    async def aclose(self) -> None:
        """Dispose the engine. Idempotent, and safe before :meth:`ainitialize`."""
        async with self._lock:
            if self._writer is None:
                return
            writer = self._writer
            reader = self._reader
            try:
                await writer.engine.dispose()
            finally:
                try:
                    if reader is not None:
                        await reader.engine.dispose()
                finally:
                    self._writer = None
                    self._reader = None
            logger.info("database closed", dsn_target=f"{self._config.host}:{self._config.port}")

    @property
    def reader_health(self) -> HealthProbe | None:
        """The reader's probe, or :data:`None` when no reader is configured.

        Separate from :attr:`health` because readiness is a question about the
        *writer*: an unreachable reader degrades throughput, since
        :meth:`reader_session` falls back to the writer, whereas an unreachable
        writer means this instance cannot serve. Folding them into one report would
        take an instance out of rotation for a condition it can absorb.
        """
        return self._reader.health if self._reader is not None else None

    def _factory(self) -> SessionFactory:
        if self._writer is None:
            reason = "Database.ainitialize() has not been awaited; there is no session factory yet."
            raise RuntimeError(reason)
        return self._writer.sessions

    def session(self) -> AbstractAsyncContextManager[AsyncSession]:
        """Open a session with no transaction begun.

        For reads. Writes go through :meth:`begin` so the transaction boundary is
        visible at the call site.
        """
        return asession_scope(self._factory(), operation=DatabaseOperation.SESSION)

    def reader_session(self) -> AbstractAsyncContextManager[AsyncSession]:
        """Open a read-only session against the reader endpoint.

        Falls back to the writer when no reader is configured, which is safe in the
        one direction that matters: the writer can always serve a read correctly, it
        is merely more loaded. The reverse -- routing a write to a replica -- is not
        expressible here at all, because :meth:`begin` has no reader variant.

        **Replication lag is yours to reason about.** This method is explicit rather
        than automatic precisely because the failure it invites is silent: a caller
        that writes a row and immediately reads it back through a replica gets a
        stale answer, or nothing. That reproduces only under lag, which means never
        on a developer machine and always under production load. Routing by
        overriding ``Session.get_bind()`` on flush state would make the decision
        invisible at the call site; requiring a different method name makes it a
        thing somebody chose.
        """
        factory = self._reader.sessions if self._reader is not None else self._factory()
        return asession_scope(factory, operation=DatabaseOperation.READER_SESSION)

    def begin(self) -> TransactionScope:
        """Start a transaction.

        Always against the **writer**, and there is deliberately no reader variant:
        an Aurora replica rejects writes with ``cannot execute INSERT in a read-only
        transaction``, so a transaction that could be routed to one is a bug waiting
        for the first write in an otherwise read-shaped unit of work.

        Pass this method *uncalled* to
        :func:`~hypervigilant.db.transaction.atransactional` -- it is the
        :data:`~hypervigilant.db.transaction.ScopeFactory` that makes retrying a
        poisoned session inexpressible.
        """
        return aunit_of_work(self._factory(), operation=DatabaseOperation.TRANSACTION)

    async def __aenter__(self) -> Self:
        await self.ainitialize()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()
