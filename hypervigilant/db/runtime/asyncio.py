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
from types import TracebackType
from typing import TYPE_CHECKING, Self

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from ...loggers import get_logger
from ..engine import build_engine, build_session_factory
from ..errors import translate_error
from ..health import PoolHealthProbe
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
        "_engine",
        "_health",
        "_lock",
        "_reader_engine",
        "_reader_health",
        "_reader_sessions",
        "_sessions",
    )

    def __init__(self, config: DBConfig) -> None:
        self._config = config
        self._engine: AsyncEngine | None = None
        self._sessions: SessionFactory | None = None
        self._health: HealthProbe | None = None
        self._reader_engine: AsyncEngine | None = None
        self._reader_sessions: SessionFactory | None = None
        self._reader_health: HealthProbe | None = None
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        target = f"{self._config.host}:{self._config.port}/{self._config.database}"
        return (
            f"Database(driver={self._config.driver.value!r}, target={target!r}, initialized={self._engine is not None})"
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
        if self._engine is None:
            reason = "Database.ainitialize() has not been awaited; there is no engine yet."
            raise RuntimeError(reason)
        return self._engine

    @property
    def health(self) -> HealthProbe:
        """The readiness probe bound to this engine."""
        if self._health is None:
            reason = "Database.ainitialize() has not been awaited; there is no health probe yet."
            raise RuntimeError(reason)
        return self._health

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
            if self._engine is not None:
                return
            engine = build_engine(self._config)
            try:
                async with engine.connect() as connection:
                    await connection.execute(_STARTUP_PROBE)
            except SQLAlchemyError as exc:
                await engine.dispose()
                raise translate_error(exc, operation="db.initialize") from exc
            self._engine = engine
            self._sessions = build_session_factory(engine)
            self._health = PoolHealthProbe(engine)

            reader_config = self._config.reader_config()
            if reader_config is not None:
                reader_engine = build_engine(reader_config)
                try:
                    async with reader_engine.connect() as connection:
                        await connection.execute(_STARTUP_PROBE)
                except SQLAlchemyError as exc:
                    await reader_engine.dispose()
                    await engine.dispose()
                    self._engine = self._sessions = self._health = None
                    raise translate_error(exc, operation="db.initialize.reader") from exc
                self._reader_engine = reader_engine
                self._reader_sessions = build_session_factory(reader_engine)
                self._reader_health = PoolHealthProbe(reader_engine, operation="db.health.reader")

            logger.info("database ready", db=self._config.model_dump(mode="json"))

    async def aclose(self) -> None:
        """Dispose the engine. Idempotent, and safe before :meth:`ainitialize`."""
        async with self._lock:
            if self._engine is None:
                return
            await self._engine.dispose()
            if self._reader_engine is not None:
                await self._reader_engine.dispose()
            self._engine = None
            self._sessions = None
            self._health = None
            self._reader_engine = None
            self._reader_sessions = None
            self._reader_health = None
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
        return self._reader_health

    def _factory(self) -> SessionFactory:
        if self._sessions is None:
            reason = "Database.ainitialize() has not been awaited; there is no session factory yet."
            raise RuntimeError(reason)
        return self._sessions

    def session(self) -> AbstractAsyncContextManager[AsyncSession]:
        """Open a session with no transaction begun.

        For reads. Writes go through :meth:`begin` so the transaction boundary is
        visible at the call site.
        """
        return asession_scope(self._factory(), operation="db.session")

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
        factory = self._reader_sessions
        if factory is None:
            return self.session()
        return asession_scope(factory, operation="db.reader_session")

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
        return aunit_of_work(self._factory(), operation="db.transaction")

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
