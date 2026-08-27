"""Session provision, and the single point where driver failures become domain errors.

The seam is a one-method :class:`SessionProvider` Protocol rather than a concrete
type, because two implementations genuinely exist: the production
:class:`~hypervigilant.db.runtime.asyncio.Database` and the rollback-scoped provider
in :mod:`hypervigilant.db.testing`. Consumers -- repositories, FastAPI dependencies,
health probes -- depend on the Protocol.

Why translation lives in a context-manager body
-----------------------------------------------
Three placements were considered.

A subclassed ``AsyncSession`` would need ``exec``, ``execute``, ``flush``, ``commit``,
``get`` and ``scalars`` overridden -- six override points that drift the moment
SQLAlchemy adds a seventh. ``@override`` catches renames, not additions.

A ``@translating`` decorator on repository methods is opt-in, so a method that
forgets it leaks -- and the forgetting is invisible until production.

The context-manager body has exactly one catch site, zero override points, and it
catches everything raised *inside* the ``async with`` -- including the caller's own
``await session.exec(...)``, which is where the exception actually originates.

The honest limitation
---------------------
An exception raised *after* the scope exits is not translated. The canonical case is
a lazy relationship load on a detached instance, which raises ``MissingGreenlet``.
This is why ``expire_on_commit=False`` matters, why the convention is to convert
rows to domain models *inside* the scope, and why ``lazy="raise"`` on every
relationship is recommended -- it converts a production surprise into a loud failure
at first access.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from sqlalchemy.exc import SQLAlchemyError

from hypervigilant.db.errors import translate_error

if TYPE_CHECKING:
    from sqlmodel.ext.asyncio.session import AsyncSession

    from hypervigilant.db.types import SessionFactory

__all__ = ["SessionProvider", "session_scope"]


@runtime_checkable
class SessionProvider(Protocol):
    """Hands out sessions. One method, so a test double is trivially writable.

    Note the method is *sync* and returns an async context manager, rather than
    being ``async def``. Call sites read ``async with provider.session() as s:``
    either way, and the sync form keeps implementations from needing a coroutine
    that does nothing but return a context manager.

    Examples
    --------
    >>> hasattr(SessionProvider, "session")
    True
    """

    def session(self) -> AbstractAsyncContextManager[AsyncSession]:
        """Open a session. No transaction is begun; see :func:`~hypervigilant.db.transaction.unit_of_work`."""
        ...


@asynccontextmanager
async def session_scope(factory: SessionFactory, *, operation: str) -> AsyncGenerator[AsyncSession]:
    """Yield a session, translating any SQLAlchemy failure on the way out.

    Parameters
    ----------
    factory
        The session factory from :func:`~hypervigilant.db.engine.build_session_factory`.
    operation
        Label carried onto any raised :class:`~hypervigilant.db.errors.DatabaseError`,
        so a log line names the failing call without a traceback. Keyword-only.

    Raises
    ------
    DatabaseError
        One of its leaves, always ``from`` the original SQLAlchemy exception.
    """
    async with factory() as session:
        try:
            yield session
        except SQLAlchemyError as exc:
            raise translate_error(exc, operation=operation) from exc
