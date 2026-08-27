"""The transaction boundary, and the only place retry is allowed to attach.

There is deliberately no ``UnitOfWork`` class here. ``async_sessionmaker.begin()``
already opens a session, begins a transaction, commits on clean exit, rolls back on
exception and closes -- a hand-written equivalent with its own ``__aenter__`` /
``__aexit__`` would re-implement shipped behaviour and add bookkeeping that can
disagree with it. This module owns only the two things SQLAlchemy does not provide:
exception translation, and a retry seam that cannot be attached at the wrong level.

The correctness property
------------------------
``40001`` serialization_failure and ``40P01`` deadlock_detected are retryable, and
only by re-running the **entire** transaction. After either, the transaction is
aborted and every subsequent statement on that session returns ``25P02
in_failed_sql_transaction``. Retrying a *statement* inside a failed transaction is
not merely useless: if it appears to work -- because it was the first statement, or
because the session was silently rolled back -- you have half-applied a unit of work
the domain believes is atomic. No test catches that, because the retry looks like it
succeeded.

So the goal is not to make retry-inside-a-transaction discouraged. It is to make it
unwritable, and :func:`atransactional` does that structurally:

1. The first parameter is a *factory*, not a scope. You cannot hand
   :func:`atransactional` a started transaction, so a retry cannot reuse a poisoned
   session -- each attempt calls the factory, which checks out a connection and
   issues ``BEGIN``.
2. ``work`` receives its session as an argument. There is no session in an enclosing
   frame to close over, because :class:`~hypervigilant.db.runtime.asyncio.Database`
   returns context managers rather than sessions.
3. Retryability is read from :attr:`~hypervigilant.db.errors.DatabaseError.retryable`,
   never from an ``isinstance`` tuple alone.

The precondition types cannot enforce
-------------------------------------
Re-running a transaction is safe only if ``work`` is a pure function of its inputs --
no email sent, no payment captured, no mutation of state accumulated by the previous
attempt. Nothing in the type system can check that, and a ``Pure[T]`` marker would be
theatre. The mitigation is architectural: side effects go through an outbox row
written *inside* the same transaction, so a rollback un-sends them.

Composition, not reimplementation
---------------------------------
The policies below are :class:`hypervigilant.retry.RetryConfig` instances and the
predicate is built with :func:`hypervigilant.retry.build_retry_condition`, so this
module contributes no retry configuration type of its own. Only the tenacity ``stop``
and ``wait`` strategy objects are constructed here, which is what
:func:`hypervigilant.retry.retry` asks its callers to supply.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING, Final

from sqlalchemy.exc import SQLAlchemyError
from tenacity import stop_after_attempt, wait_random_exponential

from ..retry import RetryConfig, RetryMode, build_retry_condition, retry
from .errors import DatabaseError, DatabaseUnavailableError, TransactionConflictError, translate_error

if TYPE_CHECKING:
    from sqlmodel.ext.asyncio.session import AsyncSession
    from tenacity import AsyncRetrying
    from tenacity.retry import RetryBaseT

    from .types import SessionFactory

__all__ = [
    "CONNECTION_RETRY",
    "SERIALIZATION_RETRY",
    "ScopeFactory",
    "TransactionScope",
    "atransactional",
    "aunit_of_work",
]

type TransactionScope = AbstractAsyncContextManager[AsyncSession]
"""An open transaction yielding its session.

Deliberately the stdlib type rather than a new Protocol. :func:`aunit_of_work`
satisfies it structurally -- and so, notably, does SQLAlchemy's own
``async_sessionmaker.begin()`` and any test double. Naming a Protocol here would have
been speculative generality over a shape the stdlib already spells.
"""

type ScopeFactory = Callable[[], TransactionScope]
"""The ability to *start* a transaction -- never a started one. See the module docstring."""

SERIALIZATION_RETRY: Final = RetryConfig(
    max_attempts=5,
    wait_min=0.005,
    wait_max=0.2,
    multiplier=0.005,
    retry_on_exceptions=(TransactionConflictError,),
    reraise=True,
)
"""Fast retry for lost races. The default.

Milliseconds, because the contending transaction has already committed or aborted by
the time this one learns it lost. Full jitter still matters: two transactions that
deadlocked will re-collide if they back off in lockstep.
"""

CONNECTION_RETRY: Final = RetryConfig(
    max_attempts=3,
    wait_min=0.2,
    wait_max=2.0,
    multiplier=0.2,
    retry_on_exceptions=(TransactionConflictError, DatabaseUnavailableError),
    reraise=True,
)
"""Slow retry that also tolerates an unreachable database.

Opt-in rather than default: an unavailable database means retrying adds load to
something already failing, and this project's convention is to fail fast on core
dependencies rather than mask them.
"""


def _retry_condition(policy: RetryConfig) -> RetryBaseT:
    """Build the two-axis predicate: the leaf is listed **and** declares itself retryable.

    Both guards are read because they answer different questions. The tuple says which
    failures *this policy* is willing to re-run; ``retryable`` says which failures are
    re-runnable at all. Reading only the tuple would let a policy re-enable retries for
    a leaf that turned non-retryable -- the bug where a unique-constraint violation
    burns the whole budget on an error that will never change.
    """
    allowed = policy.retry_on_exceptions or (DatabaseError,)

    def predicate(error: BaseException) -> bool:
        return isinstance(error, allowed) and isinstance(error, DatabaseError) and error.retryable

    return build_retry_condition(retry_if=predicate)


def _retrying(policy: RetryConfig) -> AsyncRetrying:
    """Map a :class:`~hypervigilant.retry.RetryConfig` onto a tenacity controller."""
    return retry(
        RetryMode.CONTEXT_MANAGER,
        stop=stop_after_attempt(policy.max_attempts),
        wait=wait_random_exponential(multiplier=policy.multiplier, max=policy.wait_max, exp_base=policy.exp_base),
        retry_condition=_retry_condition(policy),
        reraise=policy.reraise,
    )


@asynccontextmanager
async def aunit_of_work(factory: SessionFactory, *, operation: str) -> AsyncGenerator[AsyncSession]:
    """Open a session with a transaction: commit on clean exit, roll back on error.

    Thin on purpose -- ``async_sessionmaker.begin()`` does the session and transaction
    handling. The one thing SQLAlchemy does not do is translate its own exceptions,
    which is all this wrapper contributes.

    The ``try`` deliberately encloses the ``async with`` rather than sitting inside it,
    because that is what catches a failure raised by the **commit**. Under
    ``REPEATABLE READ`` and ``SERIALIZABLE`` a ``40001`` most often surfaces exactly
    there, not at any individual statement, so a translation that only wrapped the body
    would miss the most common conflict in the isolation levels that produce conflicts.

    Parameters
    ----------
    factory
        Session factory from :func:`~hypervigilant.db.engine.build_session_factory`.
    operation
        Label carried onto any translated error. Keyword-only.

    Examples
    --------
    >>> import inspect
    >>> inspect.isasyncgenfunction(aunit_of_work.__wrapped__)
    True
    """
    try:
        async with factory.begin() as session:
            yield session
    except SQLAlchemyError as exc:
        raise translate_error(exc, operation=operation) from exc


async def atransactional[ResultT](
    make_scope: ScopeFactory,
    work: Callable[[AsyncSession], Awaitable[ResultT]],
    *,
    policy: RetryConfig = SERIALIZATION_RETRY,
) -> ResultT:
    """Run ``work`` inside a transaction, re-running the whole thing on conflict.

    Parameters
    ----------
    make_scope
        A callable returning a *fresh* :data:`TransactionScope`. Pass the bound method
        (``db.begin``), uncalled -- that single token is the whole safety mechanism.
    work
        The unit of work. Must be a pure function of its inputs; see the module
        docstring on the precondition types cannot enforce.
    policy
        Backoff and eligibility. Keyword-only, defaults to :data:`SERIALIZATION_RETRY`.

    Returns
    -------
        Whatever ``work`` returned on the attempt that committed.

    Raises
    ------
    DatabaseError
        The last failure, once attempts are exhausted.

    Examples
    --------
    >>> import inspect
    >>> list(inspect.signature(atransactional).parameters)[0]
    'make_scope'
    >>> SERIALIZATION_RETRY.retry_on_exceptions
    (<class 'hypervigilant.db.errors.TransactionConflictError'>,)
    """
    async for attempt in _retrying(policy):
        with attempt:
            async with make_scope() as session:
                return await work(session)
    message = "atransactional exhausted its retry loop without an outcome"
    raise RuntimeError(message)
