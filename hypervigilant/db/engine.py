"""URL assembly and engine construction: the substrate's only socket-facing code.

Three functions, each a pure function of a :class:`~hypervigilant.db.config.DBConfig`.
Nothing here owns a lifetime -- that is :class:`hypervigilant.db.runtime.asyncio.Database`'s
job. The split exists so Alembic's ``env.py`` can build an engine without standing
up the full facade.

This is mostly SQLAlchemy rather than SQLModel, and that is not a lapse from being
"fully SQLModel": SQLModel is a declarative layer over SQLAlchemy's ORM, and nothing
here is a declaration. ``sqlmodel`` exports no ``create_async_engine``,
``async_sessionmaker``, ``AsyncEngine`` or ``URL`` -- there is no async-engine story
in its surface at all. Where SQLModel *does* have something to offer it is used:
:func:`build_session_factory` binds SQLModel's :class:`AsyncSession` for its typed
``exec()``.

Why SSL does not go in the URL
------------------------------
The prior implementation passed ``query={"ssl": config.sslmode}``. Verified against
SQLAlchemy 2.0.52: the asyncpg dialect performs *no* SSL translation -- every URL
query key is forwarded verbatim as a keyword argument to ``asyncpg.connect()``
(``dialects/postgresql/asyncpg.py:1133-1161``). Two consequences followed. A value of
``"require"`` reached asyncpg's ``SSLMode.parse`` and produced
``check_hostname=False, verify_mode=CERT_NONE`` -- encryption with no authentication,
indistinguishable from working TLS. And ``sslmode``/``sslrootcert`` are not asyncpg
keyword arguments at all (they are DSN-only), so naming the field's own spelling
raised ``TypeError`` at first connect. ``sslmode`` support was never added to the
dialect, on 2.0.52 or on ``main``.

So anything that actually authenticates the server is built here as an
:class:`ssl.SSLContext` and passed through ``connect_args``, which a query string
structurally cannot carry.
"""

from __future__ import annotations

import ssl
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from sqlalchemy import URL, event
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from sqlmodel.ext.asyncio.session import AsyncSession

from hypervigilant.db.config import AsyncDriver, DBConfig, PoolingMode, SSLConfig, SSLMode
from hypervigilant.db.errors import translate_error
from hypervigilant.loggers import get_logger

if TYPE_CHECKING:
    from sqlalchemy.engine.interfaces import ExceptionContext

    from hypervigilant.db.types import SessionFactory

__all__ = ["async_url_for", "build_engine", "build_session_factory"]

logger = get_logger(__name__)

_VERIFYING_MODES = frozenset({SSLMode.VERIFY_CA, SSLMode.VERIFY_FULL})


def async_url_for(config: DBConfig) -> URL:
    """Assemble the connection URL from the configured components.

    The one place a database address is composed, which is what lets
    :class:`~hypervigilant.db.config.DBConfig` be a host, a port, a role and a
    password rather than a hand-written string. Two hazards close by building it
    here.

    :meth:`~sqlalchemy.URL.create` percent-encodes the credentials, so a password
    containing ``@``, ``:``, ``/`` or ``?`` connects. Written into a DSN those
    characters are *syntax*: ``pw@ss`` truncates the password at the ``@`` and reads
    the rest as part of the host. The URL still parses, so the only symptom is an
    authentication failure that looks like a wrong password rather than an unescaped
    one.

    And the result is a :class:`~sqlalchemy.URL`, not a string. Its ``repr`` masks the
    password, so a URL reaching a log or a traceback cannot leak the credential --
    rendering it requires ``render_as_string(hide_password=False)``, which nothing but
    the driver does.

    Returns
    -------
        A URL carrying no query string. SSL and server settings travel through
        ``connect_args`` (see the module docstring); the one dialect knob that
        belongs in a query is applied by :func:`build_engine`.

    Examples
    --------
    >>> from pydantic import SecretStr
    >>> url = async_url_for(
    ...     DBConfig(host="db", user="app", password=SecretStr("p@ss/word"), database="app")
    ... )
    >>> url.drivername
    'postgresql+asyncpg'
    >>> str(url)
    'postgresql+asyncpg://app:***@db:5432/app'
    >>> "p@ss" in f"{url}"
    False
    >>> url.render_as_string(hide_password=False).split("@")[0]
    'postgresql+asyncpg://app:p%40ss%2Fword'
    """
    return URL.create(
        config.driver.value,
        username=config.user,
        password=config.password.get_secret_value(),
        host=config.host,
        port=config.port,
        database=config.database,
    )


def _ssl_connect_argument(ssl_config: SSLConfig) -> ssl.SSLContext | str:
    """Build the ``ssl`` connect argument for asyncpg.

    Returns a real :class:`ssl.SSLContext` for the verifying modes, because that is
    the only shape that can carry a CA bundle -- the mode strings asyncpg accepts
    resolve ``verify-full`` against ``~/.postgresql/root.crt`` and fail when it is
    absent. Non-verifying modes pass their libpq spelling through unchanged.

    Examples
    --------
    >>> _ssl_connect_argument(SSLConfig(mode=SSLMode.REQUIRE))
    'require'
    """
    if ssl_config.mode not in _VERIFYING_MODES:
        return ssl_config.mode.value
    context = ssl.create_default_context(cafile=str(ssl_config.root_cert))
    context.check_hostname = ssl_config.mode is SSLMode.VERIFY_FULL
    context.verify_mode = ssl.CERT_REQUIRED
    if ssl_config.cert is not None and ssl_config.key is not None:
        context.load_cert_chain(certfile=str(ssl_config.cert), keyfile=str(ssl_config.key))
    return context


def _connect_args(config: DBConfig) -> dict[str, Any]:
    """Assemble driver keyword arguments.

    Returns ``dict[str, Any]`` because that is what the contract is: the mapping is
    spread into a driver's ``connect()`` whose keyword set is not statically
    enumerable, and narrowing it would claim a shape the driver does not promise.
    This is the module's one I/O-boundary leak, and it is confined to this function.
    """
    args: dict[str, Any] = {"server_settings": config.server_settings()}
    match config.driver:
        case AsyncDriver.ASYNCPG:
            args["timeout"] = config.connect_timeout_seconds
            args["command_timeout"] = config.command_timeout_seconds
            args["ssl"] = _ssl_connect_argument(config.ssl)
            args["prepared_statement_cache_size"] = config.prepared_statement_cache_size
            if config.pooling_mode is PoolingMode.TRANSACTION:
                args["prepared_statement_name_func"] = _pgbouncer_statement_name
        case AsyncDriver.PSYCOPG:
            args["connect_timeout"] = int(config.connect_timeout_seconds)
            args["sslmode"] = config.ssl.mode.value
            if config.ssl.root_cert is not None:
                args["sslrootcert"] = str(config.ssl.root_cert)
    return args


def _pgbouncer_statement_name() -> str:
    """Return a collision-free prepared-statement name.

    asyncpg enumerates prepared statements in numeric order, so two client
    connections multiplexed onto one server connection by a transaction-pooling
    pgbouncer both reach for ``__asyncpg_stmt_1__``. The SQLAlchemy dialect
    documents this hook as the remedy (``dialects/postgresql/asyncpg.py:120-155``);
    :func:`build_engine` pairs it with :class:`~sqlalchemy.pool.NullPool`, which the
    same docs mark as required.
    """
    return f"__hypervigilant_{uuid4().hex}__"


def _translate_dbapi_error(context: ExceptionContext) -> None:
    """Replace a driver exception with this package's taxonomy, where it is raised.

    Disconnects are deliberately left alone: SQLAlchemy's pool relies on seeing its
    own exception to invalidate the connection and retry, so replacing it here would
    break ``pool_pre_ping``. Those surface at the scope boundary instead, where
    :func:`~hypervigilant.db.session.session_scope` translates them.
    """
    if context.is_disconnect or context.sqlalchemy_exception is None:
        return
    raise translate_error(context.sqlalchemy_exception, operation="db.statement") from context.original_exception


def _install_error_translation(engine: AsyncEngine) -> None:
    """Register :func:`_translate_dbapi_error` on ``engine``.

    ``handle_error`` fires at the point the exception is raised, and a handler that
    raises replaces the original. That is the difference between a caller writing
    ``except IntegrityViolationError`` around one INSERT and having to import
    ``sqlalchemy.exc`` to catch anything *inside* a session -- which is the leak the
    taxonomy exists to close, and which a scope-boundary-only translation left open.
    """
    event.listen(engine.sync_engine, "handle_error", _translate_dbapi_error)


def build_engine(config: DBConfig) -> AsyncEngine:
    """Build the async engine for ``config``.

    Not cached and not global: the caller owns the engine's lifetime, because an
    engine holds a connection pool and a module-level one would outlive the
    application that configured it -- which in tests means one suite's pool serving
    another suite's database. :class:`~hypervigilant.db.runtime.asyncio.Database` is
    the owner this package ships.

    Pooling is chosen by :attr:`~hypervigilant.db.config.DBConfig.pooling_mode`, and
    the branch is not cosmetic: ``pool_size``, ``max_overflow``, ``pool_timeout`` and
    ``pool_use_lifo`` all raise ``TypeError`` when passed alongside
    :class:`~sqlalchemy.pool.NullPool` (verified against 2.0.52), so a single
    unconditional kwarg set makes transaction-pooled and serverless deployments
    unreachable rather than merely untuned.

    ``pool_pre_ping`` and ``pool_recycle`` are both honoured under either pool. A
    pooled connection can be closed by the server, a failover, or an idle timeout
    while it sits in the pool; without pre-ping that surfaces as a failed *request*
    rather than as a connection the pool quietly replaces, and without recycle
    nothing retires a connection ahead of a load balancer's idle timeout.

    Examples
    --------
    >>> import contextlib, io
    >>> from pydantic import SecretStr
    >>> config = DBConfig(host="db", user="app", password=SecretStr("hunter2"), database="app")
    >>> log = io.StringIO()
    >>> with contextlib.redirect_stdout(log):
    ...     engine = build_engine(config)
    >>> engine.dialect.name
    'postgresql'
    >>> engine.pool.__class__.__name__
    'AsyncAdaptedQueuePool'

    The startup log line is an allow-list, so the credential is not in it:

    >>> "hunter2" in log.getvalue()
    False

    Transaction pooling switches the pool class, because the queue-pool kwargs
    would raise ``TypeError`` alongside ``NullPool``:

    >>> pooled = config.model_copy(
    ...     update={"pooling_mode": PoolingMode.TRANSACTION, "prepared_statement_cache_size": 0,
    ...             "idle_in_transaction_session_timeout_ms": None}
    ... )
    >>> with contextlib.redirect_stdout(io.StringIO()):
    ...     pooled_engine = build_engine(pooled)
    >>> pooled_engine.pool.__class__.__name__
    'NullPool'
    """
    logger.info("building the database engine", db=config.model_dump(mode="json"))

    shared: dict[str, Any] = {
        "echo": config.echo,
        "echo_pool": config.echo_pool,
        "pool_pre_ping": config.pool_pre_ping,
        "isolation_level": config.isolation_level.value,
        "connect_args": _connect_args(config),
    }
    if config.pool_recycle_seconds is not None:
        shared["pool_recycle"] = config.pool_recycle_seconds

    if config.pooling_mode is PoolingMode.TRANSACTION:
        engine = create_async_engine(async_url_for(config), poolclass=NullPool, **shared)
    else:
        engine = create_async_engine(
            async_url_for(config),
            pool_size=config.pool_size,
            max_overflow=config.max_overflow,
            pool_timeout=config.pool_timeout_seconds,
            pool_use_lifo=config.pool_use_lifo,
            **shared,
        )
    _install_error_translation(engine)
    return engine


def build_session_factory(engine: AsyncEngine) -> SessionFactory:
    """Return the factory sessions are opened from.

    ``expire_on_commit=False`` because the rows this serves are converted to frozen
    domain models and returned. With expiry on, reading any attribute after the
    commit triggers a refresh -- a second round trip per field, on an object whose
    values are already in hand, outside the session that could still lazily load
    them.

    ``class_`` is SQLModel's :class:`~sqlmodel.ext.asyncio.session.AsyncSession`, a
    subclass of SQLAlchemy's that adds ``exec()``. The factory itself is
    SQLAlchemy's -- SQLModel ships no ``async_sessionmaker`` -- so this is the one
    line that decides which session every query runs on. ``exec()`` is typed per
    statement kind, so ``select(Row)`` yields ``ScalarResult[Row]`` and an
    ``update()`` yields ``CursorResult``, results the generic ``execute()`` types as
    ``Any``. And SQLModel marks ``execute()`` deprecated with a PEP 702
    ``@deprecated`` that emits a real ``DeprecationWarning`` at call time -- under
    this project's ``filterwarnings = error`` that is a test failure, not a note.

    Examples
    --------
    >>> import contextlib, io
    >>> from pydantic import SecretStr
    >>> config = DBConfig(host="db", user="app", password=SecretStr("s"), database="app")
    >>> with contextlib.redirect_stdout(io.StringIO()):
    ...     factory = build_session_factory(build_engine(config))
    >>> factory.class_.__name__
    'AsyncSession'
    """
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
