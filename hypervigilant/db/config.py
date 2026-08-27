"""Connection configuration for the async SQL substrate.

This module is deliberately dependency-light: it imports ``pydantic`` and
``pydantic_settings`` and nothing else. A deployment built without the
``postgres`` extra can still import, construct and validate a
:class:`DBConfig` -- the substrate is a settings switch, and an unswitched
deployment must not need SQLAlchemy on the import path. Everything that
needs a :class:`sqlalchemy.URL` or an :class:`ssl.SSLContext` lives in
``hypervigilant.db.engine``, which is the module you cannot import without
the extra anyway.

Nothing here reads the environment
----------------------------------
:class:`DBConfig` is a frozen, closed :class:`~pydantic.BaseModel`, deliberately
*not* a :class:`~pydantic_settings.BaseSettings`. Two reasons, and the second is
the one that decides it.

A library that reads ``os.environ`` the moment somebody writes ``DBConfig()``
cannot be constructed deterministically in a test, and cannot tell "you forgot the
host" apart from "the ambient environment happened to supply one".

More importantly, the environment is the *application's* namespace, not ours.
Shipping a settings class here would mean asserting a prefix -- some
``HYPERVIGILANT_DB__*`` -- that competes with the one the consuming service already
has. An application with ``env_prefix="MYAPP_"`` would end up with two settings
roots and two places a database host could come from. So the edge stays where it
belongs, and :class:`DBConfig` is built to nest into whatever the consumer already
runs::

    from pydantic_settings import BaseSettings, SettingsConfigDict
    from hypervigilant.db import DBConfig

    class AppSettings(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="MYAPP_", env_nested_delimiter="__")
        db: DBConfig

    settings = AppSettings()          # MYAPP_DB__HOST, MYAPP_DB__PASSWORD, ...
    database = Database(settings.db)  # MYAPP_DB__READER__HOST for a replica

Because ``DBConfig`` is an ordinary model, that works with any prefix, with
``secrets_dir``, with a YAML source, or with no settings library at all.

Notes
-----
A sync driver is unrepresentable. :class:`AsyncDriver` is a closed
:class:`~enum.StrEnum` whose members are all async, so ``postgresql://``
(which SQLAlchemy resolves to the *synchronous* psycopg driver) cannot be
named. Without that, the engine builds, the pool opens, and the failure
surfaces at the first ``await`` as a type error several layers from the
configuration that caused it.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, ClassVar, Final, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

__all__ = [
    "AsyncDriver",
    "DBConfig",
    "IsolationLevel",
    "PoolingMode",
    "ReaderEndpoint",
    "SSLConfig",
    "SSLMode",
]

_MAX_IDENTIFIER_BYTES: Final = 63
"""PostgreSQL's ``NAMEDATALEN - 1``.

Bounds both ``application_name`` and every ``search_path`` element. The
server does not reject an over-long value, it silently truncates it, so two
workers named ``hypervigilant-ingest-shard-{0,1}`` become one indistinguishable
row in ``pg_stat_activity`` -- which is discovered during an incident, not
before one.
"""

_IDENTIFIER_PATTERN: Final = r"^[A-Za-z_][A-Za-z0-9_$]*$"
"""Unquoted SQL identifier syntax.

``search_path`` is delivered to the driver as a raw ``SET`` payload, so an
element containing a comma, a quote or a semicolon is a statement fragment,
not a name.
"""

_APPLICATION_NAME_PATTERN: Final = r"^[A-Za-z0-9._:-]+$"
"""Startup-packet-safe ``application_name`` syntax.

``,`` and ``=`` are the key/value separators of the libpq startup packet and
of asyncpg's ``server_settings`` mapping; a name containing either is a
parameter-injection primitive rather than a label.
"""

_MILLIS_PER_SECOND: Final = 1000
_DEFAULT_SEARCH_PATH: Final = ("public",)


type PortNumber = Annotated[int, Field(ge=1, le=65_535)]
"""A valid TCP port number."""

type PoolSize = Annotated[int, Field(ge=1, le=200)]
"""The bounded number of persistent connections in a pool."""

type MaxOverflow = Annotated[int, Field(ge=0, le=200)]
"""The bounded number of transient connections above the pool size."""


type PositiveMillis = Annotated[int, Field(ge=1, le=86_400_000)]
"""A server-side timeout in milliseconds, bounded to one day.

Milliseconds because that is the unit every PostgreSQL timeout GUC uses when
given a bare integer. ``statement_timeout = 30`` means thirty *milliseconds*,
and the field names here carry the unit so nobody discovers that from a
production traceback.

``ge=1`` rather than ``ge=0`` because ``0`` is PostgreSQL's spelling of
"disabled". Spelling it :data:`None` instead makes "I typed zero meaning
zero seconds" a validation error rather than an unlimited statement.
"""

type SQLIdentifier = Annotated[str, Field(min_length=1, max_length=_MAX_IDENTIFIER_BYTES, pattern=_IDENTIFIER_PATTERN)]
"""A single unquoted SQL identifier, length-bounded to ``NAMEDATALEN - 1``."""


def _reject_dsn_like_host(value: str, *, field: str) -> str:
    """Return a normalized bare host or reject DSN-shaped input."""
    host = value.strip()
    if not host:
        message = f"{field} must not be blank"
        raise ValueError(message)
    if "://" in host or "@" in host or "/" in host:
        message = f"{field} must be a bare hostname or address, not a DSN"
        raise ValueError(message)
    return host


class AsyncDriver(StrEnum):
    """The async SQLAlchemy drivers this package will build an engine for.

    A closed set, and closed is the whole point: SQLAlchemy picks its dialect
    from the URL scheme, and every synchronous scheme is absent here, so a
    configuration naming one does not validate.

    Members are :class:`~enum.StrEnum`, so a member *is* the ``drivername``
    string SQLAlchemy wants -- no ``str()`` at the call site, and no second
    place where the spelling could drift.

    Attributes
    ----------
    ASYNCPG
        ``postgresql+asyncpg``. The default; fastest, binary protocol,
        server-side prepared statements.
    PSYCOPG
        ``postgresql+psycopg``. psycopg 3's async mode. Worth having as a
        member rather than a pinned constant: it is the escape hatch when
        asyncpg's prepared-statement behaviour collides with a connection
        pooler.

    Examples
    --------
    >>> AsyncDriver.ASYNCPG
    <AsyncDriver.ASYNCPG: 'postgresql+asyncpg'>
    >>> f"{AsyncDriver.ASYNCPG}://..."
    'postgresql+asyncpg://...'
    >>> AsyncDriver("postgresql")
    Traceback (most recent call last):
        ...
    ValueError: 'postgresql' is not a valid AsyncDriver
    """

    ASYNCPG = "postgresql+asyncpg"
    PSYCOPG = "postgresql+psycopg"


class SSLMode(StrEnum):
    """libpq ``sslmode`` values, spelled as libpq spells them.

    Only the two ``verify-*`` members actually authenticate the server;
    ``require`` encrypts and accepts any certificate, which is a man in the
    middle away from plaintext. :class:`SSLConfig` will not let a
    ``verify-*`` mode stand without a trust anchor.

    Examples
    --------
    >>> SSLMode.VERIFY_FULL.value
    'verify-full'
    """

    DISABLE = "disable"
    ALLOW = "allow"
    PREFER = "prefer"
    REQUIRE = "require"
    VERIFY_CA = "verify-ca"
    VERIFY_FULL = "verify-full"


class IsolationLevel(StrEnum):
    """Transaction isolation levels SQLAlchemy will set on a connection.

    ``READ UNCOMMITTED`` is deliberately absent. PostgreSQL accepts it and
    then silently runs ``READ COMMITTED``, so a configuration naming it
    documents a guarantee the database is not providing.

    Examples
    --------
    >>> IsolationLevel.SERIALIZABLE.value
    'SERIALIZABLE'
    """

    READ_COMMITTED = "READ COMMITTED"
    REPEATABLE_READ = "REPEATABLE READ"
    SERIALIZABLE = "SERIALIZABLE"
    AUTOCOMMIT = "AUTOCOMMIT"


class PoolingMode(StrEnum):
    """What sits between this pool and PostgreSQL.

    Not cosmetic. Under ``TRANSACTION`` pooling a checked-out server
    connection is handed back to the pooler at every ``COMMIT``, so anything
    scoped to a session -- prepared statements, ``SET search_path``,
    ``SET statement_timeout`` -- either vanishes or, worse, leaks into
    somebody else's transaction.

    Attributes
    ----------
    DIRECT
        A direct TCP connection to PostgreSQL.
    SESSION
        pgbouncer/RDS-Proxy session pooling; a server connection is held for
        the life of the client connection, so session state survives.
    TRANSACTION
        pgbouncer transaction pooling; session state does not survive.

    Examples
    --------
    >>> PoolingMode.TRANSACTION.value
    'transaction'
    """

    DIRECT = "direct"
    SESSION = "session"
    TRANSACTION = "transaction"


class SSLConfig(BaseModel):
    """TLS parameters for the connection.

    Replaces the bare ``sslmode: str | None`` this package used to carry.
    That field had two defects: it was handed to the driver under a
    *different* name (``ssl``) than the one it was declared with, and there
    was no field for a CA bundle at all -- so ``sslmode="verify-full"``
    validated, connected, and verified against whatever the host's default
    trust store happened to hold.

    Parameters
    ----------
    mode
        The libpq ``sslmode``. Defaults to :attr:`SSLMode.PREFER`, matching
        libpq.
    root_cert
        PEM bundle the server certificate is verified against. Required by
        the ``verify-*`` modes.
    cert, key
        Client certificate and its private key, for certificate
        authentication. Both or neither.

    Raises
    ------
    ValueError
        If a ``verify-*`` mode has no :attr:`root_cert`, if exactly one of
        :attr:`cert` / :attr:`key` is set, or if any file is named while
        :attr:`mode` is :attr:`SSLMode.DISABLE`.

    Examples
    --------
    >>> SSLConfig().mode
    <SSLMode.PREFER: 'prefer'>
    >>> SSLConfig(mode=SSLMode.VERIFY_FULL, root_cert=Path("/etc/ssl/rds.pem")).mode
    <SSLMode.VERIFY_FULL: 'verify-full'>
    >>> from pydantic import ValidationError
    >>> try:
    ...     SSLConfig(mode=SSLMode.VERIFY_FULL)
    ... except ValidationError as exc:
    ...     "no ssl.root_cert was given" in str(exc)
    True
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        hide_input_in_errors=False,
    )

    mode: SSLMode = SSLMode.PREFER
    root_cert: Path | None = None
    cert: Path | None = None
    key: Path | None = None

    @model_validator(mode="after")
    def _verification_needs_a_trust_anchor(self) -> Self:
        if self.mode in {SSLMode.VERIFY_CA, SSLMode.VERIFY_FULL} and self.root_cert is None:
            message = (
                f"ssl.mode {self.mode.value!r} verifies the server certificate but no ssl.root_cert "
                f"was given; set the CA bundle explicitly rather than inheriting the host trust store"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _client_certificate_and_key_travel_together(self) -> Self:
        if (self.cert is None) != (self.key is None):
            message = (
                "ssl.cert and ssl.key must be set together; a client certificate without its key cannot authenticate"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _disabled_tls_ignores_no_files(self) -> Self:
        if self.mode is SSLMode.DISABLE and (self.root_cert, self.cert, self.key) != (None, None, None):
            message = (
                "ssl.mode 'disable' would silently ignore the configured certificate files; drop them or raise the mode"
            )
            raise ValueError(message)
        return self


class ReaderEndpoint(BaseModel):
    """A read-only replica endpoint sharing the writer's credentials.

    Modelled for the Aurora shape, which is the common one: a cluster exposes a
    writer endpoint (``mydb.cluster-xyz.rds.amazonaws.com``) and a load-balanced
    reader endpoint (``mydb.cluster-ro-xyz.rds.amazonaws.com``) that differ only in
    hostname. Credentials, port and database are the same cluster, so repeating them
    would be four more places for a deployment to drift.

    Because Aurora's reader endpoint already balances across replicas, there is no
    list of replica hosts and no round-robin here. A non-Aurora topology that needs
    per-replica addressing should instead build a second
    :class:`~hypervigilant.db.runtime.asyncio.Database` per replica, which also gives
    each its own pool.

    Parameters
    ----------
    host
        The reader endpoint hostname.
    port, pool_size, max_overflow
        Overrides; :data:`None` inherits the writer's value. A reporting workload
        usually wants a *smaller* pool than the writer, so that a slow analytical
        query cannot consume the cluster's connection budget.

    Examples
    --------
    >>> ReaderEndpoint(host="mydb.cluster-ro-xyz.rds.amazonaws.com").pool_size is None
    True
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True, extra="forbid", validate_default=True, hide_input_in_errors=True
    )

    host: Annotated[str, Field(min_length=1, max_length=255)]
    port: PortNumber | None = None
    pool_size: PoolSize | None = None
    max_overflow: MaxOverflow | None = None

    @field_validator("host", mode="after")
    @classmethod
    def _host_is_a_host_not_a_dsn(cls: type[Self], value: str) -> str:
        return _reject_dsn_like_host(value, field="reader.host")


class DBConfig(BaseModel):
    """Everything needed to build one async engine, and nothing else.

    Frozen and ``extra='forbid'``: a config object is a value, and a typo in
    a deployment manifest should fail at boot rather than be silently
    ignored. Every bound that can be a :class:`~pydantic.Field` constraint is
    one; the ``model_validator`` methods below carry only invariants that
    span two fields.

    Coercion is deliberately *not* strict. ``pydantic-settings`` hands
    environment values through as strings, and a ``strict=True`` model would
    reject ``HYPERVIGILANT_DB__PORT=5432``. The lax coercions that remain are
    narrow -- pydantic will not truncate ``5432.7`` into an ``int`` -- and
    the constraints below reject the values that actually cause outages.

    Parameters
    ----------
    driver
        Which async dialect to build. See :class:`AsyncDriver`.
    host, port, user, password, database
        Connection identity. ``password`` is a :class:`~pydantic.SecretStr`,
        so it is masked in ``repr``, ``str`` and ``model_dump(mode='json')``.
    search_path
        Schema resolution order, as identifiers rather than as one
        comma-joined string, so the joining happens once at the driver
        boundary.
    application_name
        The ``pg_stat_activity.application_name`` this process reports.
    connect_timeout_seconds
        Ceiling on establishing a new connection.
    command_timeout_seconds
        Client-side ceiling on one round trip.
    statement_timeout_ms, lock_timeout_ms, idle_in_transaction_session_timeout_ms
        Server-side GUCs, in milliseconds; :data:`None` leaves the server
        default in place.
    pool_size, max_overflow, pool_timeout_seconds, pool_recycle_seconds
        ``QueuePool`` sizing. ``pool_size`` is ``ge=1`` and ``max_overflow``
        is ``ge=0`` because SQLAlchemy reads ``0`` and ``-1`` respectively as
        *unlimited*, which turns ``pool_timeout_seconds`` into dead code and
        a load spike into an exhausted ``max_connections``.
    pool_pre_ping, pool_use_lifo
        Stale-connection detection and reuse order.
    echo, echo_pool
        SQLAlchemy's statement and pool logging.
    isolation_level
        Per-connection isolation. See :class:`IsolationLevel`.
    pooling_mode
        What sits between this pool and the server. See :class:`PoolingMode`.
    prepared_statement_cache_size
        SQLAlchemy's asyncpg-dialect prepared-statement cache. Must be ``0``
        under :attr:`PoolingMode.TRANSACTION`.
    ssl
        See :class:`SSLConfig`.

    Raises
    ------
    ValueError
        For any cross-field contradiction; see the ``model_validator``
        methods for the exact set.

    Examples
    --------
    >>> config = DBConfig(host="db.internal", user="app", password=SecretStr("p@ss/word"), database="app")
    >>> config.driver
    <AsyncDriver.ASYNCPG: 'postgresql+asyncpg'>
    >>> config.port
    5432

    The password never renders, in any of the three ways a value normally
    reaches a log line:

    >>> "p@ss" in repr(config)
    False
    >>> config.model_dump(mode="json")["password"]
    '**********'
    >>> "p@ss" in str(config.model_dump(mode="json"))
    False

    Reading it back requires saying so:

    >>> config.password.get_secret_value()[:4]
    'p@ss'

    Cross-field contradictions fail at construction, not at connect time:

    >>> from pydantic import ValidationError
    >>> try:
    ...     DBConfig(
    ...         host="pgbouncer",
    ...         user="app",
    ...         password=SecretStr("s"),
    ...         database="app",
    ...         pooling_mode=PoolingMode.TRANSACTION,
    ...     )
    ... except ValidationError as exc:
    ...     "prepared_statement_cache_size=100" in str(exc)
    True
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
        hide_input_in_errors=True,
    )

    driver: AsyncDriver = AsyncDriver.ASYNCPG

    host: Annotated[str, Field(min_length=1, max_length=255)]
    port: PortNumber = 5432
    user: SQLIdentifier
    password: SecretStr
    database: SQLIdentifier

    search_path: Annotated[tuple[SQLIdentifier, ...], Field(min_length=1, max_length=16)] = _DEFAULT_SEARCH_PATH
    application_name: Annotated[
        str,
        Field(min_length=1, max_length=_MAX_IDENTIFIER_BYTES, pattern=_APPLICATION_NAME_PATTERN),
    ] = "hypervigilant"

    connect_timeout_seconds: Annotated[float, Field(gt=0.0, le=120.0)] = 10.0
    command_timeout_seconds: Annotated[float, Field(gt=0.0, le=3600.0)] = 60.0
    statement_timeout_ms: PositiveMillis | None = 30_000
    lock_timeout_ms: PositiveMillis | None = 5_000
    idle_in_transaction_session_timeout_ms: PositiveMillis | None = 60_000

    pool_size: PoolSize = 10
    max_overflow: MaxOverflow = 10
    pool_timeout_seconds: Annotated[float, Field(gt=0.0, le=300.0)] = 30.0
    pool_recycle_seconds: Annotated[int, Field(ge=60, le=86_400)] | None = 1_800
    pool_pre_ping: bool = True
    pool_use_lifo: bool = True

    echo: bool = False
    echo_pool: bool = False

    isolation_level: IsolationLevel = IsolationLevel.READ_COMMITTED
    pooling_mode: PoolingMode = PoolingMode.DIRECT
    prepared_statement_cache_size: Annotated[int, Field(ge=0, le=10_000)] = 100

    ssl: SSLConfig = SSLConfig()

    reader: ReaderEndpoint | None = None
    read_only: bool = False

    @field_validator("host", mode="after")
    @classmethod
    def _host_is_a_host_not_a_dsn(cls: type[Self], value: str) -> str:
        """Reject a whole DSN pasted into the host field.

        The mistake is common (``DB__HOST=postgresql://app:hunter2@db/app``)
        and expensive: the credential lands in a plain ``str`` field with no
        masking, so it reaches the first log line that renders the config.
        The message never echoes the offending value for the same reason.
        """
        return _reject_dsn_like_host(value, field="host")

    @model_validator(mode="after")
    def _asyncpg_client_certificate_preserves_ssl_mode(self) -> Self:
        """Reject an SSLContext shape that would erase asyncpg's fallback modes."""
        if (
            self.driver is AsyncDriver.ASYNCPG
            and self.ssl.cert is not None
            and self.ssl.mode in {SSLMode.ALLOW, SSLMode.PREFER}
        ):
            message = (
                f"asyncpg cannot preserve plaintext fallback for ssl.mode {self.ssl.mode.value!r} "
                "when ssl.cert and ssl.key require an SSLContext; use ssl.mode 'require' or the psycopg driver"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _client_timeout_outlasts_server_timeout(self) -> Self:
        """The client must not give up before the server does.

        If ``command_timeout_seconds`` expires first, asyncpg abandons a
        query PostgreSQL is still executing; the connection is discarded
        rather than returned, so a workload that trips this steadily churns
        the pool while the server does the work anyway.
        """
        if self.statement_timeout_ms is None:
            return self
        client_ms = self.command_timeout_seconds * _MILLIS_PER_SECOND
        if client_ms <= self.statement_timeout_ms:
            message = (
                f"command_timeout_seconds ({self.command_timeout_seconds}) is {client_ms:.0f}ms, which does not "
                f"outlast statement_timeout_ms ({self.statement_timeout_ms}); the client would abandon queries "
                f"the server is still running"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _lock_wait_is_shorter_than_the_statement(self) -> Self:
        """A lock timeout at or above the statement timeout never fires.

        ``statement_timeout`` cancels the statement first, so the operator
        gets ``canceling statement due to statement timeout`` instead of the
        far more actionable ``canceling statement due to lock timeout`` --
        and the contention that actually caused the incident is invisible.
        """
        if self.lock_timeout_ms is None or self.statement_timeout_ms is None:
            return self
        if self.lock_timeout_ms >= self.statement_timeout_ms:
            message = (
                f"lock_timeout_ms ({self.lock_timeout_ms}) must be below statement_timeout_ms "
                f"({self.statement_timeout_ms}); otherwise lock waits are reported as statement timeouts"
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _transaction_pooling_forbids_session_state(self) -> Self:
        """Transaction pooling and session-scoped state are incompatible.

        Under pgbouncer's ``transaction`` mode the server connection is
        released at every ``COMMIT``. Server-side prepared statements from
        the previous checkout are then either missing (``prepared statement
        "__asyncpg_stmt_1__" does not exist``) or, worse, matched against a
        different backend. The same applies to ``search_path`` and to the
        per-session timeout GUCs, which is why they must be left at their
        defaults and applied per transaction instead.
        """
        if self.pooling_mode is not PoolingMode.TRANSACTION:
            return self
        offenders: list[str] = []
        if self.prepared_statement_cache_size != 0:
            offenders.append(f"prepared_statement_cache_size={self.prepared_statement_cache_size}")
        if self.search_path != _DEFAULT_SEARCH_PATH:
            offenders.append(f"search_path={self.search_path}")
        if self.idle_in_transaction_session_timeout_ms is not None:
            offenders.append(f"idle_in_transaction_session_timeout_ms={self.idle_in_transaction_session_timeout_ms}")
        if offenders:
            message = (
                f"pooling_mode 'transaction' releases the server connection at every COMMIT, so session-scoped "
                f"state does not survive: {', '.join(offenders)}. Set prepared_statement_cache_size=0, leave "
                f"search_path at its default, and apply per-session GUCs inside each transaction."
            )
            raise ValueError(message)
        return self

    @model_validator(mode="after")
    def _stale_connections_need_a_detector(self) -> Self:
        """A pool that neither recycles nor pings hands out dead sockets.

        A pooled connection can be closed by an idle timeout, a failover, or
        a pooler restart while it sits in the pool. With
        ``pool_recycle_seconds=None`` and ``pool_pre_ping=False`` nothing
        notices, and the closure surfaces as a failed *request*.
        """
        if self.pool_recycle_seconds is None and not self.pool_pre_ping:
            message = (
                "pool_recycle_seconds=None disables recycling and pool_pre_ping=False disables liveness "
                "checks; enable at least one or the pool will hand out connections the server has closed"
            )
            raise ValueError(message)
        return self

    def server_settings(self) -> dict[str, str]:
        """Return the PostgreSQL GUCs to apply on every new connection.

        Rendered here rather than in the engine module because the unit
        conversion and the ``search_path`` join are *config* concerns: this
        is the single place milliseconds become the strings PostgreSQL
        expects, and the single place identifiers become one comma-joined
        payload.

        Returns
        -------
            A mapping suitable for asyncpg's ``server_settings`` connect
            argument. Timeouts left at :data:`None` are absent, so the server
            default stands.

        Examples
        --------
        >>> config = DBConfig(host="db", user="app", password=SecretStr("s"), database="app")
        >>> config.server_settings()["statement_timeout"]
        '30000'
        >>> config.server_settings()["search_path"]
        'public'
        >>> DBConfig(
        ...     host="db",
        ...     user="app",
        ...     password=SecretStr("s"),
        ...     database="app",
        ...     statement_timeout_ms=None,
        ...     lock_timeout_ms=None,
        ... ).server_settings()
        {'application_name': 'hypervigilant', 'search_path': 'public', 'idle_in_transaction_session_timeout': '60000'}
        """
        settings: dict[str, str] = {
            "application_name": self.application_name,
            "search_path": ",".join(self.search_path),
        }
        if self.read_only:
            settings["default_transaction_read_only"] = "on"
        if self.statement_timeout_ms is not None:
            settings["statement_timeout"] = str(self.statement_timeout_ms)
        if self.lock_timeout_ms is not None:
            settings["lock_timeout"] = str(self.lock_timeout_ms)
        if self.idle_in_transaction_session_timeout_ms is not None:
            settings["idle_in_transaction_session_timeout"] = str(self.idle_in_transaction_session_timeout_ms)
        return settings

    def reader_config(self) -> Self | None:
        """Derive the reader's own :class:`DBConfig`, or ``None`` when none is configured.

        ``read_only=True`` is set here rather than left to the caller, and it is not
        cosmetic: it becomes ``default_transaction_read_only=on`` in the connection's
        server settings, so a write that reaches a replica fails immediately with a
        clear PostgreSQL error instead of relying on the operator having remembered
        which endpoint this session was opened against.

        The derived config carries ``reader=None``, so a cluster cannot nest.

        Examples
        --------
        >>> config = DBConfig(
        ...     host="writer.rds.amazonaws.com",
        ...     user="app",
        ...     password=SecretStr("s"),
        ...     database="app",
        ...     reader=ReaderEndpoint(host="reader.rds.amazonaws.com", pool_size=3),
        ... )
        >>> reader = config.reader_config()
        >>> (reader.host, reader.port, reader.pool_size, reader.read_only)
        ('reader.rds.amazonaws.com', 5432, 3, True)
        >>> reader.server_settings()["default_transaction_read_only"]
        'on'
        >>> reader.reader_config() is None
        True
        >>> DBConfig(host="solo", user="app", password=SecretStr("s"), database="app").reader_config() is None
        True
        """
        if self.reader is None:
            return None
        data = self.model_dump()
        data.update(
            {
                "host": self.reader.host,
                "port": self.reader.port if self.reader.port is not None else self.port,
                "pool_size": self.reader.pool_size if self.reader.pool_size is not None else self.pool_size,
                "max_overflow": (
                    self.reader.max_overflow if self.reader.max_overflow is not None else self.max_overflow
                ),
                "reader": None,
                "read_only": True,
            }
        )
        return type(self).model_validate(data)
