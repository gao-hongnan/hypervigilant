"""Async PostgreSQL substrate: config, engine, sessions, transactions, health.

Requires the ``postgres`` extra::

    uv add 'hypervigilant[postgres]'

Unlike :mod:`hypervigilant.circuit_breaker` -- whose Redis client is injected as a
*value*, so the driver need never be imported -- this package cannot defer its
dependency: :class:`~hypervigilant.db.types.PydanticJSON` subclasses a SQLAlchemy
class at class-definition time. The guard therefore sits at the subpackage door, and
``import hypervigilant`` remains free of it because the top-level package does not
import this one.

Examples
--------
>>> from pydantic import SecretStr
>>> config = DBConfig(host="db", user="app", password=SecretStr("s"), database="app")
>>> db = Database(config)
>>> db.config.driver
<AsyncDriver.ASYNCPG: 'postgresql+asyncpg'>

The intended wiring, in full. Nothing in this package reads the environment -- the
prefix belongs to the consuming application's own settings class::

    class AppSettings(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="MYAPP_", env_nested_delimiter="__")
        db: DBConfig          # MYAPP_DB__HOST, MYAPP_DB__PASSWORD, MYAPP_DB__READER__HOST

    db = Database(AppSettings().db)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with db:        # initialize(): engines, session factories, SELECT 1
            yield             # aclose(): dispose writer and reader

    @app.get("/readyz")
    async def readyz(response: Response) -> HealthReport:
        report = await db.health.acheck()          # writer; the reader can be absent
        response.status_code = 200 if report.ok else 503
        return report

    @app.post("/orders")
    async def place(draft: OrderDraft) -> OrderId:
        return await atransactional(db.begin, lambda s: OrderRepository(s).place(draft))

    @app.get("/reports/daily")
    async def daily() -> Report:
        async with db.reader_session() as session:   # replica, or writer if unconfigured
            return await build_report(session)

Two tokens carry the safety properties. ``db.begin`` is passed *uncalled*, which is
what makes retrying inside a poisoned transaction inexpressible -- see
:mod:`hypervigilant.db.transaction`. And ``reader_session`` is spelled differently
from ``session``, so routing a read to a possibly-lagging replica is a thing somebody
chose rather than something inferred from flush state; ``begin`` has no reader
variant at all, so a transaction cannot land on one.
"""

from importlib.util import find_spec

if find_spec("sqlalchemy") is None:  # pragma: no cover
    _REASON = "hypervigilant.db requires the 'postgres' extra: uv add 'hypervigilant[postgres]'"
    raise ImportError(_REASON)

from .config import (
    AsyncDriver,
    DBConfig,
    IsolationLevel,
    PoolingMode,
    ReaderEndpoint,
    ServerSetting,
    SSLConfig,
    SSLMode,
)
from .engine import async_url_for, build_engine, build_session_factory
from .errors import (
    DatabaseError,
    DatabaseUnavailableError,
    IntegrityViolationError,
    TransactionConflictError,
    UnclassifiedDatabaseError,
    translate_error,
)
from .health import PROBE_STATEMENT, HealthProbe, HealthReport, PoolHealthProbe, PoolStats
from .operations import DatabaseOperation
from .runtime.asyncio import Database
from .session import SessionProvider, asession_scope
from .transaction import (
    CONNECTION_RETRY,
    SERIALIZATION_RETRY,
    ScopeFactory,
    TransactionScope,
    atransactional,
    aunit_of_work,
)
from .types import NAMING_CONVENTION, PydanticJSON, SessionFactory, build_metadata

__all__ = [
    "CONNECTION_RETRY",
    "NAMING_CONVENTION",
    "PROBE_STATEMENT",
    "SERIALIZATION_RETRY",
    "AsyncDriver",
    "DBConfig",
    "Database",
    "DatabaseError",
    "DatabaseOperation",
    "DatabaseUnavailableError",
    "HealthProbe",
    "HealthReport",
    "IntegrityViolationError",
    "IsolationLevel",
    "PoolHealthProbe",
    "PoolStats",
    "PoolingMode",
    "PydanticJSON",
    "ReaderEndpoint",
    "SSLConfig",
    "SSLMode",
    "ScopeFactory",
    "ServerSetting",
    "SessionFactory",
    "SessionProvider",
    "TransactionConflictError",
    "TransactionScope",
    "UnclassifiedDatabaseError",
    "asession_scope",
    "async_url_for",
    "atransactional",
    "aunit_of_work",
    "build_engine",
    "build_metadata",
    "build_session_factory",
    "translate_error",
]
