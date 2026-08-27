"""Fixtures for the database suite: one container, one engine, a rollback per test.

Scoping is the load-bearing detail. The engine fixture is session-scoped so a single
PostgreSQL container serves the whole suite, and the event loop must therefore be
session-scoped too -- an :class:`AsyncEngine` built on one loop and used on another
raises ``got Future attached to a different loop``, which presents as a race rather
than as a configuration error.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
from pydantic import SecretStr

from hypervigilant.db.config import DBConfig
from hypervigilant.db.runtime.asyncio import Database
from hypervigilant.db.session import SessionProvider
from hypervigilant.db.testing import rollback_scope

if TYPE_CHECKING:
    from testcontainers.community.postgres import PostgresContainer

_IMAGE = "postgres:17-alpine"


@pytest.fixture(scope="session")
def postgres() -> Generator[PostgresContainer]:
    """One container for the whole suite.

    Imported inside the fixture rather than at module scope so the pure-logic tests
    in this directory never depend on testcontainers -- or on a running Docker.

    An unreachable daemon is a *skip*, not an error. ``importorskip`` covers only the
    missing package; without the try/except a contributor with no Docker sees the
    suite fail rather than report seven skips, which makes a green checkout look
    broken.
    """
    container_cls = pytest.importorskip(
        "testcontainers.community.postgres", reason="needs testcontainers[postgres]"
    ).PostgresContainer
    try:
        container = container_cls(_IMAGE, driver="asyncpg")
        container.start()
    except Exception as exc:  # noqa: BLE001 - any docker failure is the same answer: skip
        pytest.skip(f"needs a running Docker daemon: {type(exc).__name__}: {exc}")
    try:
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="session")
def db_config(postgres: PostgresContainer) -> DBConfig:
    """A config pointed at the container, with timeouts tightened for tests."""
    return DBConfig(
        host=postgres.get_container_host_ip(),
        port=int(postgres.get_exposed_port(5432)),
        user=postgres.username,
        password=SecretStr(postgres.password),
        database=postgres.dbname,
        pool_size=5,
        pool_timeout_seconds=5.0,
        statement_timeout_ms=10_000,
        lock_timeout_ms=2_000,
        command_timeout_seconds=15.0,
    )


@pytest_asyncio.fixture(loop_scope="session", scope="session")
async def database(db_config: DBConfig) -> AsyncGenerator[Database]:
    """An initialised :class:`Database`, disposed once the suite finishes."""
    async with Database(db_config) as db:
        yield db


@pytest_asyncio.fixture(loop_scope="session")
async def sessions(database: Database) -> AsyncGenerator[SessionProvider]:
    """A provider whose every session is rolled back when the test ends."""
    async with rollback_scope(database) as provider:
        yield provider
