"""Reader-endpoint derivation and the two-engine wiring.

The integration tier points the reader at the *same* container as the writer. That is
not a shortcut: what needs proving is that a second engine is built, that sessions
opened against it carry ``default_transaction_read_only=on``, and that a write
through it is refused by PostgreSQL itself. None of that depends on the reader being
a genuinely separate instance, and using one container keeps the suite fast.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import text

from hypervigilant.db.config import DBConfig, ReaderEndpoint
from hypervigilant.db.errors import DatabaseError
from hypervigilant.db.runtime.asyncio import Database


def _config(**overrides: object) -> DBConfig:
    base: dict[str, object] = {
        "host": "writer.rds.amazonaws.com",
        "user": "app",
        "password": SecretStr("s"),
        "database": "app",
    }
    return DBConfig(**(base | overrides))  # type: ignore[arg-type]  # test-side kwargs splat


@pytest.mark.unit
def test_no_reader_by_default() -> None:
    """A single-instance deployment must not have to say so."""
    assert _config().reader_config() is None


@pytest.mark.unit
def test_reader_inherits_credentials_and_port() -> None:
    """Only the hostname differs on an Aurora cluster; repeating the rest invites drift."""
    reader = _config(reader=ReaderEndpoint(host="reader.rds.amazonaws.com")).reader_config()
    assert reader is not None
    assert reader.host == "reader.rds.amazonaws.com"
    assert reader.port == 5432
    assert reader.user == "app"
    assert reader.database == "app"
    assert reader.password.get_secret_value() == "s"


@pytest.mark.unit
def test_reader_pool_can_be_sized_independently() -> None:
    """A reporting workload should not be able to consume the cluster's connection budget."""
    reader = _config(pool_size=20, reader=ReaderEndpoint(host="r.example.com", pool_size=3)).reader_config()
    assert reader is not None
    assert reader.pool_size == 3


@pytest.mark.unit
def test_reader_is_read_only_at_the_server() -> None:
    """Enforcement is a GUC, not a convention the caller has to remember."""
    reader = _config(reader=ReaderEndpoint(host="r.example.com")).reader_config()
    assert reader is not None
    assert reader.read_only is True
    assert reader.server_settings()["default_transaction_read_only"] == "on"


@pytest.mark.unit
def test_writer_is_not_read_only() -> None:
    config = _config(reader=ReaderEndpoint(host="r.example.com"))
    assert config.read_only is False
    assert "default_transaction_read_only" not in config.server_settings()


@pytest.mark.unit
def test_cluster_cannot_nest() -> None:
    """A reader's own config carries no reader, so the topology is one level deep."""
    reader = _config(reader=ReaderEndpoint(host="r.example.com")).reader_config()
    assert reader is not None
    assert reader.reader is None
    assert reader.reader_config() is None


@pytest.mark.unit
def test_reader_host_rejects_a_dsn() -> None:
    with pytest.raises(ValidationError, match="not a DSN"):
        ReaderEndpoint(host="postgresql://app:pw@reader/app")


@pytest.mark.integration
@pytest.mark.asyncio(loop_scope="session")
async def test_reader_endpoint_serves_reads_and_refuses_writes(db_config: DBConfig) -> None:
    """The whole point, end to end against a real server."""
    clustered = db_config.model_copy(
        update={"reader": ReaderEndpoint(host=db_config.host, port=db_config.port, pool_size=2)}
    )
    async with Database(clustered) as db:
        assert db.reader_health is not None
        assert (await db.reader_health.acheck()).ok is True

        async with db.reader_session() as session:
            assert (await session.execute(text("SELECT 1"))).scalar_one() == 1
            read_only = (await session.execute(text("SHOW transaction_read_only"))).scalar_one()
        assert read_only == "on"

        with pytest.raises(DatabaseError) as caught:
            async with db.reader_session() as session:
                await session.execute(text("CREATE TABLE must_not_exist (id int)"))
        assert "read-only" in str(caught.value).lower()


@pytest.mark.integration
@pytest.mark.asyncio(loop_scope="session")
async def test_writes_still_go_to_the_writer_when_a_reader_exists(db_config: DBConfig) -> None:
    """``begin()`` has no reader variant, so a transaction cannot land on a replica."""
    clustered = db_config.model_copy(update={"reader": ReaderEndpoint(host=db_config.host, port=db_config.port)})
    async with Database(clustered) as db:
        async with db.begin() as session:
            await session.execute(text("CREATE TABLE IF NOT EXISTS writer_only (id int)"))
        async with db.session() as session:
            await session.execute(text("DROP TABLE writer_only"))


@pytest.mark.integration
@pytest.mark.asyncio(loop_scope="session")
async def test_reader_session_falls_back_to_writer_when_unconfigured(database: Database) -> None:
    """Safe in the one direction that matters: the writer always serves reads correctly."""
    assert database.reader_health is None
    async with database.reader_session() as session:
        assert (await session.execute(text("SELECT 1"))).scalar_one() == 1
        assert (await session.execute(text("SHOW transaction_read_only"))).scalar_one() == "off"
