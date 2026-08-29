"""The two-engine wiring, end to end against a real server.

This tier points the reader at the *same* container as the writer. That is not a
shortcut: what needs proving is that a second engine is built, that sessions opened
against it carry ``default_transaction_read_only=on``, and that a write through it is
refused by PostgreSQL itself. None of that depends on the reader being a genuinely
separate instance, and using one container keeps the suite fast.

The pure config algebra -- inheritance, pool sizing, nesting, revalidation -- lives in
``tests/unit/db/test_replica.py`` and needs no container.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from hypervigilant.db.config import DBConfig, ReaderEndpoint
from hypervigilant.db.errors import DatabaseError
from hypervigilant.db.runtime.asyncio import Database

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]


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


async def test_writes_still_go_to_the_writer_when_a_reader_exists(db_config: DBConfig) -> None:
    """``begin()`` has no reader variant, so a transaction cannot land on a replica."""
    clustered = db_config.model_copy(update={"reader": ReaderEndpoint(host=db_config.host, port=db_config.port)})
    async with Database(clustered) as db:
        async with db.begin() as session:
            await session.execute(text("CREATE TABLE IF NOT EXISTS writer_only (id int)"))
        async with db.session() as session:
            await session.execute(text("DROP TABLE writer_only"))


async def test_reader_session_falls_back_to_writer_when_unconfigured(database: Database) -> None:
    """Safe in the one direction that matters: the writer always serves reads correctly."""
    assert database.reader_health is None
    async with database.reader_session() as session:
        assert (await session.execute(text("SELECT 1"))).scalar_one() == 1
        assert (await session.execute(text("SHOW transaction_read_only"))).scalar_one() == "off"
