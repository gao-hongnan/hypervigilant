"""End-to-end behaviour against a real PostgreSQL.

These assertions cannot be made anywhere else: SQLite has no ``40001``, no ``40P01``,
no ``JSONB``, and different constraint-violation messages, so a suite that passes on
SQLite can miss every behaviour verified here.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

import pytest
from pydantic import BaseModel, Field, TypeAdapter
from sqlalchemy import Column, Integer, String, Table, UniqueConstraint, select, text

from hypervigilant.db.errors import IntegrityViolationError
from hypervigilant.db.runtime.asyncio import Database
from hypervigilant.db.session import SessionProvider
from hypervigilant.db.transaction import transactional
from hypervigilant.db.types import PydanticJSON, build_metadata

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="session")]


class Alpha(BaseModel):
    kind: Literal["alpha"] = "alpha"
    value: int


class Beta(BaseModel):
    kind: Literal["beta"] = "beta"
    label: str


type Variant = Annotated[Alpha | Beta, Field(discriminator="kind")]

VARIANT_ADAPTER: Final = TypeAdapter[Variant](Variant)
METADATA: Final = build_metadata()

DOCS: Final = Table(
    "docs",
    METADATA,
    Column("id", Integer, primary_key=True),
    Column("ref", String(32), nullable=False),
    Column("payload", PydanticJSON(VARIANT_ADAPTER), nullable=True),
    UniqueConstraint("ref", name="uq_docs_ref"),
)


@pytest.fixture(scope="session", autouse=True)
async def schema(database: Database) -> None:
    """Create the suite's tables once."""
    async with database.engine.begin() as connection:
        await connection.run_sync(METADATA.create_all)


async def test_column_is_jsonb_in_the_real_catalog(database: Database) -> None:
    """``impl = types.JSON`` alone would give text-backed ``JSON`` here."""
    async with database.engine.connect() as connection:
        data_type = (
            await connection.execute(
                text(
                    "SELECT data_type FROM information_schema.columns "
                    "WHERE table_name = 'docs' AND column_name = 'payload'"
                )
            )
        ).scalar_one()
    assert data_type == "jsonb"


async def test_discriminated_union_round_trips(sessions: SessionProvider) -> None:
    async with sessions.session() as session:
        await session.execute(DOCS.insert(), {"id": 1, "ref": "a", "payload": Beta(label="hello")})
        stored = (await session.execute(select(DOCS.c.payload).where(DOCS.c.id == 1))).scalar_one()
    assert isinstance(stored, Beta)
    assert stored.label == "hello"


async def test_none_persists_as_sql_null(sessions: SessionProvider) -> None:
    """The defect: ``None`` became the JSON literal ``'null'`` and ``IS NULL`` matched nothing."""
    async with sessions.session() as session:
        await session.execute(DOCS.insert(), {"id": 2, "ref": "b", "payload": None})
        matched = (await session.execute(text("SELECT count(*) FROM docs WHERE payload IS NULL"))).scalar_one()
    assert matched == 1


async def test_unique_violation_becomes_a_domain_error(sessions: SessionProvider) -> None:
    """Nothing SQLAlchemy raises may cross the package boundary untranslated."""
    async with sessions.session() as session:
        await session.execute(DOCS.insert(), {"id": 3, "ref": "dup", "payload": None})
        await session.flush()
        with pytest.raises(IntegrityViolationError) as caught:
            await session.execute(DOCS.insert(), {"id": 4, "ref": "dup", "payload": None})
            await session.flush()
    assert caught.value.sqlstate == "23505"
    assert caught.value.constraint == "uq_docs_ref"
    assert caught.value.retryable is False


async def test_transactional_commits_and_rolls_back(database: Database) -> None:
    """The unit of work is the transaction boundary, not a session-shaped wrapper."""

    async def insert_one(session: object) -> int:
        await session.execute(DOCS.insert(), {"id": 10, "ref": "committed", "payload": None})  # type: ignore[attr-defined]
        return 10

    assert await transactional(database.begin, insert_one) == 10

    async def insert_then_fail(session: object) -> None:
        await session.execute(DOCS.insert(), {"id": 11, "ref": "rolled-back", "payload": None})  # type: ignore[attr-defined]
        reason = "deliberate"
        raise RuntimeError(reason)

    with pytest.raises(RuntimeError, match="deliberate"):
        await transactional(database.begin, insert_then_fail)

    async with database.session() as session:
        refs = set((await session.execute(select(DOCS.c.ref))).scalars().all())
    assert "committed" in refs
    assert "rolled-back" not in refs

    async with database.engine.begin() as connection:
        await connection.execute(text("DELETE FROM docs WHERE id = 10"))


async def test_rollback_scope_isolates_even_across_commit(sessions: SessionProvider, database: Database) -> None:
    """``join_transaction_mode='create_savepoint'`` is what makes an inner commit safe."""
    async with sessions.session() as session:
        await session.execute(DOCS.insert(), {"id": 99, "ref": "ephemeral", "payload": None})
        await session.commit()

    async with database.session() as outside:
        found = (await outside.execute(select(DOCS.c.id).where(DOCS.c.ref == "ephemeral"))).scalars().all()
    assert found == []


async def test_health_probe_reports_ready(database: Database) -> None:
    report = await database.health.check()
    assert report.ok is True
    assert report.latency_ms is not None
    assert report.pool is not None
    assert report.pool.saturated is False
