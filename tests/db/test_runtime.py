"""Unit coverage for database runtime lifecycle and routing behavior."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr
from sqlalchemy.exc import SQLAlchemyError

from hypervigilant.db.config import DBConfig, ReaderEndpoint
from hypervigilant.db.errors import UnclassifiedDatabaseError
from hypervigilant.db.runtime.asyncio import Database

pytestmark = pytest.mark.unit


def _config() -> DBConfig:
    return DBConfig(host="db", user="app", password=SecretStr("secret"), database="app")


def _engine(*, connect_error: SQLAlchemyError | None = None) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock()
    connection = MagicMock()
    connection.execute = AsyncMock()
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=connection)
    if connect_error is not None:
        context.__aenter__.side_effect = connect_error
    context.__aexit__ = AsyncMock(return_value=None)
    engine.connect.return_value = context
    return engine


@pytest.mark.asyncio
async def test_reader_fallback_retains_reader_operation_on_failure() -> None:
    database = Database(_config())
    engine = _engine()

    with patch("hypervigilant.db.runtime.asyncio.build_engine", return_value=engine):
        await database.ainitialize()
        with pytest.raises(UnclassifiedDatabaseError) as caught:
            async with database.reader_session():
                raise SQLAlchemyError("reader failed")
        await database.aclose()

    assert caught.value.operation == "db.reader_session"


@pytest.mark.asyncio
async def test_initialize_is_idempotent_and_close_disposes_once() -> None:
    database = Database(_config())
    engine = _engine()

    with patch("hypervigilant.db.runtime.asyncio.build_engine", return_value=engine) as build:
        await database.ainitialize()
        await database.ainitialize()
        await database.aclose()
        await database.aclose()

    build.assert_called_once()
    engine.dispose.assert_awaited_once()


@pytest.mark.asyncio
async def test_reader_initialize_failure_disposes_both_engines_and_leaves_database_uninitialized() -> None:
    config = _config().model_copy(update={"reader": ReaderEndpoint(host="reader")})
    database = Database(config)
    writer = _engine()
    reader = _engine(connect_error=SQLAlchemyError("reader unavailable"))

    with (
        patch("hypervigilant.db.runtime.asyncio.build_engine", side_effect=[writer, reader]),
        pytest.raises(UnclassifiedDatabaseError) as caught,
    ):
        await database.ainitialize()

    assert caught.value.operation == "db.initialize.reader"
    writer.dispose.assert_awaited_once()
    reader.dispose.assert_awaited_once()
    with pytest.raises(RuntimeError, match="there is no engine yet"):
        _ = database.engine
    assert database.reader_health is None


@pytest.mark.asyncio
async def test_reader_configuration_failure_disposes_writer_and_leaves_database_uninitialized() -> None:
    database = Database(_config())
    writer = _engine()

    with (
        patch("hypervigilant.db.runtime.asyncio.build_engine", return_value=writer),
        patch.object(DBConfig, "reader_config", side_effect=RuntimeError("invalid reader")),
        pytest.raises(RuntimeError, match="invalid reader"),
    ):
        await database.ainitialize()

    writer.dispose.assert_awaited_once()
    with pytest.raises(RuntimeError, match="there is no engine yet"):
        _ = database.engine


@pytest.mark.asyncio
async def test_close_clears_both_bundles_when_writer_disposal_fails() -> None:
    config = _config().model_copy(update={"reader": ReaderEndpoint(host="reader")})
    database = Database(config)
    writer = _engine()
    reader = _engine()

    with patch("hypervigilant.db.runtime.asyncio.build_engine", side_effect=[writer, reader]):
        await database.ainitialize()

    writer.dispose.side_effect = RuntimeError("writer disposal failed")
    with pytest.raises(RuntimeError, match="writer disposal failed"):
        await database.aclose()

    reader.dispose.assert_awaited_once()
    with pytest.raises(RuntimeError, match="there is no engine yet"):
        _ = database.engine
    assert database.reader_health is None
