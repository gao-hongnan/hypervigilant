"""Reader-endpoint derivation: pure config algebra, no server involved.

The end-to-end half -- that a second engine is built, that its sessions carry
``default_transaction_read_only=on``, and that PostgreSQL itself refuses the write --
lives in ``tests/integration/db/test_replica.py``.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from hypervigilant.db.config import DBConfig, ReaderEndpoint

pytestmark = pytest.mark.unit


def _config(**overrides: object) -> DBConfig:
    base: dict[str, object] = {
        "host": "writer.rds.amazonaws.com",
        "user": "app",
        "password": SecretStr("s"),
        "database": "app",
    }
    return DBConfig(**(base | overrides))  # type: ignore[arg-type]  # test-side kwargs splat


def test_no_reader_by_default() -> None:
    """A single-instance deployment must not have to say so."""
    assert _config().reader_config() is None


def test_reader_inherits_credentials_and_port() -> None:
    """Only the hostname differs on an Aurora cluster; repeating the rest invites drift."""
    reader = _config(reader=ReaderEndpoint(host="reader.rds.amazonaws.com")).reader_config()
    assert reader is not None
    assert reader.host == "reader.rds.amazonaws.com"
    assert reader.port == 5432
    assert reader.user == "app"
    assert reader.database == "app"
    assert reader.password.get_secret_value() == "s"


def test_reader_pool_can_be_sized_independently() -> None:
    """A reporting workload should not be able to consume the cluster's connection budget."""
    reader = _config(pool_size=20, reader=ReaderEndpoint(host="r.example.com", pool_size=3)).reader_config()
    assert reader is not None
    assert reader.pool_size == 3


def test_reader_is_read_only_at_the_server() -> None:
    """Enforcement is a GUC, not a convention the caller has to remember."""
    reader = _config(reader=ReaderEndpoint(host="r.example.com")).reader_config()
    assert reader is not None
    assert reader.read_only is True
    assert reader.server_settings()["default_transaction_read_only"] == "on"


def test_writer_is_not_read_only() -> None:
    config = _config(reader=ReaderEndpoint(host="r.example.com"))
    assert config.read_only is False
    assert "default_transaction_read_only" not in config.server_settings()


def test_cluster_cannot_nest() -> None:
    """A reader's own config carries no reader, so the topology is one level deep."""
    reader = _config(reader=ReaderEndpoint(host="r.example.com")).reader_config()
    assert reader is not None
    assert reader.reader is None
    assert reader.reader_config() is None


def test_reader_host_rejects_a_dsn() -> None:
    with pytest.raises(ValidationError, match="not a DSN"):
        ReaderEndpoint(host="postgresql://app:pw@reader/app")


def test_reader_derivation_revalidates_cross_field_invariants() -> None:
    """A copied config can bypass validation; derivation must restore the boundary."""
    invalid = _config(reader=ReaderEndpoint(host="r.example.com")).model_copy(update={"command_timeout_seconds": 1.0})

    with pytest.raises(ValidationError, match="command_timeout_seconds"):
        invalid.reader_config()


def test_reader_derivation_preserves_subclass_and_revalidates() -> None:
    class ExtendedDBConfig(DBConfig):
        region: str

    config = ExtendedDBConfig(
        host="writer.example.com",
        user="app",
        password=SecretStr("s"),
        database="app",
        region="sg",
        reader=ReaderEndpoint(host="reader.example.com"),
    )

    reader = config.reader_config()
    assert isinstance(reader, ExtendedDBConfig)
    assert reader.region == "sg"

    invalid = config.model_copy(update={"command_timeout_seconds": 1.0})
    with pytest.raises(ValidationError, match="command_timeout_seconds"):
        invalid.reader_config()
