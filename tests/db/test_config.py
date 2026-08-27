"""Cross-field validation, secret hygiene, and the unrepresentable sync driver."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from hypervigilant.db.config import AsyncDriver, DBConfig, PoolingMode, SSLConfig, SSLMode

pytestmark = pytest.mark.unit


def _config(**overrides: object) -> DBConfig:
    base: dict[str, object] = {
        "host": "db",
        "user": "app",
        "password": SecretStr("p@ss/word"),
        "database": "app",
    }
    return DBConfig(**(base | overrides))  # type: ignore[arg-type]  # test-side kwargs splat


def test_sync_driver_is_unrepresentable() -> None:
    """The property the original ``Final`` constant bought, kept as a closed type.

    ``postgresql://`` resolves to the synchronous psycopg driver: the engine builds,
    the pool opens, and the failure surfaces at the first ``await``.
    """
    with pytest.raises(ValueError, match="not a valid AsyncDriver"):
        AsyncDriver("postgresql")
    with pytest.raises(ValidationError):
        _config(driver="postgresql")


def test_password_never_renders() -> None:
    """All three routes a value normally takes to a log line."""
    config = _config()
    assert "p@ss" not in repr(config)
    assert config.model_dump(mode="json")["password"] == "**********"
    assert "p@ss" not in str(config.model_dump(mode="json"))
    assert config.password.get_secret_value() == "p@ss/word"


def test_a_pasted_dsn_is_rejected() -> None:
    """A DSN in the host field puts the credential into an unmasked ``str``."""
    with pytest.raises(ValidationError, match="not a DSN"):
        _config(host="postgresql://app:hunter2@db/app")


def test_lock_timeout_must_be_below_statement_timeout() -> None:
    """Otherwise lock contention is reported as a statement timeout and stays invisible."""
    with pytest.raises(ValidationError, match="lock_timeout_ms"):
        _config(lock_timeout_ms=30_000, statement_timeout_ms=30_000)


def test_client_timeout_must_outlast_the_server() -> None:
    """A client that gives up first churns the pool while the server does the work anyway."""
    with pytest.raises(ValidationError, match="command_timeout_seconds"):
        _config(command_timeout_seconds=1.0, statement_timeout_ms=30_000)


def test_transaction_pooling_forbids_session_state() -> None:
    """pgbouncer releases the server connection at every COMMIT."""
    with pytest.raises(ValidationError, match="prepared_statement_cache_size=100"):
        _config(pooling_mode=PoolingMode.TRANSACTION)


def test_transaction_pooling_accepts_a_consistent_config() -> None:
    config = _config(
        pooling_mode=PoolingMode.TRANSACTION,
        prepared_statement_cache_size=0,
        idle_in_transaction_session_timeout_ms=None,
    )
    assert config.pooling_mode is PoolingMode.TRANSACTION


def test_a_pool_with_no_staleness_detector_is_rejected() -> None:
    with pytest.raises(ValidationError, match="pool_recycle_seconds"):
        _config(pool_recycle_seconds=None, pool_pre_ping=False)


def test_verifying_ssl_requires_a_trust_anchor() -> None:
    """``verify-full`` without a CA silently inherits the host trust store."""
    with pytest.raises(ValidationError, match="root_cert"):
        SSLConfig(mode=SSLMode.VERIFY_FULL)


def test_client_certificate_and_key_travel_together() -> None:
    with pytest.raises(ValidationError, match="must be set together"):
        SSLConfig(mode=SSLMode.REQUIRE, cert="/tmp/c.pem")  # type: ignore[arg-type]


def test_server_settings_render_as_strings() -> None:
    """PostgreSQL GUCs are strings; an int silently does nothing."""
    settings = _config().server_settings()
    assert settings["statement_timeout"] == "30000"
    assert settings["application_name"] == "hypervigilant"
    assert all(isinstance(value, str) for value in settings.values())


def test_omitted_timeouts_leave_the_server_default() -> None:
    settings = _config(statement_timeout_ms=None, lock_timeout_ms=None).server_settings()
    assert "statement_timeout" not in settings
    assert "lock_timeout" not in settings
