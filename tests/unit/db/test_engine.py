"""URL assembly, SSL argument shape, and the pool-class branch."""

from __future__ import annotations

import contextlib
import io
import ssl
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from hypervigilant.db.config import AsyncDriver, DBConfig, PoolingMode, SSLConfig, SSLMode
from hypervigilant.db.engine import _connect_args, _ssl_connect_argument, async_url_for, build_engine

pytestmark = pytest.mark.unit


def _config(**overrides: object) -> DBConfig:
    base: dict[str, object] = {
        "host": "db",
        "user": "app",
        "password": SecretStr("p@ss/word?#:"),
        "database": "app",
    }
    return DBConfig(**(base | overrides))  # type: ignore[arg-type]  # test-side kwargs splat


def _silent_engine(config: DBConfig) -> object:
    with contextlib.redirect_stdout(io.StringIO()):
        return build_engine(config)


def test_url_percent_encodes_the_password() -> None:
    """Hand-written into a DSN, ``p@ss`` truncates at the ``@`` and the rest reads as host."""
    url = async_url_for(_config())
    assert url.password == "p@ss/word?#:"
    rendered = url.render_as_string(hide_password=False)
    assert "p%40ss%2Fword%3F%23%3A" in rendered


def test_url_masks_the_password_in_every_rendering() -> None:
    url = async_url_for(_config())
    assert "p@ss" not in str(url)
    assert "p@ss" not in repr(url)
    assert "p@ss" not in url.render_as_string()


def test_url_carries_no_query_string() -> None:
    """SSL travels through ``connect_args``; a query string cannot carry an SSLContext."""
    assert async_url_for(_config(ssl=SSLConfig(mode=SSLMode.REQUIRE))).query == {}


def test_non_verifying_ssl_passes_its_libpq_spelling() -> None:
    assert _ssl_connect_argument(SSLConfig(mode=SSLMode.REQUIRE)) == "require"


def test_asyncpg_require_with_client_certificate_builds_a_context(tmp_path: Path) -> None:
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"
    context = MagicMock(spec=ssl.SSLContext)

    config = _config(
        driver=AsyncDriver.ASYNCPG,
        ssl=SSLConfig(mode=SSLMode.REQUIRE, cert=cert, key=key),
    )

    with patch("hypervigilant.db.engine.ssl.create_default_context", return_value=context):
        result = _connect_args(config)["ssl"]

    assert result is context
    assert context.check_hostname is False
    assert context.verify_mode is ssl.CERT_NONE
    context.load_cert_chain.assert_called_once_with(certfile=str(cert), keyfile=str(key))


@pytest.mark.parametrize("mode", [SSLMode.ALLOW, SSLMode.PREFER])
def test_asyncpg_ssl_argument_defensively_rejects_client_certificate_with_plaintext_fallback(
    tmp_path: Path, mode: SSLMode
) -> None:
    ssl_config = SSLConfig(mode=mode, cert=tmp_path / "client.pem", key=tmp_path / "client.key")

    with pytest.raises(ValueError, match="cannot preserve plaintext fallback"):
        _ssl_connect_argument(ssl_config)


def test_verifying_ssl_explicitly_rejects_a_bypassed_missing_root_cert() -> None:
    invalid = SSLConfig.model_construct(mode=SSLMode.VERIFY_FULL, root_cert=None, cert=None, key=None)

    with pytest.raises(ValueError, match="root_cert"):
        _ssl_connect_argument(invalid)


def test_verifying_ssl_builds_a_real_context(tmp_path: Path) -> None:
    """The defect: ``ssl=require`` gave CERT_NONE, and ``verify-full`` had no CA field.

    A verifying mode must produce a context that actually authenticates.
    """
    ca = tmp_path / "ca.pem"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    with patch("hypervigilant.db.engine.ssl.create_default_context", return_value=context) as create_context:
        result = _ssl_connect_argument(SSLConfig(mode=SSLMode.VERIFY_FULL, root_cert=ca))

    assert isinstance(result, ssl.SSLContext)
    assert result is context
    assert result.check_hostname is True
    assert result.verify_mode is ssl.CERT_REQUIRED
    create_context.assert_called_once_with(cafile=str(ca))


def test_verify_ca_does_not_check_hostname(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    with patch("hypervigilant.db.engine.ssl.create_default_context", return_value=context) as create_context:
        result = _ssl_connect_argument(SSLConfig(mode=SSLMode.VERIFY_CA, root_cert=ca))

    assert isinstance(result, ssl.SSLContext)
    assert result is context
    assert result.check_hostname is False
    assert result.verify_mode is ssl.CERT_REQUIRED
    create_context.assert_called_once_with(cafile=str(ca))


def test_connect_args_carry_server_settings_and_timeouts() -> None:
    args = _connect_args(_config())
    assert args["server_settings"]["application_name"] == "hypervigilant"
    assert args["timeout"] == pytest.approx(10.0)
    assert args["command_timeout"] == pytest.approx(60.0)
    assert args["prepared_statement_cache_size"] == 100


@pytest.mark.parametrize("mode", [SSLMode.ALLOW, SSLMode.PREFER])
def test_psycopg_plaintext_fallback_modes_carry_client_certificate_files(tmp_path: Path, mode: SSLMode) -> None:
    cert = tmp_path / "client.pem"
    key = tmp_path / "client.key"

    args = _connect_args(
        _config(
            driver=AsyncDriver.PSYCOPG,
            ssl=SSLConfig(mode=mode, cert=cert, key=key),
        )
    )

    assert args["sslmode"] == mode.value
    assert args["sslcert"] == str(cert)
    assert args["sslkey"] == str(key)


def test_transaction_pooling_adds_a_unique_statement_namer() -> None:
    """asyncpg's numeric statement names collide behind a transaction-pooling pgbouncer."""
    args = _connect_args(
        _config(
            pooling_mode=PoolingMode.TRANSACTION,
            prepared_statement_cache_size=0,
            idle_in_transaction_session_timeout_ms=None,
        )
    )
    namer = args["prepared_statement_name_func"]
    assert namer() != namer()


def test_pool_class_switches_for_transaction_pooling() -> None:
    """``pool_size``/``max_overflow``/``pool_timeout`` all raise ``TypeError`` under NullPool."""
    direct = _silent_engine(_config())
    pooled = _silent_engine(
        _config(
            pooling_mode=PoolingMode.TRANSACTION,
            prepared_statement_cache_size=0,
            idle_in_transaction_session_timeout_ms=None,
        )
    )
    assert type(direct.pool).__name__ == "AsyncAdaptedQueuePool"  # type: ignore[attr-defined]
    assert type(pooled.pool).__name__ == "NullPool"  # type: ignore[attr-defined]
