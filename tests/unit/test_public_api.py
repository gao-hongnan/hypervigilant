from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest


class TestTopLevelImports:
    def test_top_level_imports_resolve(self) -> None:
        import hypervigilant

        expected = {
            "LOG_LEVEL_MAP",
            "BaseLoggingConfig",
            "BoundLogger",
            "ConsoleFormatterStrategy",
            "FileOutputStrategy",
            "FormatterStrategy",
            "JsonFormatterStrategy",
            "LoggerFactory",
            "LogLevel",
            "NativeLoggingConfig",
            "OutputStrategy",
            "StreamOutputStrategy",
            "StructlogConfig",
            "bind_context",
            "clear_context",
            "configure_logging",
            "get_logger",
        }
        assert set(hypervigilant.__all__) == expected
        for name in expected:
            assert getattr(hypervigilant, name) is not None

    def test_loggers_subpackage_imports_resolve(self) -> None:
        from hypervigilant import StructlogConfig as TopLevelStructlogConfig
        from hypervigilant.loggers import StructlogConfig as SubpackageStructlogConfig

        assert TopLevelStructlogConfig is SubpackageStructlogConfig


class TestOtelRemoval:
    def test_otel_module_gone(self) -> None:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("hypervigilant._otel")


class TestPyproject:
    def test_version_and_no_otel_extra(self) -> None:
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        assert data["project"]["version"] == "19.0.0"
        optional = data["project"].get("optional-dependencies", {})
        assert "otel" not in optional
