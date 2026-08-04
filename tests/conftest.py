"""Shared fixtures for the (no-live-database) unit test suite."""
import sys
from pathlib import Path
from typing import Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PATTERNS_PATH = Path(__file__).resolve().parent.parent / "config" / "sensitive_patterns.json"


class FakeConnector:
    """
    A drop-in stand-in for PostgreConnector that serves canned column metadata
    and sample values instead of hitting a real database. Lets scanner tests
    run fast and without any PostgreSQL instance.
    """

    def __init__(self, columns: List[Dict[str, str]], samples: Dict[str, List[str]]):
        self._columns = columns
        self._samples = samples

    def get_columns(self, table, schema="public"):
        return self._columns

    def get_tables(self, schema="public"):
        return ["fake_table"]

    def sample_columns(self, table, columns, schema="public", limit=100):
        return {c: self._samples.get(c, []) for c in columns}

    @staticmethod
    def scannable_columns(columns):
        return [c["name"] for c in columns if c["data_type"] not in ("boolean", "bytea", "ARRAY")]


@pytest.fixture
def patterns_path():
    return str(PATTERNS_PATH)


@pytest.fixture
def make_connector():
    def _make(columns, samples):
        return FakeConnector(columns, samples)
    return _make
