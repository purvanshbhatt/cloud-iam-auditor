"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloud_iam_auditor.loader import load_policy

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def load(fixtures_dir: Path):
    """Helper that loads a named fixture file and returns its normalized policy."""

    def _load(name: str):
        return load_policy(fixtures_dir / name)

    return _load
