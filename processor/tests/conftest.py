"""Fixtures testowe — korzystamy z kanonicznego sample z contracts/samples."""

from __future__ import annotations

from pathlib import Path

import pytest

_SAMPLE = Path(__file__).resolve().parents[2] / "contracts" / "samples" / "dataset.sample.json"


@pytest.fixture
def sample_dataset_path() -> Path:
    return _SAMPLE
