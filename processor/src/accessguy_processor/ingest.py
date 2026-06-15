"""Wczytanie i walidacja datasetu.

Najpierw walidujemy surowy JSON względem contracts/dataset.schema.json (twardy kontrakt),
dopiero potem parsujemy do modeli pydantic. Dwuwarstwowa walidacja = szybkie, czytelne błędy.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from .models import Dataset

# contracts/ leży obok katalogu processor/ w repo:
# .../accessguy/processor/src/accessguy_processor/ingest.py -> parents[3] == .../accessguy
_CONTRACTS_DIR = Path(__file__).resolve().parents[3] / "contracts"
_SCHEMA_PATH = _CONTRACTS_DIR / "dataset.schema.json"

SUPPORTED_MAJOR = "1"


class DatasetError(Exception):
    """Błąd wczytania/walidacji datasetu."""


def load_schema(schema_path: Path | None = None) -> dict:
    path = schema_path or _SCHEMA_PATH
    if not path.exists():
        raise DatasetError(f"Nie znaleziono schematu: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_dataset(dataset_path: str | Path, schema_path: Path | None = None) -> Dataset:
    path = Path(dataset_path)
    if not path.exists():
        raise DatasetError(f"Nie znaleziono datasetu: {path}")

    raw = json.loads(path.read_text(encoding="utf-8"))

    schema = load_schema(schema_path)
    try:
        jsonschema.validate(instance=raw, schema=schema)
    except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
        loc = "/".join(str(p) for p in exc.absolute_path) or "(root)"
        raise DatasetError(f"Dataset niezgodny ze schematem w '{loc}': {exc.message}") from exc

    major = str(raw.get("schemaVersion", "")).split(".")[0]
    if major != SUPPORTED_MAJOR:
        raise DatasetError(
            f"Niezgodna wersja schematu: {raw.get('schemaVersion')} "
            f"(procesor obsługuje major {SUPPORTED_MAJOR}.x)"
        )

    return Dataset.model_validate(raw)
