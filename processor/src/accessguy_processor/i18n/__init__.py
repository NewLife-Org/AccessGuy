"""Lekka warstwa i18n procesora — katalog `t(key, **kwargs)`.

Jedno źródło prawdy znaczeniowej to angielski (`catalogs/en.json`, język domyślny).
Inne języki (`pl.json`, w przyszłości `de.json`) to tłumaczenia o IDENTYCZNYM zbiorze kluczy
(pilnuje tego `tests/test_i18n.py`). Brak klucza w bieżącym języku -> fallback do EN ->
literał klucza (widoczny, łatwy do wyłapania w raporcie).

Reguły scoringu (tytuł/rekomendacja) NIE są tutaj — żyją w `contracts/rules.yaml` (kanon PL)
+ overlay `rules.<lang>.yaml` (patrz `rules.py`). Tu są: dowody (evidence), etykiety templatek,
konsola, CLI, teksty `community`.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_CATALOGS_DIR = Path(__file__).resolve().parent / "catalogs"

DEFAULT_LANG = "en"
SUPPORTED_LANGS: tuple[str, ...] = ("en", "pl")


@lru_cache(maxsize=None)
def _load_catalog(lang: str) -> dict[str, str]:
    path = _CATALOGS_DIR / f"{lang}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


class Translator:
    """Tłumacz jednego języka. `t(key, **kwargs)` zwraca szablon z podstawionymi placeholderami."""

    def __init__(self, lang: str = DEFAULT_LANG) -> None:
        self.lang = lang if lang in SUPPORTED_LANGS else DEFAULT_LANG
        self._catalog = _load_catalog(self.lang)
        self._fallback = (
            self._catalog if self.lang == DEFAULT_LANG else _load_catalog(DEFAULT_LANG)
        )

    def t(self, key: str, **kwargs: object) -> str:
        template = self._catalog.get(key) or self._fallback.get(key) or key
        if not kwargs:
            return template
        try:
            return template.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            # Niespójny placeholder w tłumaczeniu — oddaj surowy szablon zamiast wywalić raport.
            return template

    # Wygodny alias, żeby można było wstrzyknąć sam callable (np. jako Jinja global).
    __call__ = t


def make_translator(lang: str = DEFAULT_LANG) -> Translator:
    return Translator(lang)
