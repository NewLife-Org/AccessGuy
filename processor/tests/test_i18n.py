"""Testy warstwy i18n: parytet kluczy między językami + spójność placeholderów + overlay reguł.

Gwarantują, że dodanie kolejnego języka (np. de) nie rozjedzie raportu: każdy język ma
IDENTYCZNY zbiór kluczy, a placeholdery {x} w tłumaczeniu zgadzają się z angielską referencją.
"""

from __future__ import annotations

import json
import re
import string
from pathlib import Path

import pytest

from accessguy_processor.i18n import (
    DEFAULT_LANG,
    SUPPORTED_LANGS,
    Translator,
    _CATALOGS_DIR,
)
from accessguy_processor.rules import load_rubric

_CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"


def _catalog(lang: str) -> dict[str, str]:
    return json.loads((_CATALOGS_DIR / f"{lang}.json").read_text(encoding="utf-8"))


def _placeholders(template: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(template) if name}


@pytest.mark.parametrize("lang", [lang for lang in SUPPORTED_LANGS if lang != DEFAULT_LANG])
def test_key_parity_with_default(lang: str) -> None:
    ref = set(_catalog(DEFAULT_LANG))
    other = set(_catalog(lang))
    assert ref == other, (
        f"Katalog '{lang}' rozjechany z '{DEFAULT_LANG}': "
        f"brakuje {sorted(ref - other)}, nadmiarowe {sorted(other - ref)}"
    )


@pytest.mark.parametrize("lang", [lang for lang in SUPPORTED_LANGS if lang != DEFAULT_LANG])
def test_placeholder_parity(lang: str) -> None:
    ref = _catalog(DEFAULT_LANG)
    other = _catalog(lang)
    mismatched = {
        key: (sorted(_placeholders(ref[key])), sorted(_placeholders(other[key])))
        for key in ref
        if key in other and _placeholders(ref[key]) != _placeholders(other[key])
    }
    assert not mismatched, f"Niespójne placeholdery w '{lang}': {mismatched}"


def test_translator_fallback_to_english() -> None:
    """Brak klucza w bieżącym języku -> EN -> literał klucza."""
    t = Translator("pl")
    assert t.t("evidence.NO_MFA") == "Brak zarejestrowanego MFA."
    assert t.t("totally.missing.key") == "totally.missing.key"


def test_translator_formats_placeholders() -> None:
    t = Translator("en")
    assert t.t("evidence.INACTIVE_90", days=120, warn=90) == (
        "Last sign-in: 120 days ago (threshold 90)."
    )


def test_unknown_lang_falls_back_to_default() -> None:
    assert Translator("xx").lang == DEFAULT_LANG


def test_rules_overlay_translates_every_rule() -> None:
    """Po nałożeniu overlaya EN żaden tytuł/rekomendacja nie zostaje po polsku."""
    en = load_rubric(lang="en")
    polish = re.compile(r"[ąćęłńóśźżĄĆĘŁŃÓŚŹŻ]")
    leftover = [
        r.id
        for r in (*en.rules, *en.group_rules, *en.app_rules)
        if polish.search(r.title) or polish.search(r.recommendation)
    ]
    assert not leftover, f"Reguły bez tłumaczenia EN: {leftover}"


def test_rules_pl_is_canonical() -> None:
    """rules.yaml jest kanonem PL — bez overlaya tytuły są po polsku."""
    pl = load_rubric(lang="pl")
    assert "Konto nieaktywne" in pl.rules[0].title


def test_rules_de_overlay_optional() -> None:
    """Brak rules.de.yaml nie wywala loadera — zostaje baza PL (architektura gotowa na DE)."""
    de = load_rubric(lang="de")
    assert de.rules  # ładuje się bez błędu
