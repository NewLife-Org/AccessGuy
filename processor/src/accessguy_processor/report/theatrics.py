"""Hakerski przebieg generowania raportu (moduł [2]).

Czysto wizualny efekt: zamiast natychmiastowego wyniku, builder odgrywa ~10–15 s etapowego
"bootu silnika raportu" w stylu intra skanera (cyjan → zielony, sporadyczny glitch). NIE
zmienia żadnego artefaktu wyjściowego (HTML/CSV/JSON) — to tylko teatr w konsoli. Wszystkie
napisy są lokalizowane (klucze theatrics.*); wyłączane flagą --no-theatrics.

Etapy są PRAWDZIWE (load → walidacja → rubryka → korelacja → scoring → postawa → render),
tylko spowolnione i ostylowane — operator widzi, co realnie robi procesor.
"""

from __future__ import annotations

import random
import time

from rich.console import Console

from ..i18n import Translator
from ..models import Dataset
from ..rules import load_rubric

_GLITCH = "01<>#/\\|x_=accessguy"


def _glitch(text: str, reveal: float) -> str:
    """Zwraca tekst z częścią znaków podmienionych na 'szum' — im wyższy reveal (0..1), tym czyściej."""
    out = []
    for ch in text:
        if ch == " " or random.random() < reveal:
            out.append(ch)
        else:
            out.append(random.choice(_GLITCH))
    return "".join(out)


def _play_line(console: Console, label: str, dwell: float) -> None:
    """Odsłania jedną linię etapu z efektem glitch->czysto, potem stawia znacznik [ ok ].

    To tylko KRÓTKI boot preambuły — ma być szybki (Daniel). Właściwy raport odsłania się
    wolniej, w `report/console.py` (paced reveal).
    """
    frames = 3
    for i in range(frames):
        reveal = (i + 1) / frames
        console.print(f"[dim cyan]  [ .. ][/] {_glitch(label, reveal)}", end="\r", highlight=False)
        time.sleep(dwell / (frames + 1))
    # finalna, czysta linia
    console.print(f"[bold green]  [ ok ][/] [white]{label}[/]", highlight=False)
    time.sleep(dwell / (frames + 1))


def reveal_section(console: Console, label: str, dwell: float) -> None:
    """Hakerskie odsłonięcie NAGŁÓWKA sekcji raportu: pasek skanowania glitch->czysto.

    Używane przez `report/console.py` do rozłożenia wyświetlania wyniku w czasie (~10 s),
    żeby tabele nie „dumpowały się" naraz. Czysto wizualne — nie zmienia treści raportu.
    """
    frames = 5
    for i in range(frames):
        reveal = (i + 1) / frames
        console.print(f"[dim cyan]  [::] [/]{_glitch(label, reveal)}", end="\r", highlight=False)
        time.sleep(dwell / (frames + 1))
    console.print(f"[bold green]  [>>] [/][bold cyan]{label}[/]", highlight=False)
    time.sleep(dwell / (frames + 1))


def run_build_sequence(
    console: Console, t: Translator, dataset: Dataset, total_seconds: float = 4.0
) -> None:
    """Odgrywa szybki boot silnika (~4 s). To preambuła — raport odsłania się osobno, wolniej."""
    rubric = load_rubric(lang=t.lang)
    rules_total = len(rubric.rules) + len(rubric.group_rules) + len(rubric.app_rules)

    stages: list[str] = [
        t.t("theatrics.stage.boot"),
        t.t(
            "theatrics.stage.load",
            tenant=dataset.tenant.display_name or dataset.tenant.id or "?",
            accounts=len(dataset.accounts),
            groups=len(dataset.groups),
            apps=len(dataset.applications),
        ),
        t.t("theatrics.stage.schema", schema=dataset.schema_version),
        t.t("theatrics.stage.rules", rules=rules_total),
        t.t("theatrics.stage.correlate"),
        t.t("theatrics.stage.score"),
        t.t("theatrics.stage.posture"),
        t.t("theatrics.stage.render"),
        t.t("theatrics.stage.done"),
    ]

    bar = "─" * 52
    console.print(f"\n[bold green]┌─[ {t.t('theatrics.title')} ]{bar}[/]", highlight=False)
    dwell = max(0.3, total_seconds / len(stages))
    for label in stages:
        _play_line(console, label, dwell)
    console.print(f"[bold green]└{'─' * (len(bar) + len(t.t('theatrics.title')) + 6)}[/]\n", highlight=False)
