"""Silnik scoringu: generyczny, sterowany danymi z rules.yaml.

Dla każdego obiektu (konto / grupa / aplikacja) iteruje właściwą listę reguł, woła
odpowiadający predykat, a przy odpaleniu tworzy ReviewFlag z metadanymi reguły
(punkty/severity/rekomendacja) i evidence z predykatu. Sumę punktów mapuje na severity.

Trzy typy obiektów dzielą tę samą mechanikę — różnią się tylko zestawem reguł i rejestrem
predykatów. Stąd jeden generyczny `_score_entity`, a `score_account/group/app` to cienkie wejścia.
"""

from __future__ import annotations

from datetime import datetime
from typing import Callable, Protocol

from ..models import Account, Application, Dataset, Group, ReviewFlag, Severity
from ..rules import Rubric, Rule, load_rubric
from .correlation import CorrelationIndex
from .predicates import PREDICATES, ScoringContext
from .predicates_app import APP_PREDICATES
from .predicates_group import GROUP_PREDICATES

_SEVERITY_ORDER: list[Severity] = ["info", "low", "medium", "high", "critical"]


class _Scorable(Protocol):
    """Wspólny kształt obiektu poddawanego scoringowi (Account/Group/Application)."""

    review_score: int
    severity: Severity
    flags: list[ReviewFlag]


def _derive_severity(score: int, bands: dict[str, int]) -> Severity:
    level: Severity = "info"
    for name in ("low", "medium", "high", "critical"):
        if score >= bands[name]:
            level = name  # type: ignore[assignment]
    return level


def _score_entity(
    entity: _Scorable,
    rules: list[Rule],
    predicates: dict[str, Callable[..., str | None]],
    ctx: ScoringContext,
    bands: dict[str, int],
) -> _Scorable:
    flags: list[ReviewFlag] = []
    for rule in rules:
        predicate = predicates.get(rule.id)
        if predicate is None:
            # Reguła w YAML bez predykatu w kodzie — świadomie pomijamy (nie zgadujemy).
            continue
        ctx.rule = rule
        evidence = predicate(entity, ctx)
        if evidence:
            flags.append(
                ReviewFlag(
                    code=rule.id,
                    title=rule.title,
                    severity=rule.severity,  # type: ignore[arg-type]
                    points=rule.points,
                    evidence=evidence,
                    recommendation=rule.recommendation,
                )
            )
    entity.flags = sorted(flags, key=lambda f: -f.points)
    entity.review_score = sum(f.points for f in flags)
    entity.severity = _derive_severity(entity.review_score, bands)
    return entity


def score_account(
    acc: Account,
    rubric: Rubric,
    generated_at: datetime,
    index: CorrelationIndex | None = None,
) -> Account:
    ctx = ScoringContext(rubric=rubric, generated_at=generated_at, index=index)
    _score_entity(acc, rubric.rules, PREDICATES, ctx, rubric.severity_bands)
    return acc


def score_group(
    grp: Group,
    rubric: Rubric,
    generated_at: datetime,
    index: CorrelationIndex | None = None,
) -> Group:
    ctx = ScoringContext(rubric=rubric, generated_at=generated_at, index=index)
    _score_entity(grp, rubric.group_rules, GROUP_PREDICATES, ctx, rubric.severity_bands)
    return grp


def score_application(
    app: Application,
    rubric: Rubric,
    generated_at: datetime,
    index: CorrelationIndex | None = None,
) -> Application:
    ctx = ScoringContext(rubric=rubric, generated_at=generated_at, index=index)
    _score_entity(app, rubric.app_rules, APP_PREDICATES, ctx, rubric.severity_bands)
    return app


def score_dataset(dataset: Dataset, rubric: Rubric | None = None) -> Dataset:
    rb = rubric or load_rubric()
    # Indeks korelacyjny budowany RAZ — reguły mogą patrzeć w poprzek modułów
    # (członkostwa grup, właściciele aplikacji, przypisania) bez O(n²) skanów.
    index = CorrelationIndex.build(dataset)
    for acc in dataset.accounts:
        score_account(acc, rb, dataset.generated_at, index)
    for grp in dataset.groups:
        score_group(grp, rb, dataset.generated_at, index)
    for app in dataset.applications:
        score_application(app, rb, dataset.generated_at, index)
    # sortuj malejąco po ryzyku — najpierw to, co wymaga uwagi
    dataset.accounts.sort(key=lambda a: -a.review_score)
    dataset.groups.sort(key=lambda g: -g.review_score)
    dataset.applications.sort(key=lambda a: -a.review_score)
    return dataset
