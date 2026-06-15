"""Testy planu działań (agregacja flag) i głębokich linków (id w top_findings)."""

from __future__ import annotations

from accessguy_processor.ingest import load_dataset
from accessguy_processor.report.community import (
    _SEV_RANK,
    build_action_plan,
    build_community,
)
from accessguy_processor.rules import load_rubric
from accessguy_processor.scoring import score_dataset


def _scored(sample_dataset_path):
    return score_dataset(load_dataset(sample_dataset_path), load_rubric())


def test_action_plan_aggregates_flags(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    plan = build_action_plan(ds)

    assert plan, "sample dataset ma flagi, plan nie może być pusty"
    # jedna pozycja = jedna reguła w jednym module; count zgadza się z liczbą obiektów z tą flagą
    by_key = {(s["module_key"], s["code"]): s for s in plan}
    assert len(by_key) == len(plan), "pozycje planu muszą być unikalne per (moduł, reguła)"
    for step in plan:
        assert step["count"] >= 1
        assert step["points"] >= step["count"]  # każda flaga ma >=1 pkt
        assert 1 <= len(step["examples"]) <= 3
        assert all(ex["id"] and ex["name"] for ex in step["examples"])


def test_action_plan_sorted_by_severity_then_points(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    plan = build_action_plan(ds)
    keys = [(_SEV_RANK[s["severity"]], -s["points"]) for s in plan]
    assert keys == sorted(keys), "plan musi być posortowany: severity, potem suma punktów"


def test_action_plan_respects_limit(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    assert len(build_action_plan(ds, limit=2)) <= 2


def test_top_findings_carry_object_id(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    community = build_community(ds)
    assert community["top_findings"], "sample dataset ma konta z flagami"
    for t in community["top_findings"]:
        assert t["id"], "głębokie linki w summary wymagają id obiektu"
