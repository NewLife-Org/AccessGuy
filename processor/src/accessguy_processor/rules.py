"""Wczytanie rubryki scoringu (contracts/rules.yaml) do typowanych obiektów.

Metadane reguł (tytuł/severity/punkty/rekomendacja/progi) pochodzą z YAML.
Logikę 'czy reguła się odpala' dostarcza predicates.py (funkcja o tym samym id).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_CONTRACTS_DIR = Path(__file__).resolve().parents[3] / "contracts"
_RULES_PATH = _CONTRACTS_DIR / "rules.yaml"

# Język kanoniczny pliku rules.yaml (tytuły/rekomendacje po polsku). Inne języki dostają
# overlay `rules.<lang>.yaml` z samymi tytułami/rekomendacjami po id (patrz _apply_overlay).
_CANONICAL_LANG = "pl"


def _apply_overlay(data: dict[str, Any], lang: str) -> dict[str, Any]:
    """Nakłada overlay rules.<lang>.yaml na bazę: TYLKO title/recommendation po id reguły.

    Logika/punkty/severity/progi NIGDY z overlaya — to zostaje w kanonicznym rules.yaml.
    Brak overlaya albo brak id w overlayu => zostaje wartość bazowa (kanon PL)."""
    if lang == _CANONICAL_LANG:
        return data
    overlay_path = _CONTRACTS_DIR / f"rules.{lang}.yaml"
    if not overlay_path.exists():
        return data
    overlay = yaml.safe_load(overlay_path.read_text(encoding="utf-8")) or {}
    for section in ("rules", "groupRules", "appRules"):
        trans = overlay.get(section, {}) or {}
        for rule in data.get(section, []):
            tr = trans.get(rule["id"])
            if not tr:
                continue
            if "title" in tr:
                rule["title"] = tr["title"]
            if "recommendation" in tr:
                rule["recommendation"] = tr["recommendation"]
    return data


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    points: int
    recommendation: str
    thresholds: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Rubric:
    thresholds: dict[str, int]
    severity_bands: dict[str, int]
    privileged_roles: list[str]
    high_risk_app_scopes: list[str]
    high_risk_app_roles: list[str]
    broad_read_app_roles: list[str]
    rules: list[Rule]
    group_rules: list[Rule]
    app_rules: list[Rule]

    def threshold(self, name: str, rule: Rule | None = None) -> int:
        """Próg z reguły (jeśli nadpisany), inaczej globalny."""
        if rule and name in rule.thresholds:
            return int(rule.thresholds[name])
        return int(self.thresholds[name])


def load_rubric(rules_path: Path | None = None, lang: str = "en") -> Rubric:
    path = rules_path or _RULES_PATH
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data = _apply_overlay(data, lang)

    def _rules(key: str) -> list[Rule]:
        return [
            Rule(
                id=r["id"],
                title=r["title"],
                severity=r["severity"],
                points=int(r["points"]),
                recommendation=r["recommendation"],
                thresholds=r.get("thresholds", {}),
            )
            for r in data.get(key, [])
        ]

    return Rubric(
        thresholds=data["thresholds"],
        severity_bands=data["severityBands"],
        privileged_roles=data.get("privilegedRoles", []),
        high_risk_app_scopes=data.get("highRiskAppScopes", []),
        high_risk_app_roles=data.get("highRiskAppRoles", []),
        broad_read_app_roles=data.get("broadReadAppRoles", []),
        rules=_rules("rules"),
        group_rules=_rules("groupRules"),
        app_rules=_rules("appRules"),
    )
