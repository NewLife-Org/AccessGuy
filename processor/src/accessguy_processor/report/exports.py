"""Eksporty surowe: CSV (płaska tabela) i JSON (pełny model po scoringu)."""

from __future__ import annotations

import csv
from pathlib import Path

from ..models import Dataset


def export_json(dataset: Dataset, output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        dataset.model_dump_json(by_alias=True, indent=2),
        encoding="utf-8",
    )
    return out


def export_csv(dataset: Dataset, output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["upn", "displayName", "category", "enabled", "severity", "score", "flags"]
        )
        for a in dataset.accounts:
            writer.writerow(
                [
                    a.user_principal_name,
                    a.display_name,
                    a.category,
                    a.account_enabled,
                    a.severity,
                    a.review_score,
                    " | ".join(f.code for f in a.flags),
                ]
            )
    return out


def export_groups_csv(dataset: Dataset, output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "displayName", "kind", "membership", "roleAssignable", "members",
                "guests", "owners", "roles", "licenses", "severity", "score", "flags",
            ]
        )
        for g in dataset.groups:
            writer.writerow(
                [
                    g.display_name,
                    g.group_kind,
                    g.membership_type,
                    g.is_assignable_to_role,
                    g.member_count if g.member_count is not None else "",
                    g.guest_count if g.guest_count is not None else "",
                    g.owner_count if g.owner_count is not None else len(g.owners),
                    " | ".join(r.role_name for r in g.assigned_roles),
                    " | ".join(g.assigned_licenses),
                    g.severity,
                    g.review_score,
                    " | ".join(f.code for f in g.flags),
                ]
            )
    return out


def export_apps_csv(dataset: Dataset, output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "displayName", "appId", "signInAudience", "enabled", "owners",
                "secrets", "certs", "highRiskPermissions", "severity", "score", "flags",
            ]
        )
        for a in dataset.applications:
            writer.writerow(
                [
                    a.display_name,
                    a.app_id or "",
                    a.sign_in_audience or "",
                    a.account_enabled if a.account_enabled is not None else "",
                    " | ".join(a.owners),
                    len(a.secrets),
                    sum(1 for c in a.credentials if c.kind == "certificate"),
                    " | ".join(sorted({p.permission for p in a.high_risk_permissions})),
                    a.severity,
                    a.review_score,
                    " | ".join(f.code for f in a.flags),
                ]
            )
    return out
