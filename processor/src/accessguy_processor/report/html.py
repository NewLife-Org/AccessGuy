"""Render raportów HTML (jinja2) i opcjonalnie PDF (weasyprint).

Hybryda (1.2): cztery samodzielne pliki, wspólny branding/CSS:
  - summary  — zbiorcza postawa tenanta A–F (łącznie konta+grupy+aplikacje) + spostrzeżenia
  - users    — szczegóły kont (dawny pełny raport)
  - groups   — szczegóły grup
  - apps     — szczegóły aplikacji
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import branding
from ..models import Dataset
from .community import (
    build_action_plan,
    build_apps_view,
    build_community,
    build_escalation_paths,
    build_groups_view,
    build_overview,
    build_posture,
    friendly_sku,
)

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["friendly_sku"] = friendly_sku
    return env


def _base_ctx() -> dict:
    return {
        "css": (_TEMPLATES_DIR / "assets" / "style.css").read_text(encoding="utf-8"),
        "rendered_at": datetime.now(timezone.utc).isoformat(),
        "access_guy_logo": branding.ACCESS_GUY_LOGO,
        "access_guy_text": branding.ACCESS_GUY_TEXT,
        "tattoo_logo": branding.TATTOO_LOGO,
        "linkedin": branding.LINKEDIN,
        "github": branding.GITHUB,
    }


def _write(template_name: str, output_path: str | Path, **ctx) -> Path:
    env = _env()
    template = env.get_template(template_name)
    html = template.render(**_base_ctx(), **ctx)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


def render_users_html(dataset: Dataset, output_path: str | Path) -> Path:
    return _write(
        "report.html.j2",
        output_path,
        dataset=dataset,
        cats=Counter(a.category for a in dataset.accounts),
        sevs=Counter(a.severity for a in dataset.accounts),
        community=build_community(dataset),
    )


# Alias zachowujący wsteczną zgodność (testy/CLI używały render_html dla raportu kont).
render_html = render_users_html


def render_groups_html(dataset: Dataset, output_path: str | Path) -> Path:
    return _write(
        "groups.html.j2",
        output_path,
        dataset=dataset,
        view=build_groups_view(dataset),
    )


def render_apps_html(dataset: Dataset, output_path: str | Path) -> Path:
    # Mapa grup po id — pozwala rozwinąć konkretnych członków grupy przypisanej do aplikacji.
    groups_by_id = {g.id: g for g in dataset.groups}
    return _write(
        "apps.html.j2",
        output_path,
        dataset=dataset,
        view=build_apps_view(dataset),
        groups_by_id=groups_by_id,
    )


def render_summary_html(dataset: Dataset, output_path: str | Path) -> Path:
    community = build_community(dataset)
    groups_view = build_groups_view(dataset)
    apps_view = build_apps_view(dataset)
    posture = build_posture(dataset)

    # Linki do raportów szczegółowych: summary to '<base>_summary.html', a siostry
    # '<base>_{users,groups,apps}.html'. Liczymy względne nazwy (ten sam katalog).
    name = Path(output_path).name
    base = name[: -len("_summary.html")] if name.endswith("_summary.html") else Path(output_path).stem
    links = {
        "users": f"{base}_users.html",
        "groups": f"{base}_groups.html",
        "apps": f"{base}_apps.html",
    }
    return _write(
        "summary.html.j2",
        output_path,
        dataset=dataset,
        community=community,
        groups_view=groups_view,
        apps_view=apps_view,
        overview=build_overview(dataset, community, groups_view, apps_view, posture),
        action_plan=build_action_plan(dataset),
        escalation_paths=build_escalation_paths(dataset),
        posture=posture,
        links=links,
    )


def render_pdf(dataset: Dataset, output_path: str | Path) -> Path:
    """Wymaga extra [pdf] (weasyprint). Renderuje raport kont do PDF (jak dawniej)."""
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "PDF wymaga: pip install 'accessguy-processor[pdf]' (weasyprint)."
        ) from exc

    html_tmp = Path(output_path).with_suffix(".html")
    render_users_html(dataset, html_tmp)
    out = Path(output_path)
    HTML(filename=str(html_tmp)).write_pdf(str(out))
    return out
