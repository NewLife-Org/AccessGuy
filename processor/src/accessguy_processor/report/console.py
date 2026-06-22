"""Kolorowe podsumowanie w konsoli (rich)."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..i18n import Translator
from ..models import Dataset, Severity
from .community import (
    build_action_plan,
    build_community,
    build_escalation_paths,
    build_posture,
)
from .theatrics import reveal_section

# Hakerskie, stopniowane odsłanianie wyniku (~10 s łącznie, gdy paced=True). Sekcji jest ~8;
# każda dostaje krótki "skan" nagłówka. Pominięte sekcje (brak danych) skracają całość — OK.
_REVEAL_DWELL = 1.15


def _reveal(c: Console, t: Translator, key: str, paced: bool) -> None:
    if paced:
        reveal_section(c, t.t(key), _REVEAL_DWELL)

_SEVERITY_STYLE: dict[Severity, str] = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_GRADE_STYLE: dict[str, str] = {
    "A": "bold green",
    "B": "bold spring_green3",
    "C": "bold yellow",
    "D": "bold dark_orange",
    "F": "bold white on red",
}


def render_console(
    dataset: Dataset, console: Console | None = None, lang: str = "en", paced: bool = False
) -> None:
    c = console or Console()
    t = Translator(lang)

    cats = Counter(a.category for a in dataset.accounts)
    sevs = Counter(a.severity for a in dataset.accounts)
    community = build_community(dataset, t)

    grade = community["grade"]
    mfa = community["mfa_coverage"]
    _reveal(c, t, "reveal.panel", paced)
    c.print(
        Panel.fit(
            f"[bold cyan]AccessGuy[/] — {t.t('console.panel.subtitle')}\n"
            f"{t.t('console.panel.tenant')}: [white]{dataset.tenant.display_name}[/]  ·  "
            f"{t.t('console.panel.accounts')}: [white]{len(dataset.accounts)}[/]  ·  "
            f"{t.t('console.panel.mode')}: [white]{dataset.scan_context.auth_mode}[/]  ·  "
            f"{t.t('console.panel.generated')}: [white]{dataset.generated_at.isoformat()}[/]\n"
            f"Internal: {cats['internal']}  ·  External: {cats['external']}  ·  Guest: {cats['guest']}\n"
            f"{t.t('console.panel.posture_grade')}: [{_GRADE_STYLE.get(grade, 'bold')}] {grade} [/] "
            f"[dim]{community['grade_note']}[/]  ·  "
            f"MFA: [white]{f'{mfa}%' if mfa is not None else '—'}[/]  ·  "
            f"GA: [white]{community['global_admin_count']}[/]  ·  "
            f"{t.t('console.panel.priv_no_mfa')}: "
            f"[{'bold red' if community['priv_no_mfa_count'] else 'green'}]{community['priv_no_mfa_count']}[/]",
            title=t.t("console.panel.title"),
            border_style="cyan",
        )
    )

    # rozkład severity
    _reveal(c, t, "reveal.severity", paced)
    sev_table = Table(title=t.t("console.sev.title"), show_edge=False)
    sev_table.add_column(t.t("console.sev.col_severity"))
    sev_table.add_column(t.t("console.sev.col_count"), justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_table.add_row(f"[{_SEVERITY_STYLE[sev]}]{sev}[/]", str(sevs.get(sev, 0)))
    c.print(sev_table)

    # konta wymagające uwagi
    flagged = [a for a in dataset.accounts if a.severity in ("critical", "high")]
    if not flagged:
        c.print(f"[green]{t.t('console.accounts.none')}[/]")
        return

    _reveal(c, t, "reveal.accounts", paced)
    table = Table(title=t.t("console.accounts.title"))
    table.add_column(t.t("console.sev.col_severity"))
    table.add_column(t.t("console.col.score"), justify="right")
    table.add_column(t.t("console.col.upn"))
    table.add_column(t.t("console.col.category"))
    table.add_column(t.t("console.col.signals"))
    for a in flagged:
        signals = "; ".join(f.title for f in a.flags[:3])
        table.add_row(
            f"[{_SEVERITY_STYLE[a.severity]}]{a.severity}[/]",
            str(a.review_score),
            a.user_principal_name,
            a.category,
            signals,
        )
    c.print(table)

    if dataset.groups:
        _reveal(c, t, "reveal.groups", paced)
    _render_module(c, t, t.t("community.module.groups"), dataset.groups, lambda g: g.display_name)
    if dataset.applications:
        _reveal(c, t, "reveal.apps", paced)
    _render_module(c, t, t.t("community.module.apps"), dataset.applications, lambda a: a.display_name)
    _render_posture(c, t, dataset, paced=paced)
    _render_escalation_paths(c, t, dataset, paced=paced)
    _render_action_plan(c, t, dataset, paced=paced)


def _render_posture(c: Console, t: Translator, dataset: Dataset, limit: int = 5, paced: bool = False) -> None:
    """Najcięższe luki konfiguracji tenanta (CA + polityki, 1.3) — pełna lista w summary."""
    posture = build_posture(dataset, t)
    if not posture or not posture["findings"]:
        return
    _reveal(c, t, "reveal.posture", paced)
    c.print(f"\n[bold cyan]{t.t('console.posture.heading')}[/] [dim]({t.t('console.posture.subtitle')})[/]")
    for f in posture["findings"][:limit]:
        c.print(f"  [{_SEVERITY_STYLE[f['severity']]}] {f['severity']} [/] {f['text']}")


def _render_escalation_paths(c: Console, t: Translator, dataset: Dataset, limit: int = 6, paced: bool = False) -> None:
    """Imienne łańcuchy eskalacji — korelacja tożsamość × grupa × aplikacja × logi."""
    paths = build_escalation_paths(dataset, t, limit=limit)
    if not paths:
        return
    _reveal(c, t, "reveal.escalation", paced)
    c.print(f"\n[bold red]{t.t('console.escalation.heading')}[/] [dim]({t.t('console.escalation.subtitle')})[/]")
    for p in paths:
        flow = " [bold cyan]→[/] ".join(p["steps"])
        c.print(
            f"  [{_SEVERITY_STYLE[p['severity']]}] {p['severity']} [/] {flow}\n"
            f"     [dim]{t.t('console.escalation.evidence', evidence=p['evidence'])}[/]"
        )


def _render_action_plan(c: Console, t: Translator, dataset: Dataset, limit: int = 5, paced: bool = False) -> None:
    """Top działań do podjęcia — ta sama agregacja, co sekcja 'Plan działań' w summary."""
    plan = build_action_plan(dataset, t, limit=limit)
    if not plan:
        return
    _reveal(c, t, "reveal.plan", paced)
    table = Table(title=t.t("console.action.title", n=len(plan)), show_edge=False)
    table.add_column("#", justify="right")
    table.add_column(t.t("console.sev.col_severity"))
    table.add_column(t.t("console.action.col_action"))
    table.add_column(t.t("console.action.col_module"))
    table.add_column(t.t("console.action.col_objects"), justify="right")
    for i, step in enumerate(plan, start=1):
        table.add_row(
            str(i),
            f"[{_SEVERITY_STYLE[step['severity']]}]{step['severity']}[/]",
            step["title"],
            step["module"],
            str(step["count"]),
        )
    c.print(table)
    c.print(f"[dim]{t.t('console.action.full_list')}[/]")


def _render_module(c: Console, t: Translator, label: str, items: list, name) -> None:
    """Kompaktowe podsumowanie modułu (grupy/aplikacje): rozkład severity + najgorsze obiekty."""
    if not items:
        return
    sevs = Counter(i.severity for i in items)
    dist = "  ".join(
        f"[{_SEVERITY_STYLE[s]}]{s}:{sevs.get(s, 0)}[/]"
        for s in _SEVERITY_STYLE
        if sevs.get(s, 0)
    )
    no_risks = f"[green]{t.t('console.module.no_risks')}[/]"
    c.print(f"\n[bold cyan]{label}[/] ({len(items)}): {dist or no_risks}")
    flagged = [i for i in items if i.severity in ("critical", "high")]
    if not flagged:
        return
    table = Table(show_edge=False)
    table.add_column(t.t("console.sev.col_severity"))
    table.add_column(t.t("console.col.score"), justify="right")
    table.add_column(t.t("console.col.name"))
    table.add_column(t.t("console.col.signals"))
    for i in sorted(flagged, key=lambda x: -x.review_score):
        table.add_row(
            f"[{_SEVERITY_STYLE[i.severity]}]{i.severity}[/]",
            str(i.review_score),
            name(i),
            "; ".join(f.title for f in i.flags[:3]),
        )
    c.print(table)
