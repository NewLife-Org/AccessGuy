"""Kolorowe podsumowanie w konsoli (rich)."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..models import Dataset, Severity
from .community import (
    build_action_plan,
    build_community,
    build_escalation_paths,
    build_posture,
)

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


def render_console(dataset: Dataset, console: Console | None = None) -> None:
    c = console or Console()

    cats = Counter(a.category for a in dataset.accounts)
    sevs = Counter(a.severity for a in dataset.accounts)
    community = build_community(dataset)

    grade = community["grade"]
    mfa = community["mfa_coverage"]
    c.print(
        Panel.fit(
            f"[bold cyan]AccessGuy[/] — przegląd uprawnień\n"
            f"Tenant: [white]{dataset.tenant.display_name}[/]  ·  "
            f"Kont: [white]{len(dataset.accounts)}[/]  ·  "
            f"Tryb: [white]{dataset.scan_context.auth_mode}[/]  ·  "
            f"Wygenerowano: [white]{dataset.generated_at.isoformat()}[/]\n"
            f"Internal: {cats['internal']}  ·  External: {cats['external']}  ·  Guest: {cats['guest']}\n"
            f"Ocena postawy: [{_GRADE_STYLE.get(grade, 'bold')}] {grade} [/] "
            f"[dim]{community['grade_note']}[/]  ·  "
            f"MFA: [white]{f'{mfa}%' if mfa is not None else '—'}[/]  ·  "
            f"GA: [white]{community['global_admin_count']}[/]  ·  "
            f"Uprzywilejowani bez MFA: "
            f"[{'bold red' if community['priv_no_mfa_count'] else 'green'}]{community['priv_no_mfa_count']}[/]",
            title="Podsumowanie",
            border_style="cyan",
        )
    )

    # rozkład severity
    sev_table = Table(title="Rozkład severity", show_edge=False)
    sev_table.add_column("Severity")
    sev_table.add_column("Liczba", justify="right")
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_table.add_row(f"[{_SEVERITY_STYLE[sev]}]{sev}[/]", str(sevs.get(sev, 0)))
    c.print(sev_table)

    # konta wymagające uwagi
    flagged = [a for a in dataset.accounts if a.severity in ("critical", "high")]
    if not flagged:
        c.print("[green]Brak kont o severity high/critical.[/]")
        return

    table = Table(title="Konta wymagające przeglądu (high/critical)")
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("UPN")
    table.add_column("Kat.")
    table.add_column("Główne sygnały")
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

    _render_module(c, "Grupy", dataset.groups, lambda g: g.display_name)
    _render_module(c, "Aplikacje", dataset.applications, lambda a: a.display_name)
    _render_posture(c, dataset)
    _render_escalation_paths(c, dataset)
    _render_action_plan(c, dataset)


def _render_posture(c: Console, dataset: Dataset, limit: int = 5) -> None:
    """Najcięższe luki konfiguracji tenanta (CA + polityki, 1.3) — pełna lista w summary."""
    posture = build_posture(dataset)
    if not posture or not posture["findings"]:
        return
    c.print("\n[bold cyan]Konfiguracja tenanta[/] [dim](Conditional Access + polityki)[/]")
    for f in posture["findings"][:limit]:
        c.print(f"  [{_SEVERITY_STYLE[f['severity']]}] {f['severity']} [/] {f['text']}")


def _render_escalation_paths(c: Console, dataset: Dataset, limit: int = 6) -> None:
    """Imienne łańcuchy eskalacji — korelacja tożsamość × grupa × aplikacja × logi."""
    paths = build_escalation_paths(dataset, limit=limit)
    if not paths:
        return
    c.print("\n[bold red]Ścieżki eskalacji[/] [dim](korelacja modułów + logi sign-in)[/]")
    for p in paths:
        flow = " [bold cyan]→[/] ".join(p["steps"])
        c.print(
            f"  [{_SEVERITY_STYLE[p['severity']]}] {p['severity']} [/] {flow}\n"
            f"     [dim]dowód: {p['evidence']}[/]"
        )


def _render_action_plan(c: Console, dataset: Dataset, limit: int = 5) -> None:
    """Top działań do podjęcia — ta sama agregacja, co sekcja 'Plan działań' w summary."""
    plan = build_action_plan(dataset, limit=limit)
    if not plan:
        return
    table = Table(title=f"Plan działań (top {len(plan)})", show_edge=False)
    table.add_column("#", justify="right")
    table.add_column("Severity")
    table.add_column("Działanie")
    table.add_column("Moduł")
    table.add_column("Obiektów", justify="right")
    for i, step in enumerate(plan, start=1):
        table.add_row(
            str(i),
            f"[{_SEVERITY_STYLE[step['severity']]}]{step['severity']}[/]",
            step["title"],
            step["module"],
            str(step["count"]),
        )
    c.print(table)
    c.print("[dim]Pełna lista z rekomendacjami i linkami: raport summary.[/]")


def _render_module(c: Console, label: str, items: list, name) -> None:
    """Kompaktowe podsumowanie modułu (grupy/aplikacje): rozkład severity + najgorsze obiekty."""
    if not items:
        return
    sevs = Counter(i.severity for i in items)
    dist = "  ".join(
        f"[{_SEVERITY_STYLE[s]}]{s}:{sevs.get(s, 0)}[/]"
        for s in _SEVERITY_STYLE
        if sevs.get(s, 0)
    )
    c.print(f"\n[bold cyan]{label}[/] ({len(items)}): {dist or '[green]brak ryzyk[/]'}")
    flagged = [i for i in items if i.severity in ("critical", "high")]
    if not flagged:
        return
    table = Table(show_edge=False)
    table.add_column("Severity")
    table.add_column("Score", justify="right")
    table.add_column("Nazwa")
    table.add_column("Główne sygnały")
    for i in sorted(flagged, key=lambda x: -x.review_score):
        table.add_row(
            f"[{_SEVERITY_STYLE[i.severity]}]{i.severity}[/]",
            str(i.review_score),
            name(i),
            "; ".join(f.title for f in i.flags[:3]),
        )
    c.print(table)
