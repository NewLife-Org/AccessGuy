"""CLI procesora AccessGuy.

Komendy:
  build     — interaktywny tryb "AccessGuy-Report-Builder": logo + wybór pliku z folderu -> raport
  process   — wczytaj dataset.json -> scoring -> raporty (console/html/csv/json[/pdf])
  validate  — tylko walidacja datasetu względem schematu (CI / sanity-check)
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Callable

import typer
from rich.console import Console

from . import branding
from .ingest import DatasetError, load_dataset
from .models import Dataset
from .report import (
    export_apps_csv,
    export_csv,
    export_groups_csv,
    export_json,
    render_apps_html,
    render_console,
    render_groups_html,
    render_summary_html,
    render_users_html,
)
from .rules import load_rubric
from .scoring import score_dataset

# Dostępne raporty (hybryda 1.2). 'summary' = zbiorczy exec; reszta = szczegóły per moduł.
ALL_REPORTS = ("summary", "users", "groups", "apps")

app = typer.Typer(add_completion=False, help="AccessGuy — procesor (scoring + raport).")
console = Console()


def _safe_write(fn: Callable[[Path], Path], path: Path, label: str) -> None:
    """Zapis odporny na 'Permission denied' (Windows error 13).

    Najczęstsza przyczyna: docelowy raport jest właśnie otwarty w przeglądarce/podglądzie
    i system go blokuje. Zamiast wywalać cały build — zapisujemy pod alternatywną nazwą
    z sygnaturą czasu i jasno o tym informujemy.
    """
    try:
        out = fn(path)
        console.print(f"[green]{label}:[/] {out}")
    except PermissionError:
        ts = datetime.now().strftime("%H%M%S")
        alt = path.with_name(f"{path.stem}-{ts}{path.suffix}")
        console.print(
            f"[yellow]{label}: brak dostępu do {path.name} "
            f"(plik otwarty/zablokowany?). Zapisuję jako {alt.name}.[/]"
        )
        try:
            out = fn(alt)
            console.print(f"[green]{label}:[/] {out}")
        except PermissionError:
            console.print(
                f"[red]{label}: nadal brak dostępu — zamknij otwarte raporty "
                f"albo wskaż inny --out.[/]"
            )


def _output_base(dataset: Dataset, fallback: str) -> str:
    """Czytelny przedrostek nazw plików: '<NazwaTenanta>_<RRRR-MM-DD>'.

    Bierzemy PEŁNĄ nazwę tenanta z datasetu (nie 8-znakowy skrót), sanitujemy do bezpiecznych
    znaków, datę bierzemy z generatedAt (deterministycznie). Stąd 'Contoso_2026-06-11_users.html'
    zamiast 'Contoso_20260611-104925-users-report.html'.
    """
    name = (dataset.tenant.display_name or dataset.tenant.id or "").strip()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:40]
    if not slug:
        return fallback
    return f"{slug}_{dataset.generated_at:%Y-%m-%d}"


def _run_pipeline(
    dataset_path: Path,
    out_dir: Path,
    *,
    reports: tuple[str, ...] = ALL_REPORTS,
    pdf: bool = False,
    csv_out: bool = True,
    json_out: bool = False,
) -> None:
    """Wspólny przepływ: ingest -> scoring -> konsola + eksporty. Używają go process i build."""
    try:
        dataset = load_dataset(dataset_path)
    except DatasetError as exc:
        console.print(f"[bold red]Błąd datasetu:[/] {exc}")
        raise typer.Exit(code=2)

    rubric = load_rubric()
    dataset = score_dataset(dataset, rubric)

    render_console(dataset, console)

    # Czytelne, spójne nazwy: <NazwaTenanta>_<data>_{summary,users,groups,apps}.{html,csv}.
    base = _output_base(dataset, dataset_path.stem or "accessguy")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        console.print(f"[red]Brak dostępu do katalogu wyjściowego:[/] {out_dir}")
        raise typer.Exit(code=13)

    # Moduły bez danych pomijamy w trybie 'wszystko' (ale honorujemy jawny wybór).
    explicit = set(reports) != set(ALL_REPORTS)

    if "summary" in reports:
        _safe_write(lambda p: render_summary_html(dataset, p), out_dir / f"{base}_summary.html", "HTML/summary")
    if "users" in reports:
        _safe_write(lambda p: render_users_html(dataset, p), out_dir / f"{base}_users.html", "HTML/users")
    if "groups" in reports and (dataset.groups or explicit):
        _safe_write(lambda p: render_groups_html(dataset, p), out_dir / f"{base}_groups.html", "HTML/groups")
    if "apps" in reports and (dataset.applications or explicit):
        _safe_write(lambda p: render_apps_html(dataset, p), out_dir / f"{base}_apps.html", "HTML/apps")

    if pdf:
        from .report.html import render_pdf

        try:
            _safe_write(lambda p: render_pdf(dataset, p), out_dir / f"{base}_users.pdf", "PDF")
        except RuntimeError as exc:
            console.print(f"[yellow]PDF pominięty:[/] {exc}")

    if csv_out:
        if "users" in reports:
            _safe_write(lambda p: export_csv(dataset, p), out_dir / f"{base}_users.csv", "CSV/users")
        if "groups" in reports and (dataset.groups or explicit):
            _safe_write(lambda p: export_groups_csv(dataset, p), out_dir / f"{base}_groups.csv", "CSV/groups")
        if "apps" in reports and (dataset.applications or explicit):
            _safe_write(lambda p: export_apps_csv(dataset, p), out_dir / f"{base}_apps.csv", "CSV/apps")
    if json_out:
        _safe_write(lambda p: export_json(dataset, p), out_dir / f"{base}_scored.json", "JSON")


def _peek_dataset(path: Path) -> dict | None:
    """Tani podgląd: czy to plik datasetu AccessGuy? Zwraca {tenant, generatedAt, accounts} albo None."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None
    if not isinstance(raw, dict) or "schemaVersion" not in raw or "accounts" not in raw:
        return None
    tenant = raw.get("tenant") or {}
    return {
        "tenant": tenant.get("displayName") or tenant.get("id") or "?",
        "generatedAt": raw.get("generatedAt", "?"),
        "accounts": len(raw.get("accounts") or []),
    }


@app.command()
def build(
    directory: Path = typer.Option(
        Path.cwd(), "--dir", "-d", help="Folder z artefaktami skanu (*.json)."
    ),
    out_dir: Path = typer.Option(Path("./accessguy-reports"), "--out", help="Katalog wyjściowy."),
    pdf: bool = typer.Option(False, help="Generuj też PDF (wymaga extra [pdf])."),
) -> None:
    """AccessGuy-Report-Builder — logo, skan folderu, wybór pliku, raport dla zarządu."""
    console.print(f"[cyan]{branding.ACCESS_GUY_LOGO}[/]")
    console.print(branding.ACCESS_GUY_TEXT)
    console.print(f"  [dim]{branding.CAPTION}[/]\n")

    # Skanujemy wskazany folder (i typowe podkatalogi) w poszukiwaniu datasetów.
    search_dirs = [directory, directory / "out", directory / "scanner" / "out"]
    found: list[tuple[Path, dict]] = []
    seen: set[Path] = set()
    for d in search_dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.json")):
            rp = p.resolve()
            if rp in seen:
                continue
            meta = _peek_dataset(p)
            if meta:
                seen.add(rp)
                found.append((p, meta))

    if not found:
        console.print(
            f"[yellow]Nie znalazłem żadnego datasetu (*.json) w:[/] {directory}\n"
            "Uruchom najpierw skaner (tryb [1]) albo wskaż folder: "
            "[white]build --dir <ścieżka>[/]"
        )
        raise typer.Exit(code=1)

    console.print(f"[bold]Znaleziono {len(found)} plik(ów). Wybierz, z którego zrobić raport:[/]")
    for i, (p, meta) in enumerate(found, start=1):
        console.print(
            f"  [cyan][{i}][/] {p.name}  "
            f"[dim]· tenant: {meta['tenant']} · skan: {meta['generatedAt']} "
            f"· kont: {meta['accounts']}[/]"
        )
    console.print("  [cyan][Q][/] wyjście")

    # Zawsze pytamy o wybór (nawet przy jednym pliku) — Daniel chce kontroli od początku.
    # Enter bez nic = [1] dla wygody.
    choice = typer.prompt("\n  Wybierz numer pliku", default="1").strip()
    if choice.lower() == "q":
        raise typer.Exit(code=0)
    try:
        idx = int(choice)
        if idx < 1:
            raise IndexError
        selected = found[idx - 1][0]
    except (ValueError, IndexError):
        console.print("[red]Nieprawidłowy wybór.[/]")
        raise typer.Exit(code=1)

    # Wybór raportu (hybryda): zbiorczy + osobne per moduł. Enter = wszystko.
    console.print("\n[bold]Który raport zbudować?[/]")
    console.print("  [cyan][1][/] Wszystko (summary + konta + grupy + aplikacje) [dim]— domyślne[/]")
    console.print("  [cyan][2][/] Tylko streszczenie (summary)")
    console.print("  [cyan][3][/] Tylko konta")
    console.print("  [cyan][4][/] Tylko grupy")
    console.print("  [cyan][5][/] Tylko aplikacje")
    rep_choice = typer.prompt("\n  Wybierz", default="1").strip()
    reports = {
        "1": ALL_REPORTS,
        "2": ("summary",),
        "3": ("users",),
        "4": ("groups",),
        "5": ("apps",),
    }.get(rep_choice, ALL_REPORTS)

    console.print(f"\n[green]Buduję raport z:[/] {selected}\n")
    _run_pipeline(selected, out_dir, reports=reports, pdf=pdf)


@app.command()
def process(
    dataset_path: Path = typer.Argument(..., help="Ścieżka do dataset.json ze skanera."),
    out_dir: Path = typer.Option(Path("./accessguy-reports"), "--out", help="Katalog wyjściowy."),
    reports: str = typer.Option(
        "all",
        "--reports",
        help="Które raporty: 'all' albo lista po przecinku z {summary,users,groups,apps}.",
    ),
    pdf: bool = typer.Option(False, help="Generuj PDF (wymaga extra [pdf])."),
    csv_out: bool = typer.Option(True, "--csv/--no-csv", help="Eksport CSV."),
    json_out: bool = typer.Option(False, "--json/--no-json", help="Eksport JSON po scoringu."),
) -> None:
    selected: tuple[str, ...]
    if reports.strip().lower() in ("all", ""):
        selected = ALL_REPORTS
    else:
        selected = tuple(r.strip() for r in reports.split(",") if r.strip() in ALL_REPORTS)
        if not selected:
            console.print(f"[red]Nieznane raporty:[/] {reports}. Dozwolone: {', '.join(ALL_REPORTS)} albo 'all'.")
            raise typer.Exit(code=2)
    _run_pipeline(
        dataset_path, out_dir, reports=selected, pdf=pdf, csv_out=csv_out, json_out=json_out
    )


@app.command()
def validate(dataset_path: Path = typer.Argument(..., help="Ścieżka do dataset.json.")) -> None:
    try:
        ds = load_dataset(dataset_path)
    except DatasetError as exc:
        console.print(f"[bold red]NIEZGODNY:[/] {exc}")
        raise typer.Exit(code=1)
    console.print(
        f"[green]OK[/] — {len(ds.accounts)} kont, {len(ds.groups)} grup, "
        f"{len(ds.applications)} aplikacji, schema {ds.schema_version}."
    )


if __name__ == "__main__":
    app()
