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
from .i18n import SUPPORTED_LANGS, Translator
from .ingest import DatasetError, load_dataset
from .models import Dataset
from .report import (
    export_apps_csv,
    export_csv,
    export_groups_csv,
    export_json,
    render_console,
    render_report_html,
)
from .rules import load_rubric
from .scoring import score_dataset

# Dostępne raporty (hybryda 1.2). 'summary' = zbiorczy exec; reszta = szczegóły per moduł.
ALL_REPORTS = ("summary", "users", "groups", "apps")

app = typer.Typer(add_completion=False, help="AccessGuy — processor (scoring + report).")
console = Console()

_LANG_OPT = typer.Option(
    "en", "--lang", "-l", help=f"Report/console language: {', '.join(SUPPORTED_LANGS)} (default en)."
)


def _safe_write(
    fn: Callable[[Path], Path],
    path: Path,
    label: str,
    t: Translator,
    written: list[Path] | None = None,
) -> None:
    """Zapis odporny na 'Permission denied' (Windows error 13).

    Najczęstsza przyczyna: docelowy raport jest właśnie otwarty w przeglądarce/podglądzie
    i system go blokuje. Zamiast wywalać cały build — zapisujemy pod alternatywną nazwą
    z sygnaturą czasu i jasno o tym informujemy.

    Ścieżki zapisane z powodzeniem dopisujemy do `written` — z tej listy launcher (PowerShell)
    buduje zaszyfrowane archiwum (patrz manifest w `_run_pipeline`).
    """
    try:
        out = fn(path)
        console.print(f"[green]{label}:[/] {out}")
        if written is not None:
            written.append(out)
    except PermissionError:
        ts = datetime.now().strftime("%H%M%S")
        alt = path.with_name(f"{path.stem}-{ts}{path.suffix}")
        console.print(
            f"[yellow]{t.t('cli.write.denied', label=label, name=path.name, alt=alt.name)}[/]"
        )
        try:
            out = fn(alt)
            console.print(f"[green]{label}:[/] {out}")
            if written is not None:
                written.append(out)
        except PermissionError:
            console.print(f"[red]{t.t('cli.write.denied_final', label=label)}[/]")


def _write_manifest(out_dir: Path, source_dataset: Path, outputs: list[Path]) -> None:
    """Zapisuje '.ag-manifest.json' — listę artefaktów + plik źródłowy dla kroku ochrony.

    To NIE jest krok niszczący ani kryptograficzny: tylko spis ścieżek. Krypto (7-Zip, AES-256)
    robi launcher PowerShell, dzięki czemu Python pozostaje opcjonalny (patrz Protect.ps1).
    """
    if not outputs:
        return
    manifest = {
        "sourceDataset": str(source_dataset.resolve()),
        "outputs": [str(p.resolve()) for p in outputs],
    }
    try:
        (out_dir / ".ag-manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
    except OSError:
        pass  # brak manifestu = brak auto-ochrony; nie wywalamy buildu


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
    lang: str = "en",
    reports: tuple[str, ...] = ALL_REPORTS,
    pdf: bool = False,
    csv_out: bool = True,
    json_out: bool = False,
    theatrics: bool = False,
) -> None:
    """Wspólny przepływ: ingest -> scoring -> konsola + eksporty. Używają go process i build."""
    t = Translator(lang)
    try:
        dataset = load_dataset(dataset_path)
    except DatasetError as exc:
        console.print(f"[bold red]{t.t('cli.error.dataset', exc=exc)}[/]")
        raise typer.Exit(code=2)

    rubric = load_rubric(lang=t.lang)
    if theatrics:
        # Hakerski przebieg „silnika raportu" — czysto wizualny, nie zmienia artefaktów.
        from .report.theatrics import run_build_sequence

        run_build_sequence(console, t, dataset)
    dataset = score_dataset(dataset, rubric, t)

    # Gdy gramy hakerski boot (theatrics), odsłaniamy też SAM raport stopniowo (~10 s) — żeby
    # tabele nie „dumpowały się" naraz. Bez theatrics (process/CI) wynik leci natychmiast.
    render_console(dataset, console, lang=t.lang, paced=theatrics)

    # Czytelne, spójne nazwy: <NazwaTenanta>_<data>_{summary,users,groups,apps}.{html,csv}.
    base = _output_base(dataset, dataset_path.stem or "accessguy")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        console.print(f"[red]{t.t('cli.outdir.denied', dir=out_dir)}[/]")
        raise typer.Exit(code=13)

    # Moduły bez danych pomijamy w trybie 'wszystko' (ale honorujemy jawny wybór) — dotyczy CSV.
    explicit = set(reports) != set(ALL_REPORTS)
    written: list[Path] = []

    # JEDEN interaktywny raport: widok summary + zakładki Konta/Grupy/Aplikacje (zastępuje dawne 4 pliki).
    _safe_write(lambda p: render_report_html(dataset, p, t.lang), out_dir / f"{base}.html", "HTML", t, written)

    if pdf:
        from .report.html import render_pdf

        try:
            _safe_write(lambda p: render_pdf(dataset, p, t.lang), out_dir / f"{base}.pdf", "PDF", t, written)
        except RuntimeError as exc:
            console.print(f"[yellow]PDF: {exc}[/]")

    if csv_out:
        if "users" in reports:
            _safe_write(lambda p: export_csv(dataset, p), out_dir / f"{base}_users.csv", "CSV/users", t, written)
        if "groups" in reports and (dataset.groups or explicit):
            _safe_write(lambda p: export_groups_csv(dataset, p), out_dir / f"{base}_groups.csv", "CSV/groups", t, written)
        if "apps" in reports and (dataset.applications or explicit):
            _safe_write(lambda p: export_apps_csv(dataset, p), out_dir / f"{base}_apps.csv", "CSV/apps", t, written)
    if json_out:
        _safe_write(lambda p: export_json(dataset, p), out_dir / f"{base}_scored.json", "JSON", t, written)

    # Manifest dla kroku ochrony (launcher PS spakuje te pliki + dataset do zaszyfrowanego archiwum).
    _write_manifest(out_dir, dataset_path, written)


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
        Path.cwd(), "--dir", "-d", help="Folder with scan artifacts (*.json)."
    ),
    out_dir: Path = typer.Option(Path("./accessguy-reports"), "--out", help="Output directory."),
    pdf: bool = typer.Option(False, help="Also generate PDF (requires extra [pdf])."),
    lang: str = _LANG_OPT,
    theatrics: bool = typer.Option(
        True, "--theatrics/--no-theatrics", help="Animated 'hacker' report-build sequence."
    ),
) -> None:
    """AccessGuy-Report-Builder — logo, skan folderu, wybór pliku, raport dla zarządu."""
    t = Translator(lang)
    console.print(f"[cyan]{branding.ACCESS_GUY_LOGO}[/]")
    console.print(branding.ACCESS_GUY_TEXT)
    console.print(f"  [dim]{t.t('branding.caption')}[/]\n")

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
        console.print(f"[yellow]{t.t('cli.build.none_found', dir=directory)}[/]")
        raise typer.Exit(code=1)

    console.print(f"[bold]{t.t('cli.build.found_header', n=len(found))}[/]")
    for i, (p, meta) in enumerate(found, start=1):
        console.print(
            f"  [cyan][{i}][/] {p.name}  "
            f"[dim]{t.t('cli.build.file_meta', tenant=meta['tenant'], scan=meta['generatedAt'], accounts=meta['accounts'])}[/]"
        )
    console.print(f"  [cyan][Q][/] {t.t('cli.build.quit')}")

    # Zawsze pytamy o wybór (nawet przy jednym pliku) — Daniel chce kontroli od początku.
    # Enter bez nic = [1] dla wygody.
    choice = typer.prompt(f"\n  {t.t('cli.build.prompt_file')}", default="1").strip()
    if choice.lower() == "q":
        raise typer.Exit(code=0)
    try:
        idx = int(choice)
        if idx < 1:
            raise IndexError
        selected = found[idx - 1][0]
    except (ValueError, IndexError):
        console.print(f"[red]{t.t('cli.build.invalid_choice')}[/]")
        raise typer.Exit(code=1)

    # Jeden interaktywny raport (summary + zakładki Konta/Grupy/Aplikacje) — bez wyboru typu.
    console.print(f"\n[green]{t.t('cli.build.building', path=selected)}[/]\n")
    _run_pipeline(selected, out_dir, lang=t.lang, reports=ALL_REPORTS, pdf=pdf, theatrics=theatrics)


@app.command()
def process(
    dataset_path: Path = typer.Argument(..., help="Path to dataset.json from the scanner."),
    out_dir: Path = typer.Option(Path("./accessguy-reports"), "--out", help="Output directory."),
    reports: str = typer.Option(
        "all",
        "--reports",
        help="Which reports: 'all' or a comma-separated list of {summary,users,groups,apps}.",
    ),
    pdf: bool = typer.Option(False, help="Generate PDF (requires extra [pdf])."),
    csv_out: bool = typer.Option(True, "--csv/--no-csv", help="Export CSV."),
    json_out: bool = typer.Option(False, "--json/--no-json", help="Export scored JSON."),
    lang: str = _LANG_OPT,
    theatrics: bool = typer.Option(False, "--theatrics/--no-theatrics", help="Animated 'hacker' sequence."),
) -> None:
    t = Translator(lang)
    selected: tuple[str, ...]
    if reports.strip().lower() in ("all", ""):
        selected = ALL_REPORTS
    else:
        selected = tuple(r.strip() for r in reports.split(",") if r.strip() in ALL_REPORTS)
        if not selected:
            console.print(f"[red]{t.t('cli.process.unknown_reports', reports=reports, allowed=', '.join(ALL_REPORTS))}[/]")
            raise typer.Exit(code=2)
    _run_pipeline(
        dataset_path, out_dir, lang=t.lang, reports=selected, pdf=pdf,
        csv_out=csv_out, json_out=json_out, theatrics=theatrics,
    )


@app.command()
def validate(
    dataset_path: Path = typer.Argument(..., help="Path to dataset.json."),
    lang: str = _LANG_OPT,
) -> None:
    t = Translator(lang)
    try:
        ds = load_dataset(dataset_path)
    except DatasetError as exc:
        console.print(f"[bold red]{t.t('cli.validate.invalid', exc=exc)}[/]")
        raise typer.Exit(code=1)
    console.print(
        "[green]OK[/] — "
        + t.t(
            "cli.validate.ok",
            accounts=len(ds.accounts),
            groups=len(ds.groups),
            apps=len(ds.applications),
            schema=ds.schema_version,
        )
    )


if __name__ == "__main__":
    app()
