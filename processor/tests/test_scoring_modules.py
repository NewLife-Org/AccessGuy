from __future__ import annotations

from accessguy_processor.ingest import load_dataset
from accessguy_processor.report.community import (
    build_apps_view,
    build_groups_view,
    build_overview,
    build_community,
)
from accessguy_processor.report.html import (
    render_apps_html,
    render_groups_html,
    render_report_html,
    render_summary_html,
)
from accessguy_processor.rules import load_rubric
from accessguy_processor.scoring import score_dataset


def _scored(path):
    return score_dataset(load_dataset(path), load_rubric())


def _group(ds, name):
    return next(g for g in ds.groups if g.display_name == name)


def _app(ds, name):
    return next(a for a in ds.applications if a.display_name == name)


def test_role_assignable_priv_group_is_critical(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    g = _group(ds, "Helpdesk Operators")
    codes = {f.code for f in g.flags}
    assert "GROUP_ROLE_ASSIGNABLE_PRIV" in codes
    assert "GROUP_GUESTS_WITH_ACCESS" in codes  # 1 gość + nadaje rolę
    assert g.severity == "critical"


def test_dynamic_public_ownerless_group(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    g = _group(ds, "All Company")
    codes = {f.code for f in g.flags}
    assert "GROUP_DYNAMIC_MEMBERSHIP" in codes
    assert "GROUP_PUBLIC_M365" in codes
    assert "GROUP_OWNERLESS" in codes


def test_license_group_without_members(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    g = _group(ds, "E5 License Group")
    codes = {f.code for f in g.flags}
    assert "GROUP_LICENSE_NO_MEMBERS" in codes
    # ma licencje -> NIE jest traktowana jako pusta-do-usunięcia
    assert "GROUP_EMPTY" not in codes


def test_clean_group_has_no_flags(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    g = _group(ds, "Marketing Team")
    assert g.review_score == 0
    assert g.severity == "info"


def test_high_risk_app_is_critical(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    a = _app(ds, "Backup Service")
    codes = {f.code for f in a.flags}
    assert "APP_HIGH_RISK_PERM" in codes
    assert "APP_ORPHANED" in codes              # porzucona: brak ownera + userów + żywy sekret
    assert "APP_NO_OWNER" not in codes          # #2: APP_ORPHANED przejmuje — brak podwójnego punktu
    assert "APP_SECRET_OVER_CERT" in codes      # #5a: uprzywilejowana, aktywny sekret, brak certu
    assert "APP_SECRET_EXPIRED" in codes
    assert "APP_UNVERIFIED_PRIVILEGED" in codes
    assert a.severity == "critical"


def test_app_broad_read_and_expiring(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    a = _app(ds, "Reporting Connector")
    codes = {f.code for f in a.flags}
    assert "APP_BROAD_READ" in codes
    assert "APP_SECRET_EXPIRING" in codes
    assert "APP_MULTI_TENANT" in codes
    # broad read NIE jest klasyfikowany jako high-risk perm
    assert "APP_HIGH_RISK_PERM" not in codes


def test_app_long_lived_secret(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    a = _app(ds, "Legacy Sync")
    codes = {f.code for f in a.flags}
    assert "APP_LONG_LIVED_SECRET" in codes
    assert "APP_SECRET_OVER_CERT" not in codes  # #5a: brak uprawnień app-only high-risk → mniej szumu


def test_views_and_overview_build(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    gv = build_groups_view(ds)
    av = build_apps_view(ds)
    ov = build_overview(ds, build_community(ds), gv, av)

    assert gv["priv_group_count"] >= 1
    assert av["high_risk_count"] >= 1
    assert ov["escalation_paths"] >= 2
    assert ov["grade"] in ("A", "B", "C", "D", "F")
    assert ov["insights"]  # są spostrzeżenia


def test_new_group_rules(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    hd = _group(ds, "Helpdesk Operators")
    assert "GROUP_LARGE_PRIVILEGED" in {f.code for f in hd.flags}  # 25 członków + rola
    allc = _group(ds, "All Company")
    codes = {f.code for f in allc.flags}
    assert "GROUP_DYNAMIC_PRIVILEGED" in codes  # dynamiczna + licencja
    assert "GROUP_NESTED" in codes  # zawiera Marketing Team


def test_new_app_rules(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    assert "APP_ORPHANED" in {f.code for f in _app(ds, "Backup Service").flags}
    assert "APP_CREDENTIAL_SPRAWL" in {f.code for f in _app(ds, "Legacy Sync").flags}


def test_app_assigned_group_expands_members(sample_dataset_path, tmp_path):
    ds = _scored(sample_dataset_path)
    html = render_apps_html(ds, tmp_path / "a.html").read_text(encoding="utf-8")
    # Reporting Connector ma przypisaną grupę Helpdesk Operators -> w raporcie widać jej członków
    # (raport domyślnie po angielsku)
    assert "Groups assigned to the application" in html
    assert "Helpdesk Operators" in html
    assert "anna.nowak@contoso.pl" in html  # konkretny członek przypisanej grupy


def test_group_members_and_app_users_parsed(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    g = _group(ds, "Helpdesk Operators")
    assert len(g.members) == 3
    assert any(m.user_principal_name == "jan.kowalski@contoso.pl" for m in g.members)

    a = _app(ds, "Reporting Connector")
    vias = {u.via for u in a.assigned_users}
    assert "consent" in vias and "assignment" in vias


def test_active_inactive_counts(sample_dataset_path):
    ds = _scored(sample_dataset_path)
    c = build_community(ds)
    assert c["active_count"] == 3
    assert c["inactive_count"] == 0
    assert c["active_count"] + c["inactive_count"] == c["account_total"]


def test_html_renders_for_all_modules(sample_dataset_path, tmp_path):
    ds = _scored(sample_dataset_path)
    g = render_groups_html(ds, tmp_path / "g.html")
    a = render_apps_html(ds, tmp_path / "a.html")
    s = render_summary_html(ds, tmp_path / "Contoso_2026-06-01_summary.html")
    groups_html = g.read_text(encoding="utf-8")
    assert "Helpdesk Operators" in groups_html
    assert "Members" in groups_html  # rozwijana lista członków (EN domyślnie)
    assert "anna.nowak@contoso.pl" in groups_html  # konkretna osoba w grupie
    apps_html = a.read_text(encoding="utf-8")
    assert "Backup Service" in apps_html
    assert "Linked users" in apps_html
    summary = s.read_text(encoding="utf-8")
    assert "overall posture" in summary  # EN domyślnie
    assert "Contoso_2026-06-01_groups.html" in summary  # link do raportu szczegółowego
    assert "sevbar" in summary  # pasek rozkładu severity


def test_combined_report_has_summary_and_tabs(sample_dataset_path, tmp_path):
    ds = _scored(sample_dataset_path)
    html = render_report_html(ds, tmp_path / "Contoso_2026-06-01.html").read_text(encoding="utf-8")
    # 4 zakładki jak arkusze Excela (Konta/Grupy/Aplikacje/Conditional Access).
    assert 'data-tabpanel="users"' in html
    assert 'data-tabpanel="groups"' in html
    assert 'data-tabpanel="apps"' in html
    assert 'data-tabpanel="ca"' in html  # nowa zakładka Conditional Access
    assert 'data-tab="ca"' in html
    # Ocena postawy tenanta na górze, strefa summary na samym dole.
    assert "overall posture" in html
    assert 'class="ag-summaryzone"' in html
    grade = html.index('class="ag-exec"')
    tabs = html.index('class="ag-tabs"')
    zone = html.index('class="ag-summaryzone"')
    assert grade < tabs < zone  # ocena -> zakładki -> summary (dół)
    # Dane wszystkich modułów + CA w jednym pliku.
    assert "Helpdesk Operators" in html
    assert "Backup Service" in html
    assert "anna.nowak@contoso.pl" in html
    assert "_groups.html" not in html  # głębokie linki in-page, bez osobnych plików
    assert "sevbar" in html
    # Interaktywne kafelki (klik = filtr) + facety na kartach.
    assert "ag-card-btn" in html
    assert 'data-filter-sev="critical"' in html
    assert "data-facet=" in html
    # Zakładka CA: rozwijane karty polityk (kto podlega / co robią) + interaktywne kafelki.
    assert "ca-pol" in html
    assert "data-cafilter" in html
    # Ocena postawy obok logo w nagłówku (split header).
    assert "ag-header-split" in html