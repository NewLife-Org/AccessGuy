"""Charakterystyka tenanta jako wspólnoty — liczone po stronie procesora z datasetu.

Wszystko pochodzi z danych, które skaner już zebrał (konta, role, licencje) — bez dodatkowych
uprawnień. 'Subskrypcje' = licencje M365 (Graph /subscribedSkus), nie Azure ARM.
"""

from __future__ import annotations

from ..i18n import Translator
from ..models import Account, Dataset
from ..scoring.correlation import CorrelationIndex, account_weaknesses, priv_role_names

# Ładne nazwy dla najczęstszych SKU (partNumber -> nazwa handlowa). Best-effort; brak = partNumber.
_SKU_FRIENDLY: dict[str, str] = {
    "SPE_E5": "Microsoft 365 E5",
    "SPE_E3": "Microsoft 365 E3",
    "ENTERPRISEPACK": "Office 365 E3",
    "ENTERPRISEPREMIUM": "Office 365 E5",
    "SPB": "Microsoft 365 Business Premium",
    "O365_BUSINESS_PREMIUM": "Microsoft 365 Business Standard",
    "EMS": "Enterprise Mobility + Security E3",
    "EMSPREMIUM": "Enterprise Mobility + Security E5",
    "AAD_PREMIUM": "Entra ID P1",
    "AAD_PREMIUM_P2": "Entra ID P2",
    "FLOW_FREE": "Power Automate Free",
    "POWER_BI_STANDARD": "Power BI (free)",
    "DEVELOPERPACK_E5": "Microsoft 365 E5 (developer)",
}


def friendly_sku(part_number: str) -> str:
    return _SKU_FRIENDLY.get(part_number, part_number)


# Znane wartości clientAppUsed (językowo-neutralne klucze). Opis każdego siedzi w katalogu
# i18n pod kluczem "legacy.<clientAppUsed>" — pomaga ocenić, czy protokół jest świadomie
# akceptowany (np. SMTP do drukarek), czy to relikt do wyłączenia.
_LEGACY_CLIENTS: frozenset[str] = frozenset({
    "Authenticated SMTP",
    "Exchange ActiveSync",
    "Exchange Web Services",
    "Exchange Online PowerShell",
    "IMAP4",
    "POP3",
    "MAPI Over HTTP",
    "Offline Address Book",
    "Outlook Anywhere (RPC over HTTP)",
    "Outlook Service",
    "Reporting Web Services",
    "Other clients",
    "AutoDiscover",
})


def legacy_client_info(client_app: str, t: Translator | None = None) -> str:
    tr = t or Translator()
    if client_app in _LEGACY_CLIENTS:
        return tr.t(f"legacy.{client_app}")
    return tr.t("legacy.fallback")


def build_community(dataset: Dataset, t: Translator | None = None, recent_limit: int = 10) -> dict:
    tr = t or Translator()
    accounts = dataset.accounts

    # Liczba Global Adminów — konta posiadające rolę "Global Administrator".
    global_admins = [
        a
        for a in accounts
        if any(r.role_name == "Global Administrator" for r in a.roles)
    ]

    # 10 ostatnio założonych kont (po createdDateTime malejąco).
    recent = sorted(accounts, key=lambda a: a.created_date_time, reverse=True)[:recent_limit]

    # Konta bez MFA — same maile (fallback do UPN, gdy brak mail).
    no_mfa = [
        (a.mail or a.user_principal_name)
        for a in accounts
        if a.mfa_registered is False
    ]

    skus = [
        {
            "name": friendly_sku(s.sku_part_number),
            "part": s.sku_part_number,
            "consumed": s.consumed_units,
            "prepaid": s.prepaid_units,
        }
        for s in dataset.subscribed_skus
    ]

    # Pokrycie MFA — liczymy tylko konta, dla których znamy status (nie None).
    mfa_known = [a for a in accounts if a.mfa_registered is not None]
    mfa_yes = [a for a in mfa_known if a.mfa_registered is True]
    mfa_coverage = round(100 * len(mfa_yes) / len(mfa_known)) if mfa_known else None

    privileged = [a for a in accounts if a.has_privileged_role]
    priv_no_mfa = [a for a in privileged if a.mfa_registered is False]
    legacy_accounts = [a for a in accounts if a.activity and a.activity.legacy_auth_count > 0]
    legacy_success_accounts = [a for a in accounts if a.activity and a.activity.legacy_success_count > 0]
    risky_accounts = [a for a in accounts if a.activity and a.activity.risky_sign_in_count > 0]

    # Rozkład legacy auth per protokół (cały tenant) — to jest "fajniejszy output" do weryfikacji:
    # ile prób i ile UDANYCH każdym protokołem + na ilu kontach. Udane = realne ominięcie MFA.
    _legacy: dict[str, dict] = {}
    for a in accounts:
        if not a.activity:
            continue
        for c in a.activity.legacy_auth_clients:
            agg = _legacy.setdefault(
                c.client_app, {"client": c.client_app, "count": 0, "success": 0, "accounts": 0}
            )
            agg["count"] += c.count
            agg["success"] += c.success_count
            agg["accounts"] += 1
    legacy_breakdown = sorted(_legacy.values(), key=lambda d: (-d["success"], -d["count"]))
    for d in legacy_breakdown:
        d["info"] = legacy_client_info(d["client"], tr)

    # Streszczenie dla zarządu — najgorsze konta (po score, jeśli już policzony).
    worst_accounts = sorted(accounts, key=lambda a: -a.review_score)[:5]
    top_findings = [
        {
            "id": a.id,
            "upn": a.user_principal_name,
            "severity": a.severity,
            "score": a.review_score,
            "headline": (a.flags[0].title if a.flags else "—"),
        }
        for a in worst_accounts
        if a.review_score > 0
    ]

    sev_counts = {
        s: sum(1 for a in accounts if a.severity == s)
        for s in ("critical", "high", "medium", "low", "info")
    }
    # Do oceny liczy się legacy, które SIĘ POWIODŁO (realne ominięcie MFA), nie same próby.
    grade, grade_note = _posture_grade(
        sev_counts, len(priv_no_mfa), len(legacy_success_accounts), mfa_coverage, tr
    )

    return {
        "subscribed_skus": skus,
        "license_total": sum(s.consumed_units for s in dataset.subscribed_skus),
        "global_admin_count": len(global_admins),
        "global_admins": [a.user_principal_name for a in global_admins],
        "recent_accounts": [
            {"upn": a.user_principal_name, "created": a.created_date_time}
            for a in recent
        ],
        "no_mfa_emails": no_mfa,
        "no_mfa_count": len(no_mfa),
        "account_total": len(accounts),
        "active_count": sum(1 for a in accounts if a.account_enabled),
        "inactive_count": sum(1 for a in accounts if not a.account_enabled),
        "guest_count": sum(1 for a in accounts if a.category == "guest"),
        "mfa_coverage": mfa_coverage,
        "privileged_count": len(privileged),
        "priv_no_mfa_count": len(priv_no_mfa),
        "legacy_auth_count": len(legacy_accounts),
        "legacy_success_count": len(legacy_success_accounts),
        "legacy_breakdown": legacy_breakdown,
        "risky_count": len(risky_accounts),
        "top_findings": top_findings,
        "sev_counts": sev_counts,
        "grade": grade,
        "grade_note": grade_note,
    }


def _posture_grade(
    sev: dict[str, int], priv_no_mfa: int, legacy: int, mfa_coverage: int | None,
    t: Translator | None = None,
) -> tuple[str, str]:
    """Prosta, czytelna ocena postawy tenanta A–F (dla zarządu). Heurystyka, nie norma."""
    score = 100
    score -= sev["critical"] * 15
    score -= sev["high"] * 7
    score -= priv_no_mfa * 10
    if legacy > 0:
        score -= 15
    if mfa_coverage is not None and mfa_coverage < 90:
        score -= (90 - mfa_coverage) // 2
    return _grade_from_score(score, t)


def _grade_from_score(score: int, t: Translator | None = None) -> tuple[str, str]:
    tr = t or Translator()
    score = max(0, min(100, score))
    if score >= 90:
        return "A", tr.t("community.grade.A")
    if score >= 75:
        return "B", tr.t("community.grade.B")
    if score >= 60:
        return "C", tr.t("community.grade.C")
    if score >= 40:
        return "D", tr.t("community.grade.D")
    return "F", tr.t("community.grade.F")


def _sev_counts(items) -> dict[str, int]:
    return {
        s: sum(1 for it in items if it.severity == s)
        for s in ("critical", "high", "medium", "low", "info")
    }


def _grade_from_sev(
    sev: dict[str, int], extra_penalty: int = 0, t: Translator | None = None
) -> tuple[str, str]:
    """Ocena A–F wyłącznie z rozkładu severity (+ ewentualna kara dodatkowa)."""
    score = 100 - 15 * sev["critical"] - 7 * sev["high"] - 4 * sev["medium"] - 1 * sev["low"]
    return _grade_from_score(score - extra_penalty, t)


def _top_findings(items, key=lambda x: x.user_principal_name, limit: int = 6) -> list[dict]:
    worst = sorted(items, key=lambda x: -x.review_score)[:limit]
    return [
        {
            "id": x.id,
            "name": key(x),
            "severity": x.severity,
            "score": x.review_score,
            "headline": (x.flags[0].title if x.flags else "—"),
        }
        for x in worst
        if x.review_score > 0
    ]


def build_groups_view(dataset: Dataset, t: Translator | None = None) -> dict:
    """Charakterystyka warstwy GRUP — agregaty i spostrzeżenia. Wszystko z datasetu."""
    groups = dataset.groups
    sev = _sev_counts(groups)

    role_assignable = [g for g in groups if g.is_assignable_to_role]
    priv_groups = [g for g in groups if g.has_privileged_role]
    ownerless = [g for g in groups if not g.on_premises_sync_enabled and (g.owner_count or len(g.owners)) == 0]
    dynamic = [g for g in groups if g.membership_type == "dynamic"]
    public_m365 = [g for g in groups if g.group_kind == "microsoft365" and g.visibility == "Public"]
    guest_groups = [g for g in groups if (g.guest_count or 0) > 0 and g.grants_access]
    license_groups = [g for g in groups if g.assigned_licenses]

    # Promień rażenia licencjonowania grupowego: ilu użytkowników dostaje licencje przez grupy.
    license_blast = sum((g.member_count or 0) for g in license_groups)

    # Rozkład rodzajów grup (insight: ile M365 vs security vs distribution).
    kind_dist: dict[str, int] = {}
    for g in groups:
        kind_dist[g.group_kind] = kind_dist.get(g.group_kind, 0) + 1

    # Które role są najczęściej nadawane przez grupy (wektor eskalacji na widoku).
    role_freq: dict[str, int] = {}
    for g in groups:
        for r in g.assigned_roles:
            role_freq[r.role_name] = role_freq.get(r.role_name, 0) + 1
    roles_via_groups = sorted(role_freq.items(), key=lambda kv: -kv[1])

    grade, note = _grade_from_sev(sev, extra_penalty=10 * len(priv_groups), t=t)

    return {
        "group_total": len(groups),
        "sev_counts": sev,
        "role_assignable_count": len(role_assignable),
        "priv_group_count": len(priv_groups),
        "ownerless_count": len(ownerless),
        "dynamic_count": len(dynamic),
        "public_m365_count": len(public_m365),
        "guest_group_count": len(guest_groups),
        "license_group_count": len(license_groups),
        "license_blast": license_blast,
        "kind_dist": kind_dist,
        "roles_via_groups": roles_via_groups,
        "priv_groups": [
            {
                "name": g.display_name,
                "roles": ", ".join(r.role_name for r in g.assigned_roles if r.is_privileged),
                "members": g.member_count,
            }
            for g in sorted(priv_groups, key=lambda g: -g.review_score)
        ],
        "top_findings": _top_findings(groups, key=lambda g: g.display_name),
        "grade": grade,
        "grade_note": note,
    }


def build_apps_view(dataset: Dataset, t: Translator | None = None) -> dict:
    """Charakterystyka warstwy APLIKACJI — poświadczenia, uprawnienia, własność."""
    apps = dataset.applications
    sev = _sev_counts(apps)

    high_risk_apps = [a for a in apps if a.high_risk_app_permissions]
    expired = [a for a in apps if any(c.expired for c in a.credentials)]
    expiring = [
        a
        for a in apps
        if any(not c.expired and c.days_to_expiry is not None and 0 <= c.days_to_expiry <= 30 for c in a.credentials)
    ]
    no_owner = [a for a in apps if not a.owners]
    multi_tenant = [a for a in apps if a.is_multi_tenant]

    secret_total = sum(len(a.secrets) for a in apps)
    cert_total = sum(1 for a in apps for c in a.credentials if c.kind == "certificate")

    # Najczęstsze uprzywilejowane uprawnienia aplikacyjne w tenancie (insight: gdzie ryzyko skupia się).
    perm_freq: dict[str, int] = {}
    for a in apps:
        for p in a.high_risk_app_permissions:
            perm_freq[p.permission] = perm_freq.get(p.permission, 0) + 1
    top_permissions = sorted(perm_freq.items(), key=lambda kv: -kv[1])

    grade, note = _grade_from_sev(sev, extra_penalty=10 * len(high_risk_apps), t=t)

    return {
        "app_total": len(apps),
        "sev_counts": sev,
        "high_risk_count": len(high_risk_apps),
        "expired_count": len(expired),
        "expiring_count": len(expiring),
        "no_owner_count": len(no_owner),
        "multi_tenant_count": len(multi_tenant),
        "secret_total": secret_total,
        "cert_total": cert_total,
        "top_permissions": top_permissions,
        "high_risk_apps": [
            {
                "name": a.display_name,
                "perms": ", ".join(sorted({p.permission for p in a.high_risk_app_permissions})),
            }
            for a in sorted(high_risk_apps, key=lambda a: -a.review_score)
        ],
        "top_findings": _top_findings(apps, key=lambda a: a.display_name),
        "grade": grade,
        "grade_note": note,
    }


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_posture(dataset: Dataset, t: Translator | None = None) -> dict | None:
    """Postawa konfiguracyjna tenanta (1.3): Conditional Access + polityki tenanta.

    To odpowiedź na 'DLACZEGO findings per-obiekt w ogóle występują': udane legacy auth
    bierze się z braku polityki blokującej, illicit consent z otwartej polityki zgód itd.
    Zwraca None, gdy skan nie zbierał caPolicies/tenantPolicies (stare datasety 1.x).
    """
    tr = t or Translator()
    collected = set(dataset.scan_context.collectors_run)
    if "caPolicies" not in collected and "tenantPolicies" not in collected:
        return None

    ca = dataset.ca_policies
    tp = dataset.tenant_policies
    enabled = [p for p in ca if p.enabled]
    report_only = [p for p in ca if p.report_only]
    mfa_policies = [p for p in enabled if p.requires_mfa]
    broad_mfa = [p for p in mfa_policies if p.is_broad]
    legacy_block = [p for p in enabled if p.blocks_legacy_auth]

    # Konta z flagą wykluczenia z MFA / nieobsłużonym ryzykiem (scoring już policzony).
    mfa_excluded = [
        a for a in dataset.accounts if any(f.code == "CA_MFA_EXCLUDED" for f in a.flags)
    ]
    risky_users = [a for a in dataset.accounts if a.risky_user is not None]
    legacy_attempts = any(a.activity and a.activity.legacy_auth_count for a in dataset.accounts)
    legacy_success = any(
        a.activity and a.activity.legacy_success_count for a in dataset.accounts
    )

    findings: list[dict] = []

    def _f(severity: str, text: str) -> None:
        findings.append({"severity": severity, "text": text})

    if "caPolicies" in collected:
        sec_def_on = bool(tp and tp.security_defaults_enabled)
        if not broad_mfa and not sec_def_on:
            # Brak SZEROKIEJ polityki MFA (wszyscy użytkownicy + wszystkie aplikacje).
            # Jeśli istnieją wyłącznie WĄSKIE polityki (jedna aplikacja / grupa pilotażowa),
            # to nie pełne "brak MFA", ale i NIE pass — większość logowań może być niechroniona.
            # Bez żadnej polityki MFA i bez security defaults = krytyczne.
            if mfa_policies:
                _f("high", tr.t("posture.mfa_narrow", count=len(mfa_policies)))
            else:
                _f("critical", tr.t("posture.no_mfa_policy"))
        if not legacy_block:
            sev = "high" if legacy_success else ("medium" if legacy_attempts else "low")
            note = (
                tr.t("posture.legacy_block.note_success")
                if legacy_success
                else (tr.t("posture.legacy_block.note_attempts") if legacy_attempts else "")
            )
            _f(sev, tr.t("posture.legacy_block", note=note))
        if report_only:
            names = ", ".join(f"'{p.display_name}'" for p in report_only[:3])
            more = ", …" if len(report_only) > 3 else ""
            _f("medium", tr.t("posture.report_only", count=len(report_only), names=names, more=more))
        if mfa_excluded:
            _f("high", tr.t("posture.mfa_excluded", count=len(mfa_excluded)))

    if tp is not None:
        if tp.users_can_consent_to_apps:
            _f("medium", tr.t("posture.users_consent"))
        if tp.users_can_register_apps:
            _f("low", tr.t("posture.users_register"))
        if tp.guest_user_access == "memberLevel":
            _f("medium", tr.t("posture.guest_member_level"))
        if tp.weak_auth_methods_enabled:
            methods = ", ".join(tp.weak_auth_methods_enabled)
            _f("low", tr.t("posture.weak_methods", methods=methods))

    if risky_users:
        _f("high", tr.t("posture.risky_users", count=len(risky_users)))

    findings.sort(key=lambda f: _SEV_RANK[f["severity"]])
    return {
        "ca_collected": "caPolicies" in collected,
        "ca_total": len(ca),
        "ca_enabled": len(enabled),
        "ca_report_only": len(report_only),
        "ca_mfa_policies": len(mfa_policies),
        "ca_mfa_broad": len(broad_mfa),
        "ca_legacy_block": len(legacy_block),
        "mfa_excluded_count": len(mfa_excluded),
        "risky_user_count": len(risky_users),
        # Konkretne konta SŁABO objęte CA (wykluczone z polityk MFA) i z nieobsłużonym ryzykiem —
        # do pokazania imiennie w podsumowaniu / zakładce CA (kogo to dotyczy).
        "mfa_excluded_upns": sorted(a.user_principal_name for a in mfa_excluded)[:25],
        "risky_upns": sorted(a.user_principal_name for a in risky_users)[:25],
        "tenant_policies": tp,
        "findings": findings,
    }


def build_ca_view(dataset: Dataset, t: Translator | None = None) -> dict:
    """Widok Conditional Access do zakładki: polityki rozbite na czytelne pola z ROZWIĄZANYMI
    nazwami (kto podlega / kto wykluczony — po id konta/grupy), warunki i kontrole dostępu,
    plus `facet` do interaktywnego filtrowania kafelkami (stan/MFA/legacy/wykluczenia)."""
    tr = t or Translator()
    collected = "caPolicies" in set(dataset.scan_context.collectors_run)
    acc = {a.id: (a.user_principal_name or a.display_name) for a in dataset.accounts}
    grp = {g.id: g.display_name for g in dataset.groups}
    # Wartości specjalne Graph w include/exclude — zostawiamy dosłownie (to nie id).
    special = {"All", "None", "GuestsOrExternalUsers"}

    def names(ids: list[str], mp: dict[str, str]) -> list[str]:
        out: list[str] = []
        for i in ids:
            if i in special:
                out.append(i)
            elif i in mp:
                out.append(mp[i])
            else:
                out.append(i[:8] + "…" if len(i) > 9 else i)
        return out

    pols: list[dict] = []
    for p in dataset.ca_policies:
        state = "enabled" if p.enabled else ("reportonly" if p.report_only else "disabled")
        facet = [state]
        if p.requires_mfa:
            facet.append("mfa")
        if p.blocks_legacy_auth:
            facet.append("legacy")
        if p.exclude_users or p.exclude_groups or p.exclude_roles:
            facet.append("excluded")
        pols.append(
            {
                "id": p.id,
                "name": p.display_name,
                "state": state,
                "requires_mfa": p.requires_mfa,
                "blocks_legacy": p.blocks_legacy_auth,
                "grant_controls": p.grant_controls,
                "client_app_types": p.client_app_types,
                "modified": p.modified_date_time,
                "include_users": names(p.include_users, acc),
                "exclude_users": names(p.exclude_users, acc),
                "include_groups": names(p.include_groups, grp),
                "exclude_groups": names(p.exclude_groups, grp),
                "include_roles": len(p.include_roles),
                "exclude_roles": len(p.exclude_roles),
                "covers_all_users": p.covers_all_users,
                "covers_all_apps": p.covers_all_apps,
                "is_broad": p.is_broad,
                # Włączona polityka, która COŚ wymusza (MFA / blokada legacy), ale wąsko —
                # czerwona flaga zakresu (np. „Require MFA" celujące w jedną aplikację).
                "narrow_enforced": p.enabled and (p.requires_mfa or p.blocks_legacy_auth) and not p.is_broad,
                "apps_label": (
                    tr.t("tmpl.ca.scope_all_apps") if p.covers_all_apps
                    else tr.t("tmpl.ca.scope_apps_n", n=len(p.include_applications))
                ),
                "facet": " ".join(facet),
            }
        )
    ca = dataset.ca_policies
    return {
        "collected": collected,
        "policies": pols,
        "total": len(ca),
        "enabled": sum(1 for p in ca if p.enabled),
        "report_only": sum(1 for p in ca if p.report_only),
        "disabled": sum(1 for p in ca if not p.enabled and not p.report_only),
        "mfa": sum(1 for p in ca if p.requires_mfa and p.enabled),
        "legacy": sum(1 for p in ca if p.blocks_legacy_auth and p.enabled),
        "excluded": sum(
            1 for p in ca if p.exclude_users or p.exclude_groups or p.exclude_roles
        ),
    }


def build_escalation_paths(dataset: Dataset, t: Translator | None = None, limit: int = 12) -> list[dict]:
    """Konkretne, imienne łańcuchy eskalacji do pełnej kontroli nad tenantem.

    Zamiast samego licznika — gotowe ścieżki ataku z dowodami z logów sign-in:
      1. konto ze słabą ochroną, które MA bezpośrednią rolę uprzywilejowaną,
      2. słabe konto → członkostwo w grupie → rola uprzywilejowana (shadow admin),
      3. słaby właściciel → dodanie sekretu → uprawnienia app-only aplikacji.

    Każdy element to {kind, severity, title, steps[], evidence}. Korzystamy z tego samego
    indeksu korelacyjnego, co scoring, więc raport mówi dokładnie to samo, co reguły.
    """
    tr = t or Translator()
    idx = CorrelationIndex.build(dataset, tr)
    paths: list[dict] = []

    def _sev(acc: Account) -> str:
        # Udane legacy / ryzykowne logowania = realny dowód; sam brak MFA = wysokie ryzyko.
        # Liczymy z pól konta (nie z lokalizowanego tekstu), żeby było językowo-niezależne.
        hard = bool(
            acc.risky_user is not None
            or (acc.activity and (acc.activity.legacy_success_count or acc.activity.risky_sign_in_count))
        )
        return "critical" if hard else "high"

    # (1) słabo chronione konta z BEZPOŚREDNIĄ rolą uprzywilejowaną
    for acc in dataset.accounts:
        if not acc.has_privileged_role:
            continue
        weak = account_weaknesses(acc, tr)
        if not weak:
            continue
        roles = ", ".join(sorted({r.role_name for r in acc.roles if r.is_privileged}))
        paths.append(
            {
                "kind": "identity",
                "severity": _sev(acc),
                "title": tr.t("escalation.identity.title", upn=acc.user_principal_name),
                "steps": [
                    acc.user_principal_name,
                    tr.t("escalation.step.role", roles=roles),
                    tr.t("escalation.step.full_access"),
                ],
                "evidence": ", ".join(weak),
            }
        )

    # (2) słabe konta dziedziczące rolę przez grupę (shadow admin)
    for uid, groups in idx.priv_groups_of_user.items():
        macc = idx.accounts_by_id.get(uid)
        if macc is None:
            continue
        weak = account_weaknesses(macc, tr)
        if not weak:
            continue
        for g in groups:
            paths.append(
                {
                    "kind": "group",
                    "severity": _sev(macc),
                    "title": tr.t("escalation.group.title", upn=macc.user_principal_name, group=g.display_name),
                    "steps": [
                        macc.user_principal_name,
                        tr.t("escalation.step.group_member", group=g.display_name),
                        tr.t("escalation.step.role", roles=priv_role_names(g)),
                    ],
                    "evidence": ", ".join(weak),
                }
            )

    # (3) słabo chronieni właściciele aplikacji z uprawnieniami app-only wysokiego ryzyka
    for app in dataset.applications:
        if not app.high_risk_app_permissions:
            continue
        perms = ", ".join(sorted({p.permission for p in app.high_risk_app_permissions}))
        for owner in app.owners:
            oacc = idx.resolve_owner(owner)
            if oacc is None:
                continue
            weak = account_weaknesses(oacc, tr)
            if not weak:
                continue
            paths.append(
                {
                    "kind": "app",
                    "severity": _sev(oacc),
                    "title": tr.t("escalation.app.title", upn=oacc.user_principal_name, app=app.display_name),
                    "steps": [
                        oacc.user_principal_name,
                        tr.t("escalation.step.app_owner", app=app.display_name),
                        tr.t("escalation.step.add_secret"),
                        tr.t("escalation.step.app_only", perms=perms),
                    ],
                    "evidence": ", ".join(weak),
                }
            )

    paths.sort(key=lambda p: _SEV_RANK[p["severity"]])
    return paths[:limit]


def build_action_plan(dataset: Dataset, t: Translator | None = None, limit: int = 12) -> list[dict]:
    """Plan działań: wszystkie flagi z 3 modułów zagregowane per reguła.

    Zamienia setki pojedynczych ustaleń w krótką, priorytetyzowaną listę "co zrobić
    najpierw": jedna pozycja = jedna reguła w jednym module, z liczbą dotkniętych
    obiektów, sumą punktów i przykładami (id -> głęboki link do karty w raporcie).
    Kolejność: severity, potem suma punktów (= skala problemu w tym tenancie).
    """
    tr = t or Translator()
    sources = (
        (tr.t("community.module.users"), "users", dataset.accounts, lambda a: a.user_principal_name),
        (tr.t("community.module.groups"), "groups", dataset.groups, lambda g: g.display_name),
        (tr.t("community.module.apps"), "apps", dataset.applications, lambda a: a.display_name),
    )
    buckets: dict[tuple[str, str], dict] = {}
    for module, key, items, name_of in sources:
        for it in items:
            for f in it.flags:
                b = buckets.setdefault(
                    (key, f.code),
                    {
                        "module": module,
                        "module_key": key,
                        "code": f.code,
                        "title": f.title,
                        "severity": f.severity,
                        "recommendation": f.recommendation,
                        "count": 0,
                        "points": 0,
                        "examples": [],
                    },
                )
                b["count"] += 1
                b["points"] += f.points
                if len(b["examples"]) < 3:
                    b["examples"].append({"id": it.id, "name": name_of(it)})
    plan = sorted(
        buckets.values(), key=lambda b: (_SEV_RANK[b["severity"]], -b["points"], -b["count"])
    )
    return plan[:limit]


def build_overview(
    dataset: Dataset,
    community: dict,
    groups_view: dict,
    apps_view: dict,
    posture: dict | None = None,
    t: Translator | None = None,
) -> dict:
    """Zbiorcze streszczenie dla zarządu — postawa ŁĄCZNA + spostrzeżenia krzyżowe.

    To serce raportu 'summary': jedna ocena dla całego tenanta i powiązania między modułami
    (np. uprzywilejowane grupy + aplikacje z zapisem do katalogu = ścieżki do pełnej kontroli).
    Postawa konfiguracyjna (1.3, build_posture) dokłada karę do oceny: luka w konfiguracji
    (brak wymuszenia MFA, brak blokady legacy) waży, nawet gdy obiekty wyglądają czysto.
    """
    tr = t or Translator()
    combined_sev = {
        s: community["sev_counts"].get(s, 0)
        + groups_view["sev_counts"].get(s, 0)
        + apps_view["sev_counts"].get(s, 0)
        for s in ("critical", "high", "medium", "low", "info")
    }
    posture_penalty = 0
    if posture:
        posture_penalty = sum(
            {"critical": 12, "high": 6, "medium": 3}.get(f["severity"], 0)
            for f in posture["findings"]
        )
    grade, note = _grade_from_sev(
        combined_sev,
        extra_penalty=10 * community["priv_no_mfa_count"]
        + 8 * groups_view["priv_group_count"]
        + 8 * apps_view["high_risk_count"]
        + posture_penalty,
        t=tr,
    )

    # Ścieżki eskalacji: konta uprzywilejowane bez MFA + grupy nadające role + aplikacje z zapisem do katalogu.
    escalation_paths = (
        community["priv_no_mfa_count"]
        + groups_view["priv_group_count"]
        + apps_view["high_risk_count"]
    )

    insights: list[str] = []
    if community["priv_no_mfa_count"]:
        insights.append(tr.t("insight.priv_no_mfa", count=community["priv_no_mfa_count"]))
    if groups_view["priv_group_count"]:
        insights.append(tr.t("insight.priv_groups", count=groups_view["priv_group_count"]))
    if apps_view["high_risk_count"]:
        insights.append(tr.t("insight.high_risk_apps", count=apps_view["high_risk_count"]))
    if apps_view["expired_count"]:
        insights.append(tr.t("insight.expired_apps", count=apps_view["expired_count"]))
    if groups_view["license_blast"]:
        insights.append(tr.t("insight.license_blast", count=groups_view["license_blast"]))
    if community["legacy_success_count"]:
        insights.append(tr.t("insight.legacy_success", count=community["legacy_success_count"]))
    elif community["legacy_auth_count"]:
        insights.append(tr.t("insight.legacy_attempts", count=community["legacy_auth_count"]))
    if posture:
        # Konfiguracja tłumaczy objawy — najcięższe luki postawy wprost do streszczenia.
        for f in posture["findings"]:
            if f["severity"] in ("critical", "high"):
                insights.append(f["text"])

    return {
        "grade": grade,
        "grade_note": note,
        "combined_sev": combined_sev,
        "escalation_paths": escalation_paths,
        "insights": insights,
        "modules": [
            {
                "key": "users",
                "label": tr.t("community.module.users"),
                "total": community["account_total"],
                "grade": community["grade"],
                "sev": community["sev_counts"],
                "headline": (community["top_findings"][0]["headline"] if community["top_findings"] else tr.t("community.headline.none")),
            },
            {
                "key": "groups",
                "label": tr.t("community.module.groups"),
                "total": groups_view["group_total"],
                "grade": groups_view["grade"],
                "sev": groups_view["sev_counts"],
                "headline": (groups_view["top_findings"][0]["headline"] if groups_view["top_findings"] else tr.t("community.headline.none")),
            },
            {
                "key": "apps",
                "label": tr.t("community.module.apps"),
                "total": apps_view["app_total"],
                "grade": apps_view["grade"],
                "sev": apps_view["sev_counts"],
                "headline": (apps_view["top_findings"][0]["headline"] if apps_view["top_findings"] else tr.t("community.headline.none")),
            },
        ],
    }
