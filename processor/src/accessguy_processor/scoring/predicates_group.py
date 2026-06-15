"""Predykaty reguł scoringu dla modułu GRUPY.

Sygnatura jak w predicates.py: (group, ctx) -> str | None
  - None -> reguła się NIE odpala
  - str  -> evidence (konkretny dowód do raportu)

Rejestr GROUP_PREDICATES wiąże id reguły (groupRules w rules.yaml) z funkcją.
"""

from __future__ import annotations

from ..models import Group
from .correlation import account_weaknesses
from .predicates import ScoringContext


def group_role_assignable_priv(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.has_privileged_role:
        names = ", ".join(r.role_name for r in grp.assigned_roles if r.is_privileged)
        who = f"{grp.member_count} członków" if grp.member_count is not None else "członkowie"
        return f"Grupa nadaje role uprzywilejowane: {names}. {who} dziedziczy ten dostęp."
    return None


def group_role_assignable(grp: Group, ctx: ScoringContext) -> str | None:
    # Tylko gdy grupa jest role-assignable, a NIE złapała już cięższej reguły priv.
    if grp.is_assignable_to_role and not grp.has_privileged_role:
        if grp.assigned_roles:
            names = ", ".join(r.role_name for r in grp.assigned_roles)
            return f"Grupa role-assignable z przypisanymi rolami: {names}."
        return "Grupa oznaczona jako role-assignable (może otrzymać role katalogowe)."
    return None


def group_ownerless(grp: Group, ctx: ScoringContext) -> str | None:
    # Grupy synchronizowane z on-prem zarządza AD lokalny — brak ownera w chmurze to norma.
    if grp.on_premises_sync_enabled:
        return None
    count = grp.owner_count if grp.owner_count is not None else len(grp.owners)
    if count == 0:
        return "Brak właściciela — grupa nie jest atestowana ani zarządzana."
    return None


def group_dynamic_membership(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.membership_type == "dynamic":
        rule = grp.membership_rule or "(reguła nieznana)"
        snippet = rule if len(rule) <= 120 else rule[:117] + "..."
        return f"Członkostwo dynamiczne wg reguły: {snippet}"
    return None


def group_guests_with_access(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.guest_count and grp.guest_count > 0 and grp.grants_access:
        what = []
        if grp.assigned_roles:
            what.append("role")
        if grp.assigned_licenses:
            what.append("licencje")
        if grp.security_enabled:
            what.append("dostęp (security)")
        return f"{grp.guest_count} gość(i) w grupie nadającej {', '.join(what)}."
    return None


def group_public_m365(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.group_kind == "microsoft365" and grp.visibility == "Public":
        return "Grupa Microsoft 365 'Public' — każdy w organizacji może dołączyć i czytać zawartość."
    return None


def group_onprem_role(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.on_premises_sync_enabled and grp.assigned_roles:
        names = ", ".join(r.role_name for r in grp.assigned_roles)
        return f"Grupa z on-prem nadaje role w chmurze: {names} (eskalacja on-prem → Entra)."
    return None


def group_license_no_members(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.assigned_licenses and grp.member_count == 0:
        lic = ", ".join(grp.assigned_licenses)
        return f"Grupa przypisuje licencje ({lic}), ale nie ma członków."
    return None


def group_empty(grp: Group, ctx: ScoringContext) -> str | None:
    # Tylko gdy znamy liczność (best-effort) i grupa nic nie nadaje przez licencje.
    if grp.member_count == 0 and not grp.assigned_licenses and grp.group_kind in ("security", "microsoft365"):
        return "Grupa jest pusta (0 członków) — kandydat do usunięcia (higiena katalogu)."
    return None


def group_large_privileged(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.has_privileged_role and grp.member_count is not None and grp.member_count >= ctx.th("largeGroupMembers"):
        roles = ", ".join(r.role_name for r in grp.assigned_roles if r.is_privileged)
        return f"Grupa nadaje role uprzywilejowane ({roles}) i ma {grp.member_count} członków — duży promień rażenia."
    return None


def group_dynamic_privileged(grp: Group, ctx: ScoringContext) -> str | None:
    if grp.membership_type == "dynamic" and (grp.assigned_roles or grp.assigned_licenses):
        what = []
        if grp.assigned_roles:
            what.append("role")
        if grp.assigned_licenses:
            what.append("licencje")
        return f"Reguła dynamiczna automatycznie nadaje {', '.join(what)} — atrybut konta decyduje o dostępie."
    return None


def group_nested(grp: Group, ctx: ScoringContext) -> str | None:
    nested = [m for m in grp.members if m.type == "group"]
    if nested:
        names = ", ".join(m.display_name for m in nested[:5])
        return f"Grupa zawiera {len(nested)} pod-grup(y): {names} — dziedziczenie utrudnia audyt dostępu."
    return None


def group_priv_weak_members(grp: Group, ctx: ScoringContext) -> str | None:
    """Korelacja grupa × tożsamość: grupa nadaje rolę uprzywilejowaną, a wśród jej
    członków są konta słabo chronione (brak MFA / udane legacy / ryzykowne logowania).
    Każde z tych kont to admin bez ochrony — wskazujemy je IMIENNIE."""
    if ctx.index is None or not grp.has_privileged_role:
        return None
    weak: list[str] = []
    for m in grp.members:
        if m.type != "user" or not m.id:
            continue
        acc = ctx.index.accounts_by_id.get(m.id)
        if acc is None:
            continue
        reasons = account_weaknesses(acc)
        if reasons:
            weak.append(f"{acc.user_principal_name} ({', '.join(reasons)})")
    if not weak:
        return None
    shown = "; ".join(weak[:5]) + (f" … (+{len(weak) - 5})" if len(weak) > 5 else "")
    return f"{len(weak)} słabo chronionych członków dziedziczy rolę uprzywilejowaną: {shown}"


GROUP_PREDICATES = {
    "GROUP_ROLE_ASSIGNABLE_PRIV": group_role_assignable_priv,
    "GROUP_ROLE_ASSIGNABLE": group_role_assignable,
    "GROUP_OWNERLESS": group_ownerless,
    "GROUP_DYNAMIC_MEMBERSHIP": group_dynamic_membership,
    "GROUP_GUESTS_WITH_ACCESS": group_guests_with_access,
    "GROUP_PUBLIC_M365": group_public_m365,
    "GROUP_ONPREM_ROLE": group_onprem_role,
    "GROUP_LICENSE_NO_MEMBERS": group_license_no_members,
    "GROUP_EMPTY": group_empty,
    "GROUP_LARGE_PRIVILEGED": group_large_privileged,
    "GROUP_DYNAMIC_PRIVILEGED": group_dynamic_privileged,
    "GROUP_NESTED": group_nested,
    "GROUP_PRIV_WEAK_MEMBERS": group_priv_weak_members,
}
