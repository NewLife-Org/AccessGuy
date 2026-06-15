"""Predykaty reguł scoringu.

Każdy predykat: (account, ctx) -> str | None
  - None        -> reguła się NIE odpala
  - str         -> reguła się odpala; tekst to 'evidence' (konkretny dowód do raportu)

Rejestr PREDICATES wiąże id reguły z funkcją. Engine iteruje rules.yaml i woła pasujący predykat.
Predykaty są celowo proste (porównania dat/booli) — łatwe do czytania i testowania.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from ..models import Account
from ..rules import Rubric, Rule
from .correlation import CorrelationIndex, account_weaknesses, attack_signals, priv_role_names


@dataclass
class ScoringContext:
    rubric: Rubric
    generated_at: datetime  # liczymy "dni od logowania" względem momentu skanu (deterministycznie)
    rule: Rule | None = None  # ustawiane przez engine per reguła (dostęp do progów)
    # Indeks korelacyjny (tożsamość × grupa × aplikacja) — None przy scoringu pojedynczego
    # obiektu bez datasetu (testy jednostkowe); reguły korelacyjne wtedy grzecznie milczą.
    index: CorrelationIndex | None = None

    def days_since_sign_in(self, acc: Account) -> int | None:
        if acc.last_sign_in_date_time is None:
            return None
        ref = self.generated_at
        last = acc.last_sign_in_date_time
        # normalizacja do tz-aware UTC
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return max(0, (ref - last).days)

    def account_age_days(self, acc: Account) -> int:
        return self.days_since(acc.created_date_time) or 0

    def days_since(self, dt: datetime | None) -> int | None:
        """Dni od daty `dt` do momentu skanu (deterministycznie). None, gdy dt brak."""
        if dt is None:
            return None
        ref = self.generated_at
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (ref - dt).days)

    def th(self, name: str) -> int:
        return self.rubric.threshold(name, self.rule)


def _has_license(acc: Account) -> bool:
    return len(acc.assigned_licenses) > 0


# --- predykaty -------------------------------------------------------------

def inactive_90(acc: Account, ctx: ScoringContext) -> str | None:
    d = ctx.days_since_sign_in(acc)
    warn, crit = ctx.th("inactiveWarnDays"), ctx.th("inactiveCriticalDays")
    if d is not None and warn <= d < crit:
        return f"Ostatnie logowanie: {d} dni temu (próg {warn})."
    return None


def inactive_180(acc: Account, ctx: ScoringContext) -> str | None:
    d = ctx.days_since_sign_in(acc)
    crit = ctx.th("inactiveCriticalDays")
    if d is not None and d >= crit:
        return f"Ostatnie logowanie: {d} dni temu (próg krytyczny {crit})."
    return None


def never_signed_in(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.last_sign_in_date_time is None and acc.account_enabled and _has_license(acc):
        return "Konto aktywne i licencjonowane, brak rejestru logowania."
    return None


def stale_guest(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category != "guest":
        return None
    pending = ctx.th("staleGuestPendingDays")
    if acc.external_user_state == "PendingAcceptance" and ctx.account_age_days(acc) >= pending:
        return f"Zaproszenie 'PendingAcceptance' od {ctx.account_age_days(acc)} dni."
    d = ctx.days_since_sign_in(acc)
    if d is None:
        return "Gość bez rejestru logowania."
    if d >= ctx.th("inactiveWarnDays"):
        return f"Gość nieaktywny: {d} dni."
    return None


def guest_privileged(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "guest" and acc.has_privileged_role:
        names = ", ".join(r.role_name for r in acc.roles if r.is_privileged)
        return f"Gość z rolą uprzywilejowaną: {names}."
    return None


def ext_privileged(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "external" and acc.has_privileged_role:
        names = ", ".join(r.role_name for r in acc.roles if r.is_privileged)
        return f"Konto zewnętrzne z rolą uprzywilejowaną: {names}."
    return None


def permanent_privilege(acc: Account, ctx: ScoringContext) -> str | None:
    perm = [r for r in acc.roles if r.is_privileged and r.assignment_type == "permanent"]
    if perm:
        return f"Stałe (poza-PIM) role: {', '.join(r.role_name for r in perm)}."
    return None


def eligible_never_used(acc: Account, ctx: ScoringContext) -> str | None:
    unused = [
        r for r in acc.roles
        if r.assignment_type == "eligible" and r.activation_count_90d == 0
    ]
    if unused:
        return f"PIM-eligible nieaktywowane: {', '.join(r.role_name for r in unused)}."
    return None


def priv_no_mfa(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role and acc.mfa_registered is False:
        return "Konto uprzywilejowane bez zarejestrowanego MFA."
    return None


def no_mfa(acc: Account, ctx: ScoringContext) -> str | None:
    if not acc.has_privileged_role and acc.mfa_registered is False:
        return "Brak zarejestrowanego MFA."
    return None


def recent_role_grant(acc: Account, ctx: ScoringContext) -> str | None:
    days = ctx.th("recentGrantDays")
    for r in acc.roles:
        if r.granted_date_time is None:
            continue
        gd = r.granted_date_time
        ref = ctx.generated_at
        if gd.tzinfo is None:
            gd = gd.replace(tzinfo=timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        if (ref - gd).days <= days:
            return f"Rola '{r.role_name}' nadana {(ref - gd).days} dni temu."
    return None


def high_risk_app(acc: Account, ctx: ScoringContext) -> str | None:
    risky = [g for g in acc.app_grants if g.is_high_risk]
    if risky:
        return f"Zgody wysokiego ryzyka: {', '.join(g.app_display_name for g in risky)}."
    return None


def disabled_with_assets(acc: Account, ctx: ScoringContext) -> str | None:
    if not acc.account_enabled and (acc.roles or acc.assigned_licenses):
        return "Konto wyłączone, ale wciąż ma role i/lub licencje."
    return None


def license_waste(acc: Account, ctx: ScoringContext) -> str | None:
    d = ctx.days_since_sign_in(acc)
    if _has_license(acc) and d is not None and d >= ctx.th("inactiveWarnDays"):
        return f"Licencja przypisana, konto nieaktywne {d} dni."
    return None


def no_manager_privileged(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role and not acc.manager:
        return "Konto uprzywilejowane bez przypisanego managera."
    return None


def sync_anomaly(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role and acc.on_premises_sync_enabled:
        return "Konto uprzywilejowane synchronizowane z on-prem (zalecane cloud-only)."
    return None


# --- 1.1: reguły oparte o activity (signIns) i datę hasła ------------------

def unused_privilege(acc: Account, ctx: ScoringContext) -> str | None:
    """Konto ma aktywną/stałą rolę uprzywilejowaną, ale jej nie używa (brak logowań w oknie).

    Świadomie wymagamy DOWODU braku użycia (activity z signInCount==0 albo nieaktywność
    powyżej progu), żeby nie flagować kont z tenantów bez P1, gdzie activity jest None.
    """
    priv = [r for r in acc.roles if r.is_privileged and r.assignment_type in ("active", "permanent")]
    if not priv:
        return None
    names = ", ".join(r.role_name for r in priv)
    if acc.activity is not None and acc.activity.sign_in_count == 0:
        return f"Role {names}: brak logowań w ostatnich {acc.activity.window_days} dniach."
    d = ctx.days_since_sign_in(acc)
    if d is not None and d >= ctx.th("inactiveWarnDays"):
        return f"Role {names}: ostatnie logowanie {d} dni temu — uprawnienia nieużywane."
    return None


def risky_signins(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.activity and acc.activity.risky_sign_in_count > 0:
        # Korelacja z MFA: ryzykowne logowanie na koncie bez MFA to dużo gorsza wiadomość.
        note = " Konto BEZ zarejestrowanego MFA." if acc.mfa_registered is False else ""
        return (
            f"{acc.activity.risky_sign_in_count} ryzykownych logowań "
            f"w oknie {acc.activity.window_days} dni.{note}"
        )
    return None


def night_signins(acc: Account, ctx: ScoringContext) -> str | None:
    # Pojedyncze nocne logowanie to szum (strefy czasowe, nadgodziny) — wymagamy progu.
    # Wyjątek: konto uprzywilejowane, tam każda nocna aktywność jest warta spojrzenia.
    if not acc.activity or acc.activity.night_sign_in_count == 0:
        return None
    n = acc.activity.night_sign_in_count
    if acc.has_privileged_role:
        return f"{n} logowań KONTA UPRZYWILEJOWANEGO w godz. 20:00–04:00 (UTC)."
    if n >= ctx.th("nightSignInWarn"):
        return f"{n} logowań w godz. 20:00–04:00 (UTC) — próg {ctx.th('nightSignInWarn')}."
    return None


def _legacy_clients_str(acc: Account, *, only_success: bool) -> str:
    """Czytelna lista protokołów legacy, np. 'IMAP4 (2 udane / 3 prób), POP3 (1/1)'."""
    parts = []
    for c in acc.activity.legacy_auth_clients:  # type: ignore[union-attr]
        if only_success and c.success_count == 0:
            continue
        parts.append(f"{c.client_app} ({c.success_count} udane / {c.count} prób)")
    return ", ".join(parts)


def legacy_auth_success(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.activity and acc.activity.legacy_success_count > 0:
        detail = _legacy_clients_str(acc, only_success=True)
        if detail:
            return f"UDANE legacy auth (ominięcie MFA): {detail}."
        return f"{acc.activity.legacy_success_count} udanych logowań legacy (ominięcie MFA)."
    return None


def legacy_auth_blocked(acc: Account, ctx: ScoringContext) -> str | None:
    # Tylko gdy były próby, ale ŻADNA się nie powiodła (np. zablokowane przez Conditional Access).
    if acc.activity and acc.activity.legacy_auth_count > 0 and acc.activity.legacy_success_count == 0:
        detail = _legacy_clients_str(acc, only_success=False)
        if detail:
            return f"Próby legacy (zablokowane): {detail}."
        return f"{acc.activity.legacy_auth_count} zablokowanych prób legacy auth."
    return None


def stale_password(acc: Account, ctx: ScoringContext) -> str | None:
    # Stare hasło samo w sobie to dziś mały problem, JEŚLI konto ma MFA — wtedy odpuszczamy,
    # żeby nie zaśmiecać raportu. Realne ryzyko pojawia się przy braku MFA (hasło = jedyny czynnik).
    if acc.last_password_change_date_time is None:
        return None
    if acc.mfa_registered is True:
        return None
    ref = ctx.generated_at
    last = acc.last_password_change_date_time
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    days = max(0, (ref - last).days)
    if days >= ctx.th("passwordMaxAgeDays"):
        mfa_note = "konto BEZ MFA" if acc.mfa_registered is False else "status MFA nieznany"
        return f"Hasło niezmieniane od {days} dni i {mfa_note} — hasło to jedyna/główna ochrona."
    return None


def many_failed_signins(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.activity and acc.activity.failed_sign_in_count >= ctx.th("failedSignInWarn"):
        # Korelacja z legacy: spray zwykle leci starymi protokołami (brak MFA po drodze).
        note = (
            " Równolegle widoczne próby legacy auth — typowa sygnatura password spray."
            if acc.activity.legacy_auth_count > 0
            else ""
        )
        return (
            f"{acc.activity.failed_sign_in_count} nieudanych logowań w ostatnich "
            f"{acc.activity.window_days} dniach — możliwy password spray / brute force.{note}"
        )
    return None


def multiple_priv_roles(acc: Account, ctx: ScoringContext) -> str | None:
    names = sorted({r.role_name for r in acc.roles if r.is_privileged})
    if len(names) >= ctx.th("manyPrivRoles"):
        return f"{len(names)} ról uprzywilejowanych na jednym koncie: {', '.join(names)}."
    return None


def new_privileged_account(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role:
        age = ctx.account_age_days(acc)
        if age <= ctx.th("recentGrantDays"):
            return f"Konto uprzywilejowane utworzone {age} dni temu — zweryfikuj pochodzenie."
    return None


def guest_with_license(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "guest" and acc.assigned_licenses:
        return f"Gość z licencją: {', '.join(acc.assigned_licenses)}."
    return None


def external_member(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "external":
        return "Tożsamość spoza zweryfikowanych domen występuje jako 'member' (nie guest)."
    return None


# --- korelacje (tożsamość × grupa × logi sign-in) ---------------------------

def priv_compromise_signals(acc: Account, ctx: ScoringContext) -> str | None:
    """Konto z EFEKTYWNĄ rolą uprzywilejowaną (bezpośrednio lub przez grupę) + TWARDY
    dowód ataku. To celowo NAKŁADA się punktowo na RISKY_SIGNINS itd. — te same
    zdarzenia na koncie admina to inna klasa ryzyka niż na zwykłym koncie.

    ANTY-FALSE-POSITIVE: reguła odpala się WYŁĄCZNIE na twardych sygnałach
    (ryzykowne logowania Identity Protection, UDANE legacy auth, nieobsłużony
    riskState z /identityProtection/riskyUsers). Sama seria nieudanych logowań NIE
    wystarcza — to często wygasłe hasło w starym kliencie; zostaje w MANY_FAILED_SIGNINS
    (medium), a tutaj trafia co najwyżej jako kontekst w evidence."""
    hard, soft = attack_signals(acc, ctx.th("failedSignInWarn"))
    if not hard:
        return None
    sources: list[str] = []
    direct = sorted({r.role_name for r in acc.roles if r.is_privileged})
    if direct:
        sources.append(f"role: {', '.join(direct)}")
    if ctx.index:
        for g in ctx.index.priv_groups_of_user.get(acc.id, []):
            sources.append(f"grupa {g.display_name} ({priv_role_names(g)})")
    if not sources:
        return None
    evidence = (
        f"Uprawnienia uprzywilejowane ({'; '.join(sources)}). "
        f"Twarde dowody: {'; '.join(hard)}."
    )
    if soft:
        evidence += f" Kontekst dodatkowy: {'; '.join(soft)}."
    evidence += (
        " Weryfikacja: Entra ID → Monitoring → Sign-in logs, filtr na tego użytkownika "
        "(kolumny: Risk state, Client app, Status)."
    )
    return evidence


def risky_user_unremediated(acc: Account, ctx: ScoringContext) -> str | None:
    """Identity Protection oznaczyło konto jako atRisk / confirmedCompromised i NIKT tego
    nie obsłużył (brak resetu hasła / dismissa). Kolektor zbiera tylko stany nieobsłużone,
    więc sama obecność wpisu = finding."""
    ru = acc.risky_user
    if ru is None or ru.risk_state not in ("atRisk", "confirmedCompromised"):
        return None
    when = (
        ru.risk_last_updated_date_time.date().isoformat()
        if ru.risk_last_updated_date_time
        else "data nieznana"
    )
    detail = f", powód: {ru.risk_detail}" if ru.risk_detail and ru.risk_detail != "none" else ""
    note = " Konto ma rolę uprzywilejowaną!" if acc.has_privileged_role else ""
    return (
        f"Stan ryzyka '{ru.risk_state}' (poziom {ru.risk_level}, aktualizacja {when}{detail}) "
        f"wisi nieobsłużony w Identity Protection.{note} Weryfikacja: Entra ID → Identity "
        "Protection → Risky users."
    )


def ca_mfa_excluded(acc: Account, ctx: ScoringContext) -> str | None:
    """Konto wykluczone z polityk Conditional Access wymagających MFA (bezpośrednio albo
    przez grupę) — rejestracja MFA nic nie daje, jeśli CA nigdy jej nie wymusi."""
    if ctx.index is None:
        return None
    exclusions = ctx.index.mfa_exclusions_of_user.get(acc.id, [])
    if not exclusions:
        return None
    note = (
        " Konto ma rolę uprzywilejowaną — wykluczenie admina z MFA to gotowa furtka."
        if acc.has_privileged_role
        else ""
    )
    return f"Wykluczone z wymogu MFA: {'; '.join(sorted(set(exclusions)))}.{note}"


def shadow_privilege(acc: Account, ctx: ScoringContext) -> str | None:
    """Rola uprzywilejowana dziedziczona WYŁĄCZNIE przez członkostwo w grupie —
    konto nie figuruje w przeglądzie przypisań ról, a realnie jest adminem."""
    if ctx.index is None or acc.has_privileged_role:
        return None
    groups = ctx.index.priv_groups_of_user.get(acc.id, [])
    if not groups:
        return None
    chains = "; ".join(f"{g.display_name} → {priv_role_names(g)}" for g in groups)
    weak = account_weaknesses(acc)
    extra = f" Do tego konto słabo chronione: {', '.join(weak)}." if weak else ""
    return f"Rola uprzywilejowana dziedziczona przez członkostwo: {chains}.{extra}"


PREDICATES = {
    "INACTIVE_90": inactive_90,
    "INACTIVE_180": inactive_180,
    "NEVER_SIGNED_IN": never_signed_in,
    "STALE_GUEST": stale_guest,
    "GUEST_PRIVILEGED": guest_privileged,
    "EXT_PRIVILEGED": ext_privileged,
    "PERMANENT_PRIVILEGE": permanent_privilege,
    "ELIGIBLE_NEVER_USED": eligible_never_used,
    "PRIV_NO_MFA": priv_no_mfa,
    "NO_MFA": no_mfa,
    "RECENT_ROLE_GRANT": recent_role_grant,
    "HIGH_RISK_APP": high_risk_app,
    "DISABLED_WITH_ASSETS": disabled_with_assets,
    "LICENSE_WASTE": license_waste,
    "NO_MANAGER_PRIVILEGED": no_manager_privileged,
    "SYNC_ANOMALY": sync_anomaly,
    "UNUSED_PRIVILEGE": unused_privilege,
    "RISKY_SIGNINS": risky_signins,
    "NIGHT_SIGNINS": night_signins,
    "LEGACY_AUTH_SUCCESS": legacy_auth_success,
    "LEGACY_AUTH_BLOCKED": legacy_auth_blocked,
    "STALE_PASSWORD": stale_password,
    "MANY_FAILED_SIGNINS": many_failed_signins,
    "MULTIPLE_PRIV_ROLES": multiple_priv_roles,
    "NEW_PRIVILEGED_ACCOUNT": new_privileged_account,
    "GUEST_WITH_LICENSE": guest_with_license,
    "EXTERNAL_MEMBER": external_member,
    "PRIV_COMPROMISE_SIGNALS": priv_compromise_signals,
    "SHADOW_PRIVILEGE": shadow_privilege,
    "RISKY_USER_UNREMEDIATED": risky_user_unremediated,
    "CA_MFA_EXCLUDED": ca_mfa_excluded,
}
