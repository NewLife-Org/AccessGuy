"""Predykaty reguł scoringu.

Każdy predykat: (account, ctx) -> str | None
  - None        -> reguła się NIE odpala
  - str         -> reguła się odpala; tekst to 'evidence' (konkretny dowód do raportu)

Rejestr PREDICATES wiąże id reguły z funkcją. Engine iteruje rules.yaml i woła pasujący predykat.
Predykaty są celowo proste (porównania dat/booli) — łatwe do czytania i testowania.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..i18n import Translator
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
    # Tłumacz dowodów (evidence). Domyślnie EN — predykaty wołają ctx.t("evidence.<KEY>", ...).
    t: Translator = field(default_factory=Translator)

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
        return ctx.t("evidence.INACTIVE_90", days=d, warn=warn)
    return None


def inactive_180(acc: Account, ctx: ScoringContext) -> str | None:
    d = ctx.days_since_sign_in(acc)
    crit = ctx.th("inactiveCriticalDays")
    if d is not None and d >= crit:
        return ctx.t("evidence.INACTIVE_180", days=d, crit=crit)
    return None


def never_signed_in(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.last_sign_in_date_time is None and acc.account_enabled and _has_license(acc):
        return ctx.t("evidence.NEVER_SIGNED_IN")
    return None


def stale_guest(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category != "guest":
        return None
    pending = ctx.th("staleGuestPendingDays")
    if acc.external_user_state == "PendingAcceptance" and ctx.account_age_days(acc) >= pending:
        return ctx.t("evidence.STALE_GUEST.pending", days=ctx.account_age_days(acc))
    d = ctx.days_since_sign_in(acc)
    if d is None:
        return ctx.t("evidence.STALE_GUEST.no_record")
    if d >= ctx.th("inactiveWarnDays"):
        return ctx.t("evidence.STALE_GUEST.inactive", days=d)
    return None


def guest_privileged(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "guest" and acc.has_privileged_role:
        names = ", ".join(r.role_name for r in acc.roles if r.is_privileged)
        return ctx.t("evidence.GUEST_PRIVILEGED", roles=names)
    return None


def ext_privileged(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "external" and acc.has_privileged_role:
        names = ", ".join(r.role_name for r in acc.roles if r.is_privileged)
        return ctx.t("evidence.EXT_PRIVILEGED", roles=names)
    return None


def permanent_privilege(acc: Account, ctx: ScoringContext) -> str | None:
    perm = [r for r in acc.roles if r.is_privileged and r.assignment_type == "permanent"]
    if perm:
        return ctx.t("evidence.PERMANENT_PRIVILEGE", roles=", ".join(r.role_name for r in perm))
    return None


def eligible_never_used(acc: Account, ctx: ScoringContext) -> str | None:
    unused = [
        r for r in acc.roles
        if r.assignment_type == "eligible" and r.activation_count_90d == 0
    ]
    if unused:
        return ctx.t("evidence.ELIGIBLE_NEVER_USED", roles=", ".join(r.role_name for r in unused))
    return None


def priv_no_mfa(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role and acc.mfa_registered is False:
        return ctx.t("evidence.PRIV_NO_MFA")
    return None


def no_mfa(acc: Account, ctx: ScoringContext) -> str | None:
    if not acc.has_privileged_role and acc.mfa_registered is False:
        return ctx.t("evidence.NO_MFA")
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
            return ctx.t("evidence.RECENT_ROLE_GRANT", role=r.role_name, days=(ref - gd).days)
    return None


def high_risk_app(acc: Account, ctx: ScoringContext) -> str | None:
    risky = [g for g in acc.app_grants if g.is_high_risk]
    if risky:
        return ctx.t("evidence.HIGH_RISK_APP", apps=", ".join(g.app_display_name for g in risky))
    return None


def disabled_with_assets(acc: Account, ctx: ScoringContext) -> str | None:
    if not acc.account_enabled and (acc.roles or acc.assigned_licenses):
        return ctx.t("evidence.DISABLED_WITH_ASSETS")
    return None


def license_waste(acc: Account, ctx: ScoringContext) -> str | None:
    d = ctx.days_since_sign_in(acc)
    if _has_license(acc) and d is not None and d >= ctx.th("inactiveWarnDays"):
        return ctx.t("evidence.LICENSE_WASTE", days=d)
    return None


def no_manager_privileged(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role and not acc.manager:
        return ctx.t("evidence.NO_MANAGER_PRIVILEGED")
    return None


def sync_anomaly(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role and acc.on_premises_sync_enabled:
        return ctx.t("evidence.SYNC_ANOMALY")
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
        return ctx.t("evidence.UNUSED_PRIVILEGE.no_signins", roles=names, window=acc.activity.window_days)
    d = ctx.days_since_sign_in(acc)
    if d is not None and d >= ctx.th("inactiveWarnDays"):
        return ctx.t("evidence.UNUSED_PRIVILEGE.inactive", roles=names, days=d)
    return None


def risky_signins(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.activity and acc.activity.risky_sign_in_count > 0:
        # Korelacja z MFA: ryzykowne logowanie na koncie bez MFA to dużo gorsza wiadomość.
        note = ctx.t("evidence.RISKY_SIGNINS.note_no_mfa") if acc.mfa_registered is False else ""
        return ctx.t(
            "evidence.RISKY_SIGNINS",
            count=acc.activity.risky_sign_in_count,
            window=acc.activity.window_days,
            note=note,
        )
    return None


def night_signins(acc: Account, ctx: ScoringContext) -> str | None:
    # Pojedyncze nocne logowanie to szum (strefy czasowe, nadgodziny) — wymagamy progu.
    # Wyjątek: konto uprzywilejowane, tam każda nocna aktywność jest warta spojrzenia.
    if not acc.activity or acc.activity.night_sign_in_count == 0:
        return None
    n = acc.activity.night_sign_in_count
    if acc.has_privileged_role:
        return ctx.t("evidence.NIGHT_SIGNINS.priv", count=n)
    if n >= ctx.th("nightSignInWarn"):
        return ctx.t("evidence.NIGHT_SIGNINS.warn", count=n, warn=ctx.th("nightSignInWarn"))
    return None


def _legacy_clients_str(acc: Account, ctx: ScoringContext, *, only_success: bool) -> str:
    """Czytelna lista protokołów legacy, np. 'IMAP4 (2 udane / 3 prób), POP3 (1/1)'."""
    parts = []
    for c in acc.activity.legacy_auth_clients:  # type: ignore[union-attr]
        if only_success and c.success_count == 0:
            continue
        parts.append(
            ctx.t("evidence.legacy_client_part", client=c.client_app, success=c.success_count, count=c.count)
        )
    return ", ".join(parts)


def legacy_auth_success(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.activity and acc.activity.legacy_success_count > 0:
        detail = _legacy_clients_str(acc, ctx, only_success=True)
        if detail:
            return ctx.t("evidence.LEGACY_AUTH_SUCCESS.detail", detail=detail)
        return ctx.t("evidence.LEGACY_AUTH_SUCCESS.count", count=acc.activity.legacy_success_count)
    return None


def legacy_auth_blocked(acc: Account, ctx: ScoringContext) -> str | None:
    # Tylko gdy były próby, ale ŻADNA się nie powiodła (np. zablokowane przez Conditional Access).
    if acc.activity and acc.activity.legacy_auth_count > 0 and acc.activity.legacy_success_count == 0:
        detail = _legacy_clients_str(acc, ctx, only_success=False)
        if detail:
            return ctx.t("evidence.LEGACY_AUTH_BLOCKED.detail", detail=detail)
        return ctx.t("evidence.LEGACY_AUTH_BLOCKED.count", count=acc.activity.legacy_auth_count)
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
        mfa_note = (
            ctx.t("evidence.STALE_PASSWORD.no_mfa")
            if acc.mfa_registered is False
            else ctx.t("evidence.STALE_PASSWORD.mfa_unknown")
        )
        return ctx.t("evidence.STALE_PASSWORD", days=days, mfa_note=mfa_note)
    return None


def many_failed_signins(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.activity and acc.activity.failed_sign_in_count >= ctx.th("failedSignInWarn"):
        # Korelacja z legacy: spray zwykle leci starymi protokołami (brak MFA po drodze).
        note = (
            ctx.t("evidence.MANY_FAILED_SIGNINS.note_legacy")
            if acc.activity.legacy_auth_count > 0
            else ""
        )
        return ctx.t(
            "evidence.MANY_FAILED_SIGNINS",
            count=acc.activity.failed_sign_in_count,
            window=acc.activity.window_days,
            note=note,
        )
    return None


def multiple_priv_roles(acc: Account, ctx: ScoringContext) -> str | None:
    names = sorted({r.role_name for r in acc.roles if r.is_privileged})
    if len(names) >= ctx.th("manyPrivRoles"):
        return ctx.t("evidence.MULTIPLE_PRIV_ROLES", count=len(names), roles=", ".join(names))
    return None


def new_privileged_account(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.has_privileged_role:
        age = ctx.account_age_days(acc)
        if age <= ctx.th("recentGrantDays"):
            return ctx.t("evidence.NEW_PRIVILEGED_ACCOUNT", days=age)
    return None


def guest_with_license(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "guest" and acc.assigned_licenses:
        return ctx.t("evidence.GUEST_WITH_LICENSE", licenses=", ".join(acc.assigned_licenses))
    return None


def external_member(acc: Account, ctx: ScoringContext) -> str | None:
    if acc.category == "external":
        return ctx.t("evidence.EXTERNAL_MEMBER")
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
    hard, soft = attack_signals(acc, ctx.th("failedSignInWarn"), ctx.t)
    if not hard:
        return None
    sources: list[str] = []
    direct = sorted({r.role_name for r in acc.roles if r.is_privileged})
    if direct:
        sources.append(ctx.t("evidence.PRIV_COMPROMISE_SIGNALS.source_roles", roles=", ".join(direct)))
    if ctx.index:
        for g in ctx.index.priv_groups_of_user.get(acc.id, []):
            sources.append(
                ctx.t("evidence.PRIV_COMPROMISE_SIGNALS.source_group",
                      group=g.display_name, roles=priv_role_names(g))
            )
    if not sources:
        return None
    evidence = ctx.t(
        "evidence.PRIV_COMPROMISE_SIGNALS.base",
        sources="; ".join(sources),
        hard="; ".join(hard),
    )
    if soft:
        evidence += ctx.t("evidence.PRIV_COMPROMISE_SIGNALS.context", soft="; ".join(soft))
    evidence += ctx.t("evidence.PRIV_COMPROMISE_SIGNALS.verify")
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
        else ctx.t("evidence.RISKY_USER_UNREMEDIATED.date_unknown")
    )
    detail = (
        ctx.t("evidence.RISKY_USER_UNREMEDIATED.detail", reason=ru.risk_detail)
        if ru.risk_detail and ru.risk_detail != "none"
        else ""
    )
    note = ctx.t("evidence.RISKY_USER_UNREMEDIATED.note_priv") if acc.has_privileged_role else ""
    return ctx.t(
        "evidence.RISKY_USER_UNREMEDIATED.base",
        state=ru.risk_state,
        level=ru.risk_level,
        when=when,
        detail=detail,
        note=note,
    )


def ca_mfa_excluded(acc: Account, ctx: ScoringContext) -> str | None:
    """Konto wykluczone z polityk Conditional Access wymagających MFA (bezpośrednio albo
    przez grupę) — rejestracja MFA nic nie daje, jeśli CA nigdy jej nie wymusi."""
    if ctx.index is None:
        return None
    exclusions = ctx.index.mfa_exclusions_of_user.get(acc.id, [])
    if not exclusions:
        return None
    note = ctx.t("evidence.CA_MFA_EXCLUDED.note_priv") if acc.has_privileged_role else ""
    return ctx.t("evidence.CA_MFA_EXCLUDED", policies="; ".join(sorted(set(exclusions))), note=note)


def shadow_privilege(acc: Account, ctx: ScoringContext) -> str | None:
    """Rola uprzywilejowana dziedziczona WYŁĄCZNIE przez członkostwo w grupie —
    konto nie figuruje w przeglądzie przypisań ról, a realnie jest adminem."""
    if ctx.index is None or acc.has_privileged_role:
        return None
    groups = ctx.index.priv_groups_of_user.get(acc.id, [])
    if not groups:
        return None
    chains = "; ".join(f"{g.display_name} → {priv_role_names(g)}" for g in groups)
    weak = account_weaknesses(acc, ctx.t)
    extra = ctx.t("evidence.SHADOW_PRIVILEGE.extra", weak=", ".join(weak)) if weak else ""
    return ctx.t("evidence.SHADOW_PRIVILEGE", chains=chains, extra=extra)


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
