"""Predykaty reguł scoringu dla modułu APLIKACJE.

Sygnatura jak w predicates.py: (application, ctx) -> str | None.
Rejestr APP_PREDICATES wiąże id reguły (appRules w rules.yaml) z funkcją.
"""

from __future__ import annotations

from ..models import Application
from .correlation import account_weaknesses
from .predicates import ScoringContext


def app_high_risk_perm(app: Application, ctx: ScoringContext) -> str | None:
    risky = [p for p in app.app_permissions if p.is_high_risk]
    if risky:
        names = ", ".join(sorted({p.permission for p in risky}))
        return ctx.t("evidence.APP_HIGH_RISK_PERM", perms=names)
    return None


def app_broad_read(app: Application, ctx: ScoringContext) -> str | None:
    broad = ctx.rubric.broad_read_app_roles
    hits = sorted(
        {
            p.permission
            for p in app.app_permissions
            if p.permission in broad and not p.is_high_risk
        }
    )
    if hits:
        return ctx.t("evidence.APP_BROAD_READ", perms=", ".join(hits))
    return None


def _enabled(app: Application) -> bool:
    # None traktujemy jak 'aktywna' — brak danych o SP nie powinien wyciszać higieny poświadczeń.
    return app.account_enabled is not False


def app_secret_expired(app: Application, ctx: ScoringContext) -> str | None:
    if not _enabled(app):
        return None
    expired = [c for c in app.credentials if c.expired]
    if expired:
        kinds = ", ".join(sorted({c.kind for c in expired}))
        return ctx.t("evidence.APP_SECRET_EXPIRED", count=len(expired), kinds=kinds)
    return None


def app_secret_expiring(app: Application, ctx: ScoringContext) -> str | None:
    warn = ctx.th("secretExpiryWarnDays")
    soon = [
        c
        for c in app.credentials
        if not c.expired and c.days_to_expiry is not None and 0 <= c.days_to_expiry <= warn
    ]
    if soon:
        nearest = min(c.days_to_expiry for c in soon if c.days_to_expiry is not None)
        return ctx.t("evidence.APP_SECRET_EXPIRING", days=nearest, warn=warn)
    return None


def app_long_lived_secret(app: Application, ctx: ScoringContext) -> str | None:
    limit = ctx.th("secretLongLivedDays")
    long = [
        c
        for c in app.credentials
        if c.lifetime_days is not None and c.lifetime_days > limit
    ]
    if long:
        longest = max(c.lifetime_days for c in long if c.lifetime_days is not None)
        return ctx.t("evidence.APP_LONG_LIVED_SECRET", days=longest, limit=limit)
    return None


def app_secret_over_cert(app: Application, ctx: ScoringContext) -> str | None:
    # Mniej szumu: „sekret zamiast certu" flagujemy tylko dla aplikacji UPRZYWILEJOWANYCH
    # (uprawnienia app-only high-risk) — tam wyciek sekretu daje pełnię dostępu do tenanta.
    if not app.high_risk_app_permissions:
        return None
    has_secret = any(c.kind == "secret" and not c.expired for c in app.credentials)
    has_cert = any(c.kind == "certificate" and not c.expired for c in app.credentials)
    if has_secret and not has_cert:
        return ctx.t("evidence.APP_SECRET_OVER_CERT")
    return None


def app_no_owner(app: Application, ctx: ScoringContext) -> str | None:
    if app.owners:
        return None
    # Gdy aplikacja jest PORZUCONA (brak właściciela + brak przypisanych użytkowników + żywe
    # poświadczenie), cięższa reguła APP_ORPHANED ją przejmuje — nie podwajamy punktów za sam
    # „brak ownera".
    if not app.assigned_users and app.credentials:
        return None
    return ctx.t("evidence.APP_NO_OWNER")


def app_multi_tenant(app: Application, ctx: ScoringContext) -> str | None:
    if app.is_multi_tenant:
        return ctx.t("evidence.APP_MULTI_TENANT", audience=app.sign_in_audience)
    return None


def app_unverified_privileged(app: Application, ctx: ScoringContext) -> str | None:
    if not app.verified_publisher and app.high_risk_permissions:
        return ctx.t("evidence.APP_UNVERIFIED_PRIVILEGED")
    return None


def app_credential_sprawl(app: Application, ctx: ScoringContext) -> str | None:
    # Liczymy tylko AKTYWNE poświadczenia — wygasłe to martwy ślad (łapie je APP_SECRET_EXPIRED),
    # rozrost dotyczy tych do rotacji TERAZ. Mniej szumu, ostrzejszy sygnał.
    active = [c for c in app.credentials if not c.expired]
    if len(active) >= ctx.th("credentialSprawl"):
        secrets = sum(1 for c in active if c.kind == "secret")
        certs = len(active) - secrets
        return ctx.t("evidence.APP_CREDENTIAL_SPRAWL", count=len(active), secrets=secrets, certs=certs)
    return None


def app_wide_consent(app: Application, ctx: ScoringContext) -> str | None:
    consent = [u for u in app.assigned_users if u.via == "consent"]
    if len(consent) >= ctx.th("wideConsentUsers"):
        return ctx.t("evidence.APP_WIDE_CONSENT", count=len(consent))
    return None


def app_orphaned(app: Application, ctx: ScoringContext) -> str | None:
    if not app.owners and not app.assigned_users and app.credentials:
        return ctx.t("evidence.APP_ORPHANED")
    return None


def app_dormant_privileged(app: Application, ctx: ScoringContext) -> str | None:
    """Aplikacja z uprawnieniami app-only wysokiego ryzyka, która NIE loguje się od dawna
    (lub wcale) — martwy ładunek: nikt jej nie używa, a kompromitacja poświadczenia daje
    pełnię uprawnień. Dane z /reports/servicePrincipalSignInActivities (1.3).

    'lastSignInDateTime is None' znaczy 'nigdy' tylko wtedy, gdy kolektor spSignIns
    faktycznie biegł — inaczej to brak danych i milczymy (zero zgadywania)."""
    if not app.high_risk_app_permissions:
        return None
    dormant_days = ctx.th("appDormantDays")
    perms = ", ".join(sorted({p.permission for p in app.high_risk_app_permissions}))
    if app.last_sign_in_date_time is not None:
        d = ctx.days_since(app.last_sign_in_date_time)
        if d is not None and d >= dormant_days:
            return ctx.t("evidence.APP_DORMANT_PRIVILEGED.inactive", days=d, dormant=dormant_days, perms=perms)
        return None
    if ctx.index is not None and "spSignIns" in ctx.index.collectors_run:
        return ctx.t("evidence.APP_DORMANT_PRIVILEGED.never", perms=perms)
    return None


def app_credential_added(app: Application, ctx: ScoringContext) -> str | None:
    """Świeże zdarzenie na poświadczeniach (audit ApplicationManagement, 1.3): kto i kiedy
    dodał/zmienił sekret lub certyfikat. Na aplikacji z uprawnieniami wysokiego ryzyka to
    dokładnie ten ruch, który wykonuje atakujący po przejęciu ownera — do potwierdzenia."""
    window = ctx.th("credentialEventDays")
    recent = [
        e
        for e in app.credential_events
        if (d := ctx.days_since(e.activity_date_time)) is not None and d <= window
    ]
    if not recent:
        return None
    recent.sort(key=lambda e: e.activity_date_time, reverse=True)
    items = "; ".join(
        ctx.t(
            "evidence.APP_CREDENTIAL_ADDED.item",
            date=e.activity_date_time.date().isoformat(),
            activity=e.activity,
            actor=e.actor or ctx.t("evidence.APP_CREDENTIAL_ADDED.actor_unknown"),
        )
        for e in recent[:3]
    )
    risk_note = ctx.t("evidence.APP_CREDENTIAL_ADDED.risk_note") if app.high_risk_permissions else ""
    return ctx.t("evidence.APP_CREDENTIAL_ADDED", window=window, items=items, risk=risk_note)


def app_priv_owner_weak(app: Application, ctx: ScoringContext) -> str | None:
    """Korelacja aplikacja × tożsamość: właściciel aplikacji z uprawnieniami app-only
    wysokiego ryzyka może w każdej chwili DODAĆ WŁASNE poświadczenie i działać jako
    aplikacja (klasyczna eskalacja). Jeśli owner jest słabo chroniony — to gotowa ścieżka:
    przejęcie ownera → nowy sekret → pełnia uprawnień aplikacji bez żadnego MFA."""
    if ctx.index is None or not app.high_risk_app_permissions:
        return None
    hits: list[str] = []
    for owner in app.owners:
        acc = ctx.index.resolve_owner(owner)
        if acc is None:
            continue
        reasons = account_weaknesses(acc, ctx.t)
        if reasons:
            hits.append(ctx.t("evidence.APP_PRIV_OWNER_WEAK.hit", upn=acc.user_principal_name, reasons=", ".join(reasons)))
    if not hits:
        return None
    perms = ", ".join(sorted({p.permission for p in app.high_risk_app_permissions}))
    evidence = ctx.t("evidence.APP_PRIV_OWNER_WEAK.base", hits="; ".join(hits), perms=perms)
    # Audit ApplicationManagement (1.3): jeśli na poświadczeniach FAKTYCZNIE coś się działo,
    # hipoteza "może dodać sekret" zamienia się w konkretny ślad do zweryfikowania.
    if app.credential_events:
        last = max(app.credential_events, key=lambda e: e.activity_date_time)
        evidence += ctx.t(
            "evidence.APP_PRIV_OWNER_WEAK.audit",
            date=last.activity_date_time.date().isoformat(),
            actor=last.actor or ctx.t("evidence.APP_CREDENTIAL_ADDED.actor_unknown"),
        )
    return evidence


def app_guest_reach(app: Application, ctx: ScoringContext) -> str | None:
    """Korelacja aplikacja × grupa × tożsamość: konta-goście mają dostęp do aplikacji —
    bezpośrednio (przypisanie/zgoda) albo przez przypisaną grupę zawierającą gości."""
    if ctx.index is None:
        return None
    direct: list[str] = []
    via_groups: list[str] = []
    for u in app.assigned_users:
        if not u.id:
            continue
        if u.type == "user":
            acc = ctx.index.accounts_by_id.get(u.id)
            if acc is not None and acc.category == "guest":
                direct.append(acc.user_principal_name)
        elif u.type == "group":
            g = ctx.index.groups_by_id.get(u.id)
            if g is not None and (g.guest_count or 0) > 0:
                via_groups.append(ctx.t("evidence.APP_GUEST_REACH.group_part", group=g.display_name, count=g.guest_count))
    if not direct and not via_groups:
        return None
    parts: list[str] = []
    if direct:
        parts.append(ctx.t("evidence.APP_GUEST_REACH.direct", users=", ".join(direct[:5])))
    if via_groups:
        parts.append(ctx.t("evidence.APP_GUEST_REACH.via_groups", groups=", ".join(via_groups[:5])))
    return ctx.t("evidence.APP_GUEST_REACH", parts="; ".join(parts))


APP_PREDICATES = {
    "APP_HIGH_RISK_PERM": app_high_risk_perm,
    "APP_BROAD_READ": app_broad_read,
    "APP_SECRET_EXPIRED": app_secret_expired,
    "APP_SECRET_EXPIRING": app_secret_expiring,
    "APP_LONG_LIVED_SECRET": app_long_lived_secret,
    "APP_SECRET_OVER_CERT": app_secret_over_cert,
    "APP_NO_OWNER": app_no_owner,
    "APP_MULTI_TENANT": app_multi_tenant,
    "APP_UNVERIFIED_PRIVILEGED": app_unverified_privileged,
    "APP_CREDENTIAL_SPRAWL": app_credential_sprawl,
    "APP_WIDE_CONSENT": app_wide_consent,
    "APP_ORPHANED": app_orphaned,
    "APP_PRIV_OWNER_WEAK": app_priv_owner_weak,
    "APP_GUEST_REACH": app_guest_reach,
    "APP_DORMANT_PRIVILEGED": app_dormant_privileged,
    "APP_CREDENTIAL_ADDED": app_credential_added,
}
