"""Korelacje między modułami: tożsamość × grupa × aplikacja × logi sign-in.

`CorrelationIndex` budowany jest RAZ per dataset — predykaty dostają go w ScoringContext
i mogą patrzeć "w poprzek" modułów: członkostwa grup (po id), właściciele aplikacji
(po UPN/nazwie), przypisania aplikacji. Helpery `account_weaknesses` / `attack_signals`
mieszkają tutaj, żeby konta, grupy i aplikacje oceniały tożsamość IDENTYCZNĄ miarą —
spójna semantyka "słabego konta" w całym raporcie.

Słabość (weakness)  = konto łatwe do przejęcia (brak MFA) lub z dowodem ominięcia
                      ochrony (udane legacy auth, ryzykowne logowania).
Sygnał ataku        = aktywność w logach sign-in wskazująca trwający atak/nadużycie.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..models import Account, CaPolicy, Dataset, Group

if TYPE_CHECKING:
    from ..i18n import Translator


def account_weaknesses(acc: Account, t: "Translator | None" = None) -> list[str]:
    """Dlaczego to konto jest łatwe do przejęcia / być może już przejęte. Pusta lista = OK."""
    from ..i18n import Translator

    tr = (t or Translator()).t
    w: list[str] = []
    if acc.mfa_registered is False:
        w.append(tr("weakness.no_mfa"))
    if acc.activity:
        if acc.activity.legacy_success_count:
            w.append(tr("weakness.legacy_success", count=acc.activity.legacy_success_count))
        if acc.activity.risky_sign_in_count:
            w.append(tr("weakness.risky_signins", count=acc.activity.risky_sign_in_count))
    if acc.risky_user is not None:
        w.append(
            tr("weakness.identity_protection",
               state=acc.risky_user.risk_state, level=acc.risky_user.risk_level)
        )
    return w


def attack_signals(
    acc: Account, failed_warn: int, t: "Translator | None" = None
) -> tuple[list[str], list[str]]:
    """Sygnały z logów, że konto jest atakowane/nadużywane — rozdzielone na klasy dowodu.

    TWARDE = uwierzytelnienie faktycznie ZASZŁO w podejrzany sposób albo Microsoft
    potwierdza ryzyko (ryzykowne logowania, udane legacy auth, riskState z Identity
    Protection). MIĘKKIE = szum, który bywa niewinny (seria nieudanych logowań to często
    wygasłe hasło w starym kliencie, nie atak). Reguły krytyczne (PRIV_COMPROMISE_SIGNALS)
    odpalają się WYŁĄCZNIE na twardych — miękkie idą do evidence jako kontekst.
    Zwraca (twarde, miękkie)."""
    from ..i18n import Translator

    tr = (t or Translator()).t
    hard: list[str] = []
    soft: list[str] = []
    if acc.activity:
        a = acc.activity
        if a.risky_sign_in_count:
            hard.append(tr("attack.risky", count=a.risky_sign_in_count, window=a.window_days))
        if a.legacy_success_count:
            protos = ", ".join(
                tr("attack.legacy_proto_part", client=c.client_app, count=c.success_count)
                for c in a.legacy_auth_clients
                if c.success_count
            )
            hard.append(
                tr("attack.legacy_success", count=a.legacy_success_count)
                + (tr("attack.legacy_protocols", protos=protos) if protos else "")
            )
        if a.failed_sign_in_count >= failed_warn:
            soft.append(tr("attack.failed_soft", count=a.failed_sign_in_count, window=a.window_days))
    if acc.risky_user is not None:
        when = (
            acc.risky_user.risk_last_updated_date_time.date().isoformat()
            if acc.risky_user.risk_last_updated_date_time
            else tr("attack.date_unknown")
        )
        hard.append(
            tr("attack.risky_user",
               state=acc.risky_user.risk_state, level=acc.risky_user.risk_level, when=when)
        )
    return hard, soft


def priv_role_names(grp: Group) -> str:
    return ", ".join(r.role_name for r in grp.assigned_roles if r.is_privileged)


@dataclass
class CorrelationIndex:
    accounts_by_id: dict[str, Account] = field(default_factory=dict)
    accounts_by_upn: dict[str, Account] = field(default_factory=dict)
    accounts_by_name: dict[str, Account] = field(default_factory=dict)
    groups_by_id: dict[str, Group] = field(default_factory=dict)
    # user id -> grupy nadające role uprzywilejowane, których jest członkiem
    priv_groups_of_user: dict[str, list[Group]] = field(default_factory=dict)
    # user id -> opisy wykluczeń z polityk CA wymagających MFA (1.3, kolektor caPolicies):
    # "polityka 'X' (wykluczenie bezpośrednie)" / "polityka 'X' (przez grupę 'Y')"
    mfa_exclusions_of_user: dict[str, list[str]] = field(default_factory=dict)
    # które kolektory faktycznie biegły — pozwala odróżnić "brak danych" od "brak zdarzeń"
    # (np. lastSignInDateTime=None aplikacji znaczy 'nigdy' tylko, gdy spSignIns zebrano)
    collectors_run: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def build(cls, dataset: Dataset, t: "Translator | None" = None) -> CorrelationIndex:
        from ..i18n import Translator

        tr = (t or Translator()).t
        idx = cls()
        idx.collectors_run = frozenset(dataset.scan_context.collectors_run)
        for a in dataset.accounts:
            idx.accounts_by_id[a.id] = a
            idx.accounts_by_upn[a.user_principal_name.lower()] = a
            # displayName bywa niejednoznaczny — pierwszy wygrywa (best-effort fallback)
            idx.accounts_by_name.setdefault(a.display_name.lower(), a)
        for g in dataset.groups:
            idx.groups_by_id[g.id] = g
            if g.has_privileged_role:
                for m in g.members:
                    if m.type == "user" and m.id:
                        idx.priv_groups_of_user.setdefault(m.id, []).append(g)
        # Wykluczenia z MFA: tylko polityki WŁĄCZONE i wymagające MFA. Liczymy wykluczenie jako
        # realną LUKĘ tylko, gdy: (a) polityka faktycznie OBEJMOWAŁABY konto (zakres include),
        # ORAZ (b) ŻADNA inna włączona polityka MFA i tak go nie wymusza. To zabija dwa
        # false-positive: wykluczenie z polityki, która konta i tak nie dotyczy, oraz konto
        # wciąż chronione przez inną politykę. Wykluczenia przez grupę rozwiązujemy po members
        # (lista bywa przycięta do MemberCap — best effort).
        mfa_pols = [p for p in dataset.ca_policies if p.enabled and p.requires_mfa]

        def _covered_elsewhere(uid: str, excluding: CaPolicy) -> bool:
            return any(
                q is not excluding
                and idx._policy_applies_to(q, uid)
                and not idx._policy_excludes(q, uid)
                for q in mfa_pols
            )

        for p in mfa_pols:
            candidates: list[tuple[str, str]] = []  # (uid, lokalizowane evidence)
            for uid in p.exclude_users:
                if uid in idx.accounts_by_id:
                    candidates.append((uid, tr("ca_exclusion.direct", policy=p.display_name)))
            for gid in p.exclude_groups:
                xg = idx.groups_by_id.get(gid)
                if xg is None:
                    continue
                for m in xg.members:
                    if m.type == "user" and m.id and m.id in idx.accounts_by_id:
                        candidates.append(
                            (m.id, tr("ca_exclusion.via_group", policy=p.display_name, group=xg.display_name))
                        )
            for uid, evidence in candidates:
                if not idx._policy_applies_to(p, uid):
                    continue  # wykluczenie z polityki, która i tak nie obejmuje konta = szum
                if _covered_elsewhere(uid, p):
                    continue  # inna włączona polityka MFA wciąż wymusza MFA na tym koncie
                idx.mfa_exclusions_of_user.setdefault(uid, []).append(evidence)
        return idx

    def resolve_owner(self, owner: str) -> Account | None:
        """Owner ze skanera to UPN (preferowany) albo displayName — dopasuj do konta."""
        key = owner.strip().lower()
        return self.accounts_by_upn.get(key) or self.accounts_by_name.get(key)

    def _policy_applies_to(self, p: CaPolicy, uid: str) -> bool:
        """Czy konto MIEŚCI SIĘ w zakresie include polityki (pomijając wykluczenia)?
        include-by-role traktujemy zachowawczo jako 'nie wiem' (False) — nie mamy mapy
        rola→konto, a fałszywe 'objęte' byłoby gorsze niż pominięcie tej ścieżki."""
        inc = p.include_users
        if "All" in inc or uid in inc:
            return True
        acc = self.accounts_by_id.get(uid)
        if "GuestsOrExternalUsers" in inc and acc is not None and acc.category in ("guest", "external"):
            return True
        return any(
            (g := self.groups_by_id.get(gid)) is not None and any(m.id == uid for m in g.members)
            for gid in p.include_groups
        )

    def _policy_excludes(self, p: CaPolicy, uid: str) -> bool:
        """Czy konto jest wykluczone z polityki (wprost lub przez grupę z przyciętej listy members)?"""
        if uid in p.exclude_users:
            return True
        return any(
            (g := self.groups_by_id.get(gid)) is not None and any(m.id == uid for m in g.members)
            for gid in p.exclude_groups
        )
