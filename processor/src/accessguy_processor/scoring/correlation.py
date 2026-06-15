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

from ..models import Account, Dataset, Group


def account_weaknesses(acc: Account) -> list[str]:
    """Dlaczego to konto jest łatwe do przejęcia / być może już przejęte. Pusta lista = OK."""
    w: list[str] = []
    if acc.mfa_registered is False:
        w.append("brak MFA")
    if acc.activity:
        if acc.activity.legacy_success_count:
            w.append(f"udane legacy auth ({acc.activity.legacy_success_count})")
        if acc.activity.risky_sign_in_count:
            w.append(f"{acc.activity.risky_sign_in_count} ryzykownych logowań")
    if acc.risky_user is not None:
        w.append(
            f"Identity Protection: {acc.risky_user.risk_state} "
            f"(poziom {acc.risky_user.risk_level})"
        )
    return w


def attack_signals(acc: Account, failed_warn: int) -> tuple[list[str], list[str]]:
    """Sygnały z logów, że konto jest atakowane/nadużywane — rozdzielone na klasy dowodu.

    TWARDE = uwierzytelnienie faktycznie ZASZŁO w podejrzany sposób albo Microsoft
    potwierdza ryzyko (ryzykowne logowania, udane legacy auth, riskState z Identity
    Protection). MIĘKKIE = szum, który bywa niewinny (seria nieudanych logowań to często
    wygasłe hasło w starym kliencie, nie atak). Reguły krytyczne (PRIV_COMPROMISE_SIGNALS)
    odpalają się WYŁĄCZNIE na twardych — miękkie idą do evidence jako kontekst.
    Zwraca (twarde, miękkie)."""
    hard: list[str] = []
    soft: list[str] = []
    if acc.activity:
        a = acc.activity
        if a.risky_sign_in_count:
            hard.append(
                f"{a.risky_sign_in_count} logowań oznaczonych jako ryzykowne przez Identity "
                f"Protection w oknie {a.window_days} dni"
            )
        if a.legacy_success_count:
            protos = ", ".join(
                f"{c.client_app} ({c.success_count}x)"
                for c in a.legacy_auth_clients
                if c.success_count
            )
            hard.append(
                f"{a.legacy_success_count} UDANYCH logowań legacy auth (ominięcie MFA)"
                + (f" — protokoły: {protos}" if protos else "")
            )
        if a.failed_sign_in_count >= failed_warn:
            soft.append(
                f"{a.failed_sign_in_count} nieudanych logowań w {a.window_days} dni "
                "(może być atak, ale równie dobrze wygasłe hasło w starym kliencie)"
            )
    if acc.risky_user is not None:
        when = (
            acc.risky_user.risk_last_updated_date_time.date().isoformat()
            if acc.risky_user.risk_last_updated_date_time
            else "?"
        )
        hard.append(
            f"konto oznaczone '{acc.risky_user.risk_state}' przez Identity Protection "
            f"(poziom {acc.risky_user.risk_level}, stan z {when}) — alert NIEOBSŁUŻONY"
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
    def build(cls, dataset: Dataset) -> CorrelationIndex:
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
        # Wykluczenia z MFA: tylko polityki WŁĄCZONE i wymagające MFA. Wykluczenia przez
        # grupę rozwiązujemy po members (lista bywa przycięta do MemberCap — best effort).
        for p in dataset.ca_policies:
            if not (p.enabled and p.requires_mfa):
                continue
            for uid in p.exclude_users:
                if uid in idx.accounts_by_id:
                    idx.mfa_exclusions_of_user.setdefault(uid, []).append(
                        f"polityka '{p.display_name}' (wykluczenie bezpośrednie)"
                    )
            for gid in p.exclude_groups:
                xg = idx.groups_by_id.get(gid)
                if xg is None:
                    continue
                for m in xg.members:
                    if m.type == "user" and m.id:
                        idx.mfa_exclusions_of_user.setdefault(m.id, []).append(
                            f"polityka '{p.display_name}' (przez grupę '{xg.display_name}')"
                        )
        return idx

    def resolve_owner(self, owner: str) -> Account | None:
        """Owner ze skanera to UPN (preferowany) albo displayName — dopasuj do konta."""
        key = owner.strip().lower()
        return self.accounts_by_upn.get(key) or self.accounts_by_name.get(key)
