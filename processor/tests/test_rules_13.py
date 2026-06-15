"""Reguły schema 1.3: Identity Protection (riskyUsers), Conditional Access,
aktywność SP i audit poświadczeń — oraz anty-false-positive PRIV_COMPROMISE_SIGNALS
(twarde vs miękkie sygnały)."""

from __future__ import annotations

from datetime import datetime, timezone

from accessguy_processor.ingest import load_dataset
from accessguy_processor.models import (
    Account,
    Activity,
    Application,
    AppPermissionGrant,
    CredentialEvent,
    Dataset,
    RiskyUser,
    RoleAssignment,
    ScanContext,
    Tenant,
)
from accessguy_processor.report.community import build_posture
from accessguy_processor.rules import load_rubric
from accessguy_processor.scoring import score_dataset

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
RUBRIC = load_rubric()


def _ds(accounts=None, applications=None, collectors=None) -> Dataset:
    return Dataset(
        schema_version="1.3",
        generated_at=NOW,
        tenant=Tenant(id="t", display_name="Test", verified_domains=["contoso.pl"]),
        scan_context=ScanContext(
            scanner_version="test", auth_mode="delegated",
            collectors_run=collectors or ["users"], premium_license=True,
        ),
        accounts=accounts or [],
        applications=applications or [],
    )


def _acc(**kw) -> Account:
    base = dict(
        id="u1", user_principal_name="u1@contoso.pl", display_name="User One",
        category="internal", account_enabled=True, created_date_time=NOW,
    )
    base.update(kw)
    return Account(**base)


def _codes(obj) -> set[str]:
    return {f.code for f in obj.flags}


# --- anty-false-positive: PRIV_COMPROMISE_SIGNALS ----------------------------

def test_priv_compromise_not_fired_on_failed_signins_only():
    """Sama seria nieudanych logowań (wygasłe hasło w starym kliencie) NIE robi
    z admina incydentu critical — zostaje MANY_FAILED_SIGNINS (medium)."""
    acc = _acc(
        mfa_registered=True,
        roles=[RoleAssignment(role_name="Global Administrator", assignment_type="active", is_privileged=True)],
        activity=Activity(window_days=30, sign_in_count=20, failed_sign_in_count=25),
    )
    ds = score_dataset(_ds(accounts=[acc]), RUBRIC)
    codes = _codes(ds.accounts[0])
    assert "PRIV_COMPROMISE_SIGNALS" not in codes
    assert "MANY_FAILED_SIGNINS" in codes


def test_priv_compromise_fired_on_hard_signal_with_concrete_evidence():
    """Twardy dowód (ryzykowne logowania) → reguła odpala się, a evidence podaje
    konkrety: liczbę, okno, źródło uprawnień i gdzie zweryfikować."""
    acc = _acc(
        mfa_registered=True,
        roles=[RoleAssignment(role_name="Global Administrator", assignment_type="active", is_privileged=True)],
        activity=Activity(window_days=30, sign_in_count=5, risky_sign_in_count=2, failed_sign_in_count=15),
    )
    ds = score_dataset(_ds(accounts=[acc]), RUBRIC)
    flag = next(f for f in ds.accounts[0].flags if f.code == "PRIV_COMPROMISE_SIGNALS")
    assert "2 logowań oznaczonych jako ryzykowne" in flag.evidence
    assert "Global Administrator" in flag.evidence
    assert "Sign-in logs" in flag.evidence          # wskazówka weryfikacji
    assert "Kontekst dodatkowy" in flag.evidence    # failed sign-ins jako kontekst, nie powód


def test_priv_compromise_fired_on_risky_user_state():
    """Nieobsłużony riskState z Identity Protection to też twardy dowód."""
    acc = _acc(
        roles=[RoleAssignment(role_name="Security Administrator", assignment_type="active", is_privileged=True)],
        risky_user=RiskyUser(risk_level="high", risk_state="atRisk"),
    )
    ds = score_dataset(_ds(accounts=[acc]), RUBRIC)
    assert "PRIV_COMPROMISE_SIGNALS" in _codes(ds.accounts[0])


# --- 1.3: nowe reguły kont ----------------------------------------------------

def test_risky_user_unremediated_on_sample(sample_dataset_path):
    ds = score_dataset(load_dataset(sample_dataset_path), RUBRIC)
    svc = next(a for a in ds.accounts if a.user_principal_name == "stary.serwis@contoso.pl")
    flag = next(f for f in svc.flags if f.code == "RISKY_USER_UNREMEDIATED")
    assert "atRisk" in flag.evidence
    assert "high" in flag.evidence


def test_ca_mfa_excluded_on_sample(sample_dataset_path):
    """admin.ext jest wykluczony wprost z polityki 'Require MFA for all users';
    jan.kowalski nie jest wykluczony z niczego (musi zostać czysty)."""
    ds = score_dataset(load_dataset(sample_dataset_path), RUBRIC)
    guest = next(a for a in ds.accounts if a.user_principal_name == "admin.ext@partner.com")
    flag = next(f for f in guest.flags if f.code == "CA_MFA_EXCLUDED")
    assert "Require MFA for all users" in flag.evidence
    assert "uprzywilejowan" in flag.evidence  # GA wykluczony z MFA -> dopisek
    jan = next(a for a in ds.accounts if a.user_principal_name == "jan.kowalski@contoso.pl")
    assert "CA_MFA_EXCLUDED" not in _codes(jan)


# --- 1.3: nowe reguły aplikacji -----------------------------------------------

def test_app_dormant_privileged_fires_on_old_signin():
    app = Application(
        id="a1", display_name="DeadApp",
        last_sign_in_date_time=datetime(2025, 6, 1, tzinfo=timezone.utc),  # rok temu
        permissions=[AppPermissionGrant(permission="Directory.ReadWrite.All", grant_type="application", is_high_risk=True)],
    )
    ds = score_dataset(_ds(applications=[app], collectors=["apps", "spSignIns"]), RUBRIC)
    assert "APP_DORMANT_PRIVILEGED" in _codes(ds.applications[0])


def test_app_dormant_privileged_silent_without_collector():
    """lastSignIn=None bez kolektora spSignIns = brak danych, nie 'nigdy' — milczymy."""
    app = Application(
        id="a1", display_name="UnknownApp",
        permissions=[AppPermissionGrant(permission="Directory.ReadWrite.All", grant_type="application", is_high_risk=True)],
    )
    ds = score_dataset(_ds(applications=[app], collectors=["apps"]), RUBRIC)
    assert "APP_DORMANT_PRIVILEGED" not in _codes(ds.applications[0])
    # ...ale z kolektorem ten sam kształt danych ZNACZY 'nigdy' i flaga jest
    ds2 = score_dataset(_ds(applications=[app.model_copy(deep=True)], collectors=["apps", "spSignIns"]), RUBRIC)
    assert "APP_DORMANT_PRIVILEGED" in _codes(ds2.applications[0])


def test_app_credential_added_on_sample(sample_dataset_path):
    ds = score_dataset(load_dataset(sample_dataset_path), RUBRIC)
    backup = next(a for a in ds.applications if a.display_name == "Backup Service")
    flag = next(f for f in backup.flags if f.code == "APP_CREDENTIAL_ADDED")
    assert "jan.kowalski@contoso.pl" in flag.evidence
    assert "2026-05-20" in flag.evidence


def test_app_credential_added_respects_window():
    app = Application(
        id="a1", display_name="OldChange",
        credential_events=[CredentialEvent(
            activity="Update application – Certificates and secrets management",
            actor="ktos@contoso.pl",
            activity_date_time=datetime(2026, 1, 1, tzinfo=timezone.utc),  # 5 mies. temu
        )],
    )
    ds = score_dataset(_ds(applications=[app]), RUBRIC)
    assert "APP_CREDENTIAL_ADDED" not in _codes(ds.applications[0])


# --- 1.3: postawa tenanta -------------------------------------------------------

def test_build_posture_on_sample(sample_dataset_path):
    ds = score_dataset(load_dataset(sample_dataset_path), RUBRIC)
    posture = build_posture(ds)
    assert posture is not None
    assert posture["ca_total"] == 2
    assert posture["ca_mfa_policies"] == 1
    assert posture["ca_legacy_block"] == 0   # jedyna blokada legacy jest report-only
    assert posture["mfa_excluded_count"] == 1
    assert posture["risky_user_count"] == 1
    texts = " ".join(f["text"] for f in posture["findings"])
    assert "legacy" in texts
    assert "report-only" in texts
    assert "Sms" in texts


def test_build_posture_none_for_old_datasets():
    """Dataset 1.2 bez kolektorów 1.3 → posture None (sekcja w summary znika)."""
    ds = _ds(accounts=[_acc()])
    assert build_posture(ds) is None
