from __future__ import annotations

from accessguy_processor.ingest import load_dataset
from accessguy_processor.rules import load_rubric
from accessguy_processor.scoring import score_dataset


def _by_upn(ds, upn):
    return next(a for a in ds.accounts if a.user_principal_name == upn)


def test_guest_with_global_admin_is_critical(sample_dataset_path):
    ds = load_dataset(sample_dataset_path)
    ds = score_dataset(ds, load_rubric())

    guest = _by_upn(ds, "admin.ext@partner.com")
    codes = {f.code for f in guest.flags}
    # gość + Global Admin + brak MFA + pending zaproszenie -> wiele flag, severity critical
    assert "GUEST_PRIVILEGED" in codes
    assert "PRIV_NO_MFA" in codes
    assert guest.severity == "critical"


def test_internal_user_shadow_admin_via_group(sample_dataset_path):
    # Jan nie ma BEZPOŚREDNIEJ roli, ale jest członkiem grupy "Helpdesk Operators"
    # z rolą Helpdesk Administrator -> korelacja wykrywa ukrytego admina (shadow privilege).
    # Klasyczny przegląd przypisań ról by go przeoczył — to sedno modułu korelacji.
    ds = load_dataset(sample_dataset_path)
    ds = score_dataset(ds, load_rubric())

    jan = _by_upn(ds, "jan.kowalski@contoso.pl")
    codes = {f.code for f in jan.flags}
    assert codes == {"SHADOW_PRIVILEGE"}, "jedyny sygnał to dziedziczenie roli przez grupę"
    shadow = next(f for f in jan.flags if f.code == "SHADOW_PRIVILEGE")
    assert "Helpdesk Administrator" in shadow.evidence


def test_eligible_never_used_flagged(sample_dataset_path):
    ds = load_dataset(sample_dataset_path)
    ds = score_dataset(ds, load_rubric())

    svc = _by_upn(ds, "stary.serwis@contoso.pl")
    codes = {f.code for f in svc.flags}
    assert "ELIGIBLE_NEVER_USED" in codes
    assert "HIGH_RISK_APP" in codes


def test_activity_and_password_rules_v11(sample_dataset_path):
    ds = load_dataset(sample_dataset_path)
    ds = score_dataset(ds, load_rubric())

    svc = _by_upn(ds, "stary.serwis@contoso.pl")
    codes = {f.code for f in svc.flags}
    # stary.serwis ma w activity ryzykowne + nocne logowania i bardzo stare hasło
    assert "RISKY_SIGNINS" in codes
    assert "NIGHT_SIGNINS" in codes
    assert "STALE_PASSWORD" in codes
    # ma UDANE legacy (IMAP4 2/3) -> reguła SUCCESS, nie BLOCKED
    assert "LEGACY_AUTH_SUCCESS" in codes
    assert "LEGACY_AUTH_BLOCKED" not in codes
    # 12 nieudanych logowań -> sygnał ataku
    assert "MANY_FAILED_SIGNINS" in codes


def test_guest_with_license_flagged(sample_dataset_path):
    ds = load_dataset(sample_dataset_path)
    ds = score_dataset(ds, load_rubric())
    guest = _by_upn(ds, "admin.ext@partner.com")
    assert "GUEST_WITH_LICENSE" in {f.code for f in guest.flags}

    # aktywny user nie dostaje fałszywych flag z activity (jedyny sygnał to shadow-admin z grupy)
    jan = _by_upn(ds, "jan.kowalski@contoso.pl")
    assert {f.code for f in jan.flags} == {"SHADOW_PRIVILEGE"}
