"""Reguły, których mały sample nie wyzwala (wymagają skali/specyficznych danych).
Budujemy minimalne obiekty modeli i sprawdzamy predykaty przez silnik scoringu."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from accessguy_processor.models import Account, Application, AssignedPrincipal, RoleAssignment
from accessguy_processor.rules import load_rubric
from accessguy_processor.scoring import score_account, score_application

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
RUBRIC = load_rubric()


def _priv(name: str) -> RoleAssignment:
    return RoleAssignment(role_name=name, assignment_type="active", is_privileged=True)


def _acc(**kw) -> Account:
    base = dict(
        id="1", user_principal_name="x@contoso.pl", display_name="X",
        category="internal", account_enabled=True, created_date_time=NOW,
    )
    base.update(kw)
    return Account(**base)


def _codes(obj) -> set[str]:
    return {f.code for f in obj.flags}


def test_external_member():
    acc = _acc(category="external", user_principal_name="x@ext.com")
    score_account(acc, RUBRIC, NOW)
    assert "EXTERNAL_MEMBER" in _codes(acc)


def test_multiple_priv_roles():
    acc = _acc(roles=[_priv("Global Administrator"), _priv("Security Administrator"), _priv("User Administrator")])
    score_account(acc, RUBRIC, NOW)
    assert "MULTIPLE_PRIV_ROLES" in _codes(acc)


def test_new_privileged_account():
    acc = _acc(created_date_time=NOW - timedelta(days=5), roles=[_priv("Global Administrator")])
    score_account(acc, RUBRIC, NOW)
    assert "NEW_PRIVILEGED_ACCOUNT" in _codes(acc)


def test_app_wide_consent():
    users = [AssignedPrincipal(display_name=f"u{i}", via="consent") for i in range(20)]
    app = Application(id="a", display_name="WideApp", assigned_users=users)
    score_application(app, RUBRIC, NOW)
    assert "APP_WIDE_CONSENT" in _codes(app)
