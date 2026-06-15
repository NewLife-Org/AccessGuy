"""Testy reguł korelacyjnych (tożsamość × grupa × aplikacja × logi sign-in)
i imiennych ścieżek eskalacji. Budujemy minimalne datasety i sprawdzamy, że
korelacja faktycznie łączy moduły."""

from __future__ import annotations

from datetime import datetime, timezone

from accessguy_processor.models import (
    Account,
    Activity,
    Application,
    AppPermissionGrant,
    AssignedPrincipal,
    Dataset,
    Group,
    GroupRoleAssignment,
    PrincipalRef,
    RoleAssignment,
    ScanContext,
    Tenant,
)
from accessguy_processor.report.community import build_escalation_paths
from accessguy_processor.rules import load_rubric
from accessguy_processor.scoring import score_dataset

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)
RUBRIC = load_rubric()


def _ds(accounts=None, groups=None, applications=None) -> Dataset:
    return Dataset(
        schema_version="1.2",
        generated_at=NOW,
        tenant=Tenant(id="t", display_name="Test", verified_domains=["contoso.pl"]),
        scan_context=ScanContext(
            scanner_version="test", auth_mode="delegated",
            collectors_run=["users"], premium_license=True,
        ),
        accounts=accounts or [],
        groups=groups or [],
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


def test_shadow_privilege_via_group():
    """Konto bez bezpośredniej roli, ale członek grupy role-assignable z rolą priv."""
    acc = _acc(mfa_registered=True)  # MFA on → to NIE jest weak, ale shadow nadal łapie
    grp = Group(
        id="g1", display_name="Admins", group_kind="security",
        created_date_time=NOW, is_assignable_to_role=True,
        assigned_roles=[GroupRoleAssignment(role_name="Global Administrator", is_privileged=True)],
        members=[PrincipalRef(id="u1", display_name="User One", type="user")],
        owners=["someone@contoso.pl"],
    )
    ds = score_dataset(_ds(accounts=[acc], groups=[grp]), RUBRIC)
    u = next(a for a in ds.accounts if a.id == "u1")
    assert "SHADOW_PRIVILEGE" in _codes(u)


def test_group_priv_weak_members_names_them():
    """Grupa priv z członkiem bez MFA → GROUP_PRIV_WEAK_MEMBERS z UPN w evidence."""
    acc = _acc(mfa_registered=False)
    grp = Group(
        id="g1", display_name="Admins", group_kind="security",
        created_date_time=NOW, is_assignable_to_role=True,
        assigned_roles=[GroupRoleAssignment(role_name="Global Administrator", is_privileged=True)],
        members=[PrincipalRef(id="u1", display_name="User One", type="user")],
        owners=["o@contoso.pl"],
    )
    ds = score_dataset(_ds(accounts=[acc], groups=[grp]), RUBRIC)
    g = ds.groups[0]
    flag = next(f for f in g.flags if f.code == "GROUP_PRIV_WEAK_MEMBERS")
    assert "u1@contoso.pl" in flag.evidence


def test_priv_compromise_signals():
    """Konto z rolą priv + ryzykowne logowania → reguła incydentu (critical)."""
    acc = _acc(
        mfa_registered=True,
        roles=[RoleAssignment(role_name="Global Administrator", assignment_type="active", is_privileged=True)],
        activity=Activity(window_days=30, sign_in_count=5, risky_sign_in_count=2),
    )
    ds = score_dataset(_ds(accounts=[acc]), RUBRIC)
    u = ds.accounts[0]
    assert "PRIV_COMPROMISE_SIGNALS" in _codes(u)
    assert u.severity == "critical"


def test_app_priv_owner_weak():
    """Owner aplikacji z app-only high-risk jest bez MFA → APP_PRIV_OWNER_WEAK."""
    owner = _acc(id="o1", user_principal_name="owner@contoso.pl", mfa_registered=False)
    app = Application(
        id="a1", display_name="RiskyApp", owners=["owner@contoso.pl"],
        permissions=[AppPermissionGrant(permission="Directory.ReadWrite.All", grant_type="application", is_high_risk=True)],
    )
    ds = score_dataset(_ds(accounts=[owner], applications=[app]), RUBRIC)
    a = ds.applications[0]
    assert "APP_PRIV_OWNER_WEAK" in _codes(a)


def test_app_guest_reach_direct():
    guest = _acc(id="x1", user_principal_name="ext@partner.com", category="guest")
    app = Application(
        id="a1", display_name="App",
        assigned_users=[AssignedPrincipal(id="x1", display_name="Ext", via="assignment", type="user")],
    )
    ds = score_dataset(_ds(accounts=[guest], applications=[app]), RUBRIC)
    assert "APP_GUEST_REACH" in _codes(ds.applications[0])


def test_escalation_paths_named():
    """build_escalation_paths zwraca imienne łańcuchy ze wszystkich trzech źródeł."""
    weak_admin = _acc(id="a1", user_principal_name="admin@contoso.pl", mfa_registered=False,
                      roles=[RoleAssignment(role_name="Global Administrator", assignment_type="active", is_privileged=True)])
    member = _acc(id="m1", user_principal_name="member@contoso.pl", mfa_registered=False)
    grp = Group(
        id="g1", display_name="HelpdeskAdmins", group_kind="security", created_date_time=NOW,
        is_assignable_to_role=True,
        assigned_roles=[GroupRoleAssignment(role_name="Helpdesk Administrator", is_privileged=True)],
        members=[PrincipalRef(id="m1", display_name="Member", type="user")], owners=["o@contoso.pl"],
    )
    owner = _acc(id="o1", user_principal_name="appowner@contoso.pl", mfa_registered=False)
    app = Application(
        id="ap1", display_name="SyncApp", owners=["appowner@contoso.pl"],
        permissions=[AppPermissionGrant(permission="Mail.Send", grant_type="application", is_high_risk=True)],
    )
    ds = score_dataset(_ds(accounts=[weak_admin, member, owner], groups=[grp], applications=[app]), RUBRIC)
    paths = build_escalation_paths(ds)
    kinds = {p["kind"] for p in paths}
    assert kinds == {"identity", "group", "app"}
    titles = " ".join(p["title"] for p in paths)
    assert "admin@contoso.pl" in titles
    assert "member@contoso.pl" in titles
    assert "appowner@contoso.pl" in titles
