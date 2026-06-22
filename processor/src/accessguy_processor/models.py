"""Modele danych odzwierciedlające contracts/dataset.schema.json.

Pydantic z aliasami camelCase: JSON używa camelCase (konwencja Graph), kod Pythona snake_case.
To jedyne miejsce po stronie procesora, które zna kształt datasetu — reszta operuje na modelach.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["internal", "external", "guest"]
AssignmentType = Literal["eligible", "active", "permanent"]
GrantType = Literal["delegated", "application"]
Severity = Literal["info", "low", "medium", "high", "critical"]
GroupKind = Literal["microsoft365", "security", "mailSecurity", "distribution"]
MembershipType = Literal["assigned", "dynamic"]
CredentialKind = Literal["secret", "certificate"]
AppGrantType = Literal["application", "delegated"]


class _Base(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")


class RoleAssignment(_Base):
    role_name: str = Field(alias="roleName")
    role_template_id: str | None = Field(default=None, alias="roleTemplateId")
    assignment_type: AssignmentType = Field(alias="assignmentType")
    is_privileged: bool = Field(alias="isPrivileged")
    granted_date_time: datetime | None = Field(default=None, alias="grantedDateTime")
    last_activation_date_time: datetime | None = Field(default=None, alias="lastActivationDateTime")
    activation_count_90d: int = Field(default=0, alias="activationCount90d")


class AppGrant(_Base):
    app_display_name: str = Field(alias="appDisplayName")
    grant_type: GrantType = Field(alias="grantType")
    scopes: list[str] = Field(default_factory=list)
    is_high_risk: bool = Field(alias="isHighRisk")


class TopApplication(_Base):
    app_display_name: str = Field(alias="appDisplayName")
    count: int = 0


class LegacyAuthClient(_Base):
    """Rozkład legacy auth per konkretny protokół/klient (clientAppUsed)."""

    client_app: str = Field(alias="clientApp")
    count: int = 0
    success_count: int = Field(default=0, alias="successCount")


class Activity(_Base):
    """Agregat logowań (1.1) z /auditLogs/signIns w oknie obserwacji."""

    window_days: int = Field(default=30, alias="windowDays")
    sign_in_count: int = Field(default=0, alias="signInCount")
    failed_sign_in_count: int = Field(default=0, alias="failedSignInCount")
    night_sign_in_count: int = Field(default=0, alias="nightSignInCount")
    risky_sign_in_count: int = Field(default=0, alias="riskySignInCount")
    legacy_auth_count: int = Field(default=0, alias="legacyAuthCount")
    legacy_success_count: int = Field(default=0, alias="legacySuccessCount")
    legacy_auth_clients: list[LegacyAuthClient] = Field(
        default_factory=list, alias="legacyAuthClients"
    )
    last_sign_in_app: str | None = Field(default=None, alias="lastSignInApp")
    top_applications: list[TopApplication] = Field(default_factory=list, alias="topApplications")


class RiskyUser(_Base):
    """Bieżący stan ryzyka konta z Identity Protection (1.3). Kolektor zbiera tylko
    stany nieobsłużone (atRisk / confirmedCompromised) — obecność wpisu to finding."""

    risk_level: str = Field(alias="riskLevel")
    risk_state: str = Field(alias="riskState")
    risk_detail: str | None = Field(default=None, alias="riskDetail")
    risk_last_updated_date_time: datetime | None = Field(
        default=None, alias="riskLastUpdatedDateTime"
    )


class SubscribedSku(_Base):
    sku_part_number: str = Field(alias="skuPartNumber")
    sku_id: str | None = Field(default=None, alias="skuId")
    prepaid_units: int = Field(default=0, alias="prepaidUnits")
    consumed_units: int = Field(default=0, alias="consumedUnits")


class Account(_Base):
    id: str
    user_principal_name: str = Field(alias="userPrincipalName")
    display_name: str = Field(alias="displayName")
    mail: str | None = None
    category: Category
    account_enabled: bool = Field(alias="accountEnabled")
    created_date_time: datetime = Field(alias="createdDateTime")
    last_sign_in_date_time: datetime | None = Field(default=None, alias="lastSignInDateTime")
    last_non_interactive_sign_in_date_time: datetime | None = Field(
        default=None, alias="lastNonInteractiveSignInDateTime"
    )
    on_premises_sync_enabled: bool | None = Field(default=None, alias="onPremisesSyncEnabled")
    external_user_state: str | None = Field(default=None, alias="externalUserState")
    external_user_state_change_date_time: datetime | None = Field(
        default=None, alias="externalUserStateChangeDateTime"
    )
    assigned_licenses: list[str] = Field(default_factory=list, alias="assignedLicenses")
    mfa_registered: bool | None = Field(default=None, alias="mfaRegistered")
    manager: str | None = None
    last_password_change_date_time: datetime | None = Field(
        default=None, alias="lastPasswordChangeDateTime"
    )
    activity: Activity | None = None
    roles: list[RoleAssignment] = Field(default_factory=list)
    app_grants: list[AppGrant] = Field(default_factory=list, alias="appGrants")
    risky_user: RiskyUser | None = Field(default=None, alias="riskyUser")

    # --- pola wzbogacane przez scoring (nie pochodzą z datasetu) ---
    review_score: int = 0
    severity: Severity = "info"
    flags: list["ReviewFlag"] = Field(default_factory=list)

    @property
    def has_privileged_role(self) -> bool:
        return any(r.is_privileged for r in self.roles)


class Tenant(_Base):
    id: str
    display_name: str = Field(alias="displayName")
    verified_domains: list[str] = Field(alias="verifiedDomains")


class ScanContext(_Base):
    scanner_version: str = Field(alias="scannerVersion")
    auth_mode: Literal["delegated", "app"] = Field(alias="authMode")
    operator: str | None = None
    collectors_run: list[str] = Field(alias="collectorsRun")
    premium_license: bool = Field(alias="premiumLicense")
    warnings: list[str] = Field(default_factory=list)


class ServicePrincipal(_Base):
    id: str
    display_name: str = Field(alias="displayName")
    app_id: str | None = Field(default=None, alias="appId")
    account_enabled: bool | None = Field(default=None, alias="accountEnabled")
    app_role_assignments: list[str] = Field(default_factory=list, alias="appRoleAssignments")
    high_risk_permissions: list[str] = Field(default_factory=list, alias="highRiskPermissions")


class GroupRoleAssignment(_Base):
    """Rola katalogowa przypisana DO grupy (role-assignable). Członkowie dziedziczą uprawnienie."""

    role_name: str = Field(alias="roleName")
    role_template_id: str | None = Field(default=None, alias="roleTemplateId")
    assignment_type: AssignmentType = Field(default="permanent", alias="assignmentType")
    is_privileged: bool = Field(alias="isPrivileged")


PrincipalType = Literal["user", "group", "servicePrincipal", "device", "other"]
AssignedVia = Literal["assignment", "consent"]


class PrincipalRef(_Base):
    """Członek grupy lub podmiot podpięty do aplikacji."""

    id: str | None = None
    display_name: str = Field(alias="displayName")
    user_principal_name: str | None = Field(default=None, alias="userPrincipalName")
    type: PrincipalType = "user"


class AssignedPrincipal(_Base):
    id: str | None = None
    display_name: str = Field(alias="displayName")
    user_principal_name: str | None = Field(default=None, alias="userPrincipalName")
    type: PrincipalType = "user"
    via: AssignedVia


class Group(_Base):
    id: str
    display_name: str = Field(alias="displayName")
    description: str | None = None
    mail: str | None = None
    group_kind: GroupKind = Field(alias="groupKind")
    mail_enabled: bool | None = Field(default=None, alias="mailEnabled")
    security_enabled: bool | None = Field(default=None, alias="securityEnabled")
    membership_type: MembershipType = Field(default="assigned", alias="membershipType")
    membership_rule: str | None = Field(default=None, alias="membershipRule")
    visibility: str | None = None
    is_assignable_to_role: bool | None = Field(default=None, alias="isAssignableToRole")
    on_premises_sync_enabled: bool | None = Field(default=None, alias="onPremisesSyncEnabled")
    created_date_time: datetime = Field(alias="createdDateTime")
    renewed_date_time: datetime | None = Field(default=None, alias="renewedDateTime")
    member_count: int | None = Field(default=None, alias="memberCount")
    guest_count: int | None = Field(default=None, alias="guestCount")
    owner_count: int | None = Field(default=None, alias="ownerCount")
    owners: list[str] = Field(default_factory=list)
    assigned_roles: list[GroupRoleAssignment] = Field(default_factory=list, alias="assignedRoles")
    assigned_licenses: list[str] = Field(default_factory=list, alias="assignedLicenses")
    members: list[PrincipalRef] = Field(default_factory=list)

    # --- pola wzbogacane przez scoring ---
    review_score: int = 0
    severity: Severity = "info"
    flags: list["ReviewFlag"] = Field(default_factory=list)

    @property
    def has_privileged_role(self) -> bool:
        return any(r.is_privileged for r in self.assigned_roles)

    @property
    def grants_access(self) -> bool:
        """Czy grupa realnie nadaje dostęp (role, licencje albo bezpieczeństwo)."""
        return bool(self.assigned_roles or self.assigned_licenses or self.security_enabled)


class AppCredential(_Base):
    kind: CredentialKind
    display_name: str | None = Field(default=None, alias="displayName")
    start_date_time: datetime | None = Field(default=None, alias="startDateTime")
    end_date_time: datetime | None = Field(default=None, alias="endDateTime")
    days_to_expiry: int | None = Field(default=None, alias="daysToExpiry")
    expired: bool = False
    lifetime_days: int | None = Field(default=None, alias="lifetimeDays")


class AppPermissionGrant(_Base):
    resource: str | None = None
    permission: str
    grant_type: AppGrantType = Field(alias="grantType")
    is_high_risk: bool = Field(alias="isHighRisk")


class CredentialEvent(_Base):
    """Zdarzenie na poświadczeniach aplikacji z auditu ApplicationManagement (1.3):
    kto i kiedy dodał/zmienił sekret lub certyfikat."""

    activity: str
    actor: str | None = None
    activity_date_time: datetime = Field(alias="activityDateTime")


class Application(_Base):
    id: str
    app_id: str | None = Field(default=None, alias="appId")
    display_name: str = Field(alias="displayName")
    description: str | None = None
    sign_in_audience: str | None = Field(default=None, alias="signInAudience")
    publisher_domain: str | None = Field(default=None, alias="publisherDomain")
    verified_publisher: str | None = Field(default=None, alias="verifiedPublisher")
    account_enabled: bool | None = Field(default=None, alias="accountEnabled")
    created_date_time: datetime | None = Field(default=None, alias="createdDateTime")
    last_sign_in_date_time: datetime | None = Field(default=None, alias="lastSignInDateTime")
    owners: list[str] = Field(default_factory=list)
    credentials: list[AppCredential] = Field(default_factory=list)
    permissions: list[AppPermissionGrant] = Field(default_factory=list)
    assigned_users: list[AssignedPrincipal] = Field(default_factory=list, alias="assignedUsers")
    credential_events: list[CredentialEvent] = Field(
        default_factory=list, alias="credentialEvents"
    )

    # --- pola wzbogacane przez scoring ---
    review_score: int = 0
    severity: Severity = "info"
    flags: list["ReviewFlag"] = Field(default_factory=list)

    @property
    def is_multi_tenant(self) -> bool:
        return self.sign_in_audience in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount")

    @property
    def app_permissions(self) -> list[AppPermissionGrant]:
        return [p for p in self.permissions if p.grant_type == "application"]

    @property
    def high_risk_permissions(self) -> list[AppPermissionGrant]:
        return [p for p in self.permissions if p.is_high_risk]

    @property
    def high_risk_app_permissions(self) -> list[AppPermissionGrant]:
        """Uprawnienia APP-ONLY (działają bez użytkownika) oznaczone jako high-risk — to one
        czynią z aplikacji 'klucz do tenanta'. Delegowane high-risk (wymagają zalogowanego
        użytkownika) zostają w high_risk_permissions, ale reguły o semantyce app-only
        (dormant / weak owner / ocena ryzyka aplikacji) używają TEGO, węższego zbioru."""
        return [p for p in self.permissions if p.is_high_risk and p.grant_type == "application"]

    @property
    def secrets(self) -> list[AppCredential]:
        return [c for c in self.credentials if c.kind == "secret"]


class CaPolicy(_Base):
    """Znormalizowana polityka Conditional Access (1.3). Booleany requiresMfa /
    blocksLegacyAuth liczy skaner — tu tylko czytamy. Wykluczenia to surowe id
    (rozwiązywane przez CorrelationIndex)."""

    id: str
    display_name: str = Field(alias="displayName")
    state: str
    requires_mfa: bool = Field(default=False, alias="requiresMfa")
    blocks_legacy_auth: bool = Field(default=False, alias="blocksLegacyAuth")
    client_app_types: list[str] = Field(default_factory=list, alias="clientAppTypes")
    include_users: list[str] = Field(default_factory=list, alias="includeUsers")
    exclude_users: list[str] = Field(default_factory=list, alias="excludeUsers")
    include_groups: list[str] = Field(default_factory=list, alias="includeGroups")
    exclude_groups: list[str] = Field(default_factory=list, alias="excludeGroups")
    include_roles: list[str] = Field(default_factory=list, alias="includeRoles")
    exclude_roles: list[str] = Field(default_factory=list, alias="excludeRoles")
    include_applications: list[str] = Field(default_factory=list, alias="includeApplications")
    exclude_applications: list[str] = Field(default_factory=list, alias="excludeApplications")
    grant_controls: list[str] = Field(default_factory=list, alias="grantControls")
    modified_date_time: datetime | None = Field(default=None, alias="modifiedDateTime")

    @property
    def enabled(self) -> bool:
        return self.state == "enabled"

    @property
    def report_only(self) -> bool:
        return self.state == "enabledForReportingButNotEnforced"

    @property
    def covers_all_users(self) -> bool:
        """Polityka celuje we WSZYSTKICH użytkowników (includeUsers zawiera 'All')."""
        return "All" in self.include_users

    @property
    def covers_all_apps(self) -> bool:
        """Wszystkie aplikacje. Pusta lista = brak danych o zakresie (stary dataset / skaner
        bez 1.4) — zachowawczo traktujemy jak 'All', żeby nie generować fałszywych alarmów."""
        return (not self.include_applications) or ("All" in self.include_applications)

    @property
    def is_broad(self) -> bool:
        """Szeroki zasięg = wszyscy użytkownicy i wszystkie aplikacje. Tylko taka włączona
        polityka MFA realnie 'pokrywa tenant'; wąska (jedna aplikacja / grupa pilotażowa) NIE
        — i nie powinna wyciszać krytycznego findingu o braku wymuszenia MFA."""
        return self.covers_all_users and self.covers_all_apps


class TenantPolicies(_Base):
    """Postawa konfiguracyjna tenanta (1.3). None w polu = nie udało się odczytać."""

    security_defaults_enabled: bool | None = Field(
        default=None, alias="securityDefaultsEnabled"
    )
    users_can_consent_to_apps: bool | None = Field(default=None, alias="usersCanConsentToApps")
    users_can_register_apps: bool | None = Field(default=None, alias="usersCanRegisterApps")
    guest_user_access: str | None = Field(default=None, alias="guestUserAccess")
    weak_auth_methods_enabled: list[str] = Field(
        default_factory=list, alias="weakAuthMethodsEnabled"
    )


class Dataset(_Base):
    schema_version: str = Field(alias="schemaVersion")
    generated_at: datetime = Field(alias="generatedAt")
    tenant: Tenant
    scan_context: ScanContext = Field(alias="scanContext")
    accounts: list[Account]
    service_principals: list[ServicePrincipal] = Field(
        default_factory=list, alias="servicePrincipals"
    )
    subscribed_skus: list[SubscribedSku] = Field(default_factory=list, alias="subscribedSkus")
    groups: list[Group] = Field(default_factory=list)
    applications: list[Application] = Field(default_factory=list)
    ca_policies: list[CaPolicy] = Field(default_factory=list, alias="caPolicies")
    tenant_policies: TenantPolicies | None = Field(default=None, alias="tenantPolicies")


class ReviewFlag(_Base):
    code: str
    title: str
    severity: Severity
    points: int
    evidence: str
    recommendation: str


Account.model_rebuild()
Group.model_rebuild()
Application.model_rebuild()
