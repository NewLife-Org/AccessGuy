#Requires -Version 7.0
<#
    AccessGuy Scanner — Collectors.ps1
    Każdy kolektor zwraca SUROWE obiekty Graph. Normalizacja do kontraktu dzieje się w Build-AgDataset.
    Kolektory są odporne na brak scope'a: łapią błąd, dopisują do $Warnings i zwracają pustą kolekcję.

    Mapowanie uprawnień -> patrz docs/PERMISSIONS.md.
#>

function Invoke-AgCollector {
    # Wrapper: wykonuje scriptblock, a przy błędzie dopisuje warning i zwraca @() zamiast wywalać skan.
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [scriptblock]$Body,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings
    )
    try {
        Write-AgLog -Level INFO -Message "Kolektor: $Name ..."
        return & $Body
    }
    catch {
        $msg = "Kolektor '$Name' nieudany: $($_.Exception.Message)"
        Write-AgLog -Level WARN -Message $msg
        $Warnings.Add($msg)
        return @()
    }
}

function Get-AgUsers {
    param([switch]$PremiumLicense, [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'users' -Warnings $Warnings -Body {
        # Beta: signInActivity (P1/P2) + manager przez $expand (jedno przejście, bez N+1).
        $props = @('id','displayName','userPrincipalName','mail','userType','accountEnabled',
                   'createdDateTime','onPremisesSyncEnabled','externalUserState',
                   'externalUserStateChangeDateTime','assignedLicenses','lastPasswordChangeDateTime')
        if ($PremiumLicense) { $props += 'signInActivity' }
        $select = $props -join ','
        $uri = "/users?`$select=$select&`$expand=manager(`$select=id,displayName,userPrincipalName)&`$top=999"
        Invoke-AgGraphPaged -Uri $uri -Beta
    }
}

function Get-AgRoles {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'roles' -Warnings $Warnings -Body {
        # Kilka źródeł -> jeden strumień. Każdy element tagujemy syntetycznym '__agType'
        # (active/eligible/permanent); deduplikację per (principal, rola, typ) robi Build-AgDataset.
        # Wszystko read-only (RoleManagement.Read.All); historię aktywacji bierzemy z auditu.
        #
        # WAŻNE (fix "Bad Request -> roles"): KAŻDE źródło ma własny try/catch.
        # Endpointy PIM (roleAssignmentSchedules / roleEligibilitySchedules) zwracają
        # 400/403 w tenantach BEZ Entra ID P2. Wcześniej jeden taki błąd wywracał cały
        # kolektor i nawet Global Admin nie widział żadnych ról. Teraz brak P2 = tylko
        # brak danych PIM; klasyczne aktywne role i tak złapie fallback /directoryRoles.
        $out = [System.Collections.Generic.List[object]]::new()

        # UWAGA: NIE rozszerzamy 'principal' — endpoint roleAssignments 400-uje na nim w wielu
        # tenantach ("Bad Request"). Wystarczy 'principalId' (czytany w Build-AgDataset) + rozwinięty
        # roleDefinition (nazwa roli). To usuwa błąd "źródło ról 'permanent' niedostępne".
        $sources = @(
            @{ Type = 'permanent'; Uri = '/roleManagement/directory/roleAssignments?$expand=roleDefinition'; Optional = $false }
            @{ Type = 'active';    Uri = '/roleManagement/directory/roleAssignmentSchedules?$expand=roleDefinition'; Optional = $true }
            @{ Type = 'eligible';  Uri = '/roleManagement/directory/roleEligibilitySchedules?$expand=roleDefinition'; Optional = $true }
        )
        $gotUnified = $false
        foreach ($s in $sources) {
            try {
                foreach ($item in @(Invoke-AgGraphPaged -Uri $s.Uri)) {
                    if ($item -is [System.Collections.IDictionary]) { $item['__agType'] = $s.Type }
                    $out.Add($item)
                    $gotUnified = $true
                }
            }
            catch {
                $msg = "Źródło ról '$($s.Type)' niedostępne ($($_.Exception.Message))"
                if ($s.Optional) {
                    $msg += ' — prawdopodobnie brak Entra ID P2 (PIM). Pomijam, używam klasycznych directoryRoles.'
                }
                Write-AgLog -Level WARN -Message $msg
                $Warnings.Add("roles/$($s.Type): $msg")
            }
        }

        # FALLBACK / baseline: klasyczne katalogowe role + ich członkowie.
        # Działa BEZ P2, rzadko zwraca 400 i gwarantuje, że aktywne przypisania
        # (np. Global Administrator) zawsze trafią do datasetu. Normalizujemy do tego
        # samego kształtu co wyżej (principal + roleDefinition + __agType), żeby
        # Build-AgDataset nie musiał znać dwóch formatów (deduplikacja zrobi resztę).
        try {
            foreach ($role in @(Invoke-AgGraphPaged -Uri '/directoryRoles?$expand=members')) {
                $roleName = [string](Get-AgProp $role 'displayName')
                $templ    = [string](Get-AgProp $role 'roleTemplateId')
                foreach ($m in @(Get-AgProp $role 'members')) {
                    $mid = [string](Get-AgProp $m 'id')
                    if (-not $mid) { continue }
                    $out.Add(@{
                        '__agType'     = 'active'
                        principal      = @{
                            id                = $mid
                            displayName       = [string](Get-AgProp $m 'displayName')
                            userPrincipalName = [string](Get-AgProp $m 'userPrincipalName')
                        }
                        roleDefinition = @{ displayName = $roleName; templateId = $templ }
                    })
                }
            }
        }
        catch {
            $msg = "Fallback directoryRoles nieudany: $($_.Exception.Message)"
            Write-AgLog -Level WARN -Message $msg
            $Warnings.Add("roles/directoryRoles: $msg")
            if (-not $gotUnified) { throw }   # nic nie zebraliśmy — niech wrapper dopisze twardy warning
        }

        $out.ToArray()
    }
}

function Get-AgGroups {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings,
        [int]$CountCap = 3000,
        [int]$MemberCap = 200
    )
    Invoke-AgCollector -Name 'groups' -Warnings $Warnings -Body {
        # Inwentarz grup + właściciele (expand) + licencje grupowe + flagi governance.
        # role-assignable / dynamic / visibility / onPrem zbieramy wprost z /groups.
        # Role NADANE grupie liczymy w Build-AgDataset z kolektora ról (principalId == groupId).
        $select = 'id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,visibility,' +
                  'isAssignableToRole,membershipRule,onPremisesSyncEnabled,createdDateTime,renewedDateTime,assignedLicenses'
        $uri = "/groups?`$select=$select&`$expand=owners(`$select=id,displayName,userPrincipalName)&`$top=999"
        $groups = @(Invoke-AgGraphPaged -Uri $uri)

        # Liczność (exact, $count z ConsistencyLevel: eventual) + KONKRETNI członkowie (lista do MemberCap).
        # To N zapytań, więc powyżej CountCap odpuszczamy (oszczędzamy Graph w wielkich tenantach).
        if ($groups.Count -le $CountCap) {
            foreach ($g in $groups) {
                $id = [string](Get-AgProp $g 'id')
                if (-not $id -or -not ($g -is [System.Collections.IDictionary])) { continue }
                $g['__memberCount'] = Get-AgCount -Uri "/groups/$id/members/`$count"
                $g['__guestCount']  = Get-AgCount -Uri "/groups/$id/members/microsoft.graph.user/`$count?`$filter=userType eq 'Guest'"
                # Konkretni członkowie (do MemberCap) — userType pozwala odróżnić gości; @odata.type rodzaj principala.
                $g['__members'] = @(Invoke-AgGraphPaged -Uri "/groups/$id/members?`$select=id,displayName,userPrincipalName,userType&`$top=999" -MaxItems $MemberCap)
            }
        }
        else {
            $Warnings.Add(("groups: pominięto liczność i członków (>{0} grup) — memberCount/guestCount/members będą puste." -f $CountCap))
        }
        $groups
    }
}

function Get-AgApps {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'apps' -Warnings $Warnings -Body {
        # Trzy źródła sklejane w Build-AgDataset:
        #  - servicePrincipals: id/appId/nazwa/stan + appRoles (mapowanie GUID->nazwa uprawnienia)
        #    + appRoleAssignments (uprawnienia APLIKACYJNE nadane aplikacji) przez $expand.
        #  - oauth2PermissionGrants: zgody DELEGOWANE (per scope).
        #  - applications: rejestracje (tenant-owned) + właściciele + poświadczenia (sekrety/certy).
        # appRoleAssignments = uprawnienia NADANE aplikacji; appRoleAssignedTo = podmioty PRZYPISANE do aplikacji
        # (kto z niej korzysta). Łańcuch fallbacków: oba -> tylko uprawnienia -> bez expandów.
        $spSelect = 'id,appId,displayName,accountEnabled,servicePrincipalType,appRoles'
        $sps = @()
        try {
            $sps = @(Invoke-AgGraphPaged -Uri "/servicePrincipals?`$select=$spSelect&`$expand=appRoleAssignments,appRoleAssignedTo&`$top=999")
        }
        catch {
            $Warnings.Add("apps/servicePrincipals: expand appRoleAssignments,appRoleAssignedTo nieudany ($($_.Exception.Message)) — próbuję węziej.")
            try {
                $sps = @(Invoke-AgGraphPaged -Uri "/servicePrincipals?`$select=$spSelect&`$expand=appRoleAssignments&`$top=999")
            }
            catch {
                $Warnings.Add("apps/servicePrincipals: expand nieudany — uprawnienia i przypisania pominięte.")
                $sps = @(Invoke-AgGraphPaged -Uri "/servicePrincipals?`$select=$spSelect&`$top=999")
            }
        }

        $grants = @(Invoke-AgGraphPaged -Uri '/oauth2PermissionGrants?$top=999')

        $appSelect = 'id,appId,displayName,description,signInAudience,createdDateTime,verifiedPublisher,' +
                     'publisherDomain,passwordCredentials,keyCredentials'
        $applications = @()
        try {
            $applications = @(Invoke-AgGraphPaged -Uri "/applications?`$select=$appSelect&`$expand=owners(`$select=id,displayName,userPrincipalName)&`$top=999")
        }
        catch {
            $Warnings.Add("apps/applications: $($_.Exception.Message)")
        }

        [pscustomobject]@{ servicePrincipals = $sps; oauth2Grants = $grants; applications = $applications }
    }
}

function Get-AgAuthMethods {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'authMethods' -Warnings $Warnings -Body {
        # id == userId; mapowanie userId -> mfaRegistered robi Build-AgDataset (IsMfaRegistered).
        Invoke-AgGraphPaged -Uri '/reports/authenticationMethods/userRegistrationDetails?$top=999'
    }
}

function Get-AgSignIns {
    # Logi logowań z ostatnich $Days dni (czysty Graph, AuditLog.Read.All — to samo logowanie GA wystarcza).
    # Surowe wpisy; agregację per użytkownik (liczba, nocne 20-04, top-aplikacje, błędy, ryzyko) robi
    # Build-AgDataset, bo dopiero tam znamy generatedAt (determinizm okna). Wymaga P1/P2 po stronie tenanta.
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings,
        [int]$Days = 30
    )
    Invoke-AgCollector -Name 'signIns' -Warnings $Warnings -Body {
        $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $select = 'id,userId,appDisplayName,createdDateTime,status,riskState,riskLevelDuringSignIn,isInteractive,clientAppUsed'
        $uri = "/auditLogs/signIns?`$filter=createdDateTime ge $since&`$select=$select&`$top=1000"
        Invoke-AgGraphPaged -Uri $uri
    }
}

function Get-AgAudit {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'audit' -Warnings $Warnings -Body {
        # Surowe wpisy directoryAudits: RoleManagement (PIM — agregacja per principal w Build-AgDataset)
        # + ApplicationManagement (1.3: kto i kiedy dodał sekret/cert do aplikacji — credentialEvents).
        # Oba pod tym samym AuditLog.Read.All; rozdzielenie po 'category' robi Build-AgDataset.
        Invoke-AgGraphPaged -Uri "/auditLogs/directoryAudits?`$filter=category eq 'RoleManagement' or category eq 'ApplicationManagement'&`$top=999"
    }
}

function Get-AgSpSignIns {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'spSignIns' -Warnings $Warnings -Body {
        # 1.3: aktywność logowań SERVICE PRINCIPALI (beta) — wypełnia application.lastSignInDateTime.
        # Uśpiona aplikacja z uprawnieniami app-only high-risk = APP_DORMANT_PRIVILEGED w procesorze.
        # Ten sam AuditLog.Read.All co signIns; mapowanie appId -> data robi Build-AgDataset.
        Invoke-AgGraphPaged -Uri '/reports/servicePrincipalSignInActivities?$top=999' -Beta
    }
}

function Get-AgRiskyUsers {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'riskyUsers' -Warnings $Warnings -Body {
        # 1.3: BIEŻĄCY stan ryzyka kont z Identity Protection (IdentityRiskyUser.Read.All, P2).
        # Filtrujemy server-side do stanów NIEOBSŁUŻONYCH (atRisk/confirmedCompromised) —
        # remediated/dismissed to historia, nie finding. W tenantach bez P2 endpoint zwraca
        # 403/B2C błąd — wrapper dopisze warning i jedziemy dalej bez tych danych.
        Invoke-AgGraphPaged -Uri "/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'&`$top=500"
    }
}

function Get-AgCaPolicies {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    Invoke-AgCollector -Name 'caPolicies' -Warnings $Warnings -Body {
        # 1.3: polityki Conditional Access (Policy.Read.All). Surowe obiekty; normalizację
        # (requiresMfa / blocksLegacyAuth / wykluczenia) robi Build-AgDataset. To pozwala
        # procesorowi wykryć: brak blokady legacy, polityki report-only, konta WYKLUCZONE z MFA.
        Invoke-AgGraphPaged -Uri '/identity/conditionalAccess/policies'
    }
}

function Get-AgTenantPolicies {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [System.Collections.Generic.List[string]]$Warnings)
    # 1.3: trzy pojedyncze GET-y postawy tenanta (Policy.Read.All). Każdy ma własny try/catch —
    # częściowy odczyt jest OK (pola, których nie udało się odczytać, zostają $null).
    $auth = $null; $secDefaults = $null; $authMethods = $null
    try { $auth = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -OutputType Hashtable -ErrorAction Stop }
    catch { $Warnings.Add("tenantPolicies/authorizationPolicy: $($_.Exception.Message)") }
    try { $secDefaults = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy' -OutputType Hashtable -ErrorAction Stop }
    catch { $Warnings.Add("tenantPolicies/securityDefaults: $($_.Exception.Message)") }
    try { $authMethods = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy' -OutputType Hashtable -ErrorAction Stop }
    catch { $Warnings.Add("tenantPolicies/authenticationMethodsPolicy: $($_.Exception.Message)") }
    if (-not $auth -and -not $secDefaults -and -not $authMethods) { return $null }
    [pscustomobject]@{ Authorization = $auth; SecurityDefaults = $secDefaults; AuthMethods = $authMethods }
}
