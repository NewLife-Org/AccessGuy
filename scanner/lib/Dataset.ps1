#Requires -Version 7.0
<#
    AccessGuy Scanner — Dataset.ps1
    Skleja surowe wyniki kolektorów w JEDEN obiekt zgodny z contracts/dataset.schema.json.
    To jedyne miejsce, które "zna" kontrakt po stronie PowerShell — trzymaj zgodność nazw pól ze schema.
#>

function Get-AgAccountCategory {
    # internal / external / guest na podstawie userType, UPN (#EXT#) i domen zweryfikowanych.
    param(
        [Parameter(Mandatory)] [string]$UserType,
        [Parameter(Mandatory)] [string]$Upn,
        [string[]]$VerifiedDomains
    )
    if ($UserType -eq 'Guest') { return 'guest' }
    $domain = ($Upn -split '@')[-1]
    if ($Upn -like '*#EXT#*' -or ($VerifiedDomains.Count -gt 0 -and $domain -notin $VerifiedDomains)) {
        return 'external'
    }
    return 'internal'
}

# --- Agregacja auditu RoleManagement per principal ---------------------------
# Z surowych directoryAudits wyciągamy per użytkownik: ostatnią aktywację PIM,
# liczbę aktywacji w oknie 90 dni względem $GeneratedAt (determinizm!) oraz datę
# ostatniego nadania roli. Heurystyka po activityDisplayName — best-effort.
function Get-AgAuditAggregate {
    param($Audit, [Parameter(Mandatory)] [datetime]$GeneratedAt)
    $map = @{}
    $windowStart = $GeneratedAt.AddDays(-90)
    foreach ($rec in @($Audit)) {
        $activity = [string](Get-AgProp $rec 'activityDisplayName')
        $whenIso  = ConvertTo-AgIso (Get-AgProp $rec 'activityDateTime')
        if (-not $whenIso) { continue }
        $when = [datetimeoffset]::Parse($whenIso).UtcDateTime
        $isActivation = $activity -match '(?i)activat'                      # "Add member to role completed (PIM activation)"
        $isGrant      = $activity -match '(?i)add member to role(?!.*activat)'  # nadanie (nie aktywacja)

        foreach ($t in @(Get-AgProp $rec 'targetResources')) {
            $type = [string](Get-AgProp $t 'type')
            if ($type -and $type -ne 'User') { continue }   # interesują nas konta użytkowników
            $id = [string](Get-AgProp $t 'id')
            if (-not $id) { continue }
            if (-not $map.ContainsKey($id)) {
                $map[$id] = [pscustomobject]@{ LastActivation = $null; ActivationCount90d = 0; LastGrant = $null }
            }
            $e = $map[$id]
            if ($isActivation) {
                if (-not $e.LastActivation -or $when -gt [datetimeoffset]::Parse($e.LastActivation).UtcDateTime) { $e.LastActivation = $whenIso }
                if ($when -ge $windowStart) { $e.ActivationCount90d++ }
            }
            elseif ($isGrant) {
                if (-not $e.LastGrant -or $when -gt [datetimeoffset]::Parse($e.LastGrant).UtcDateTime) { $e.LastGrant = $whenIso }
            }
        }
    }
    return $map
}

# --- Agregacja logowań (signIns) per principal -------------------------------
# Z surowych /auditLogs/signIns liczymy per użytkownik w oknie $WindowDays:
# liczbę logowań, nieudane, nocne (20:00-04:00 UTC), ryzykowne, ostatnią aplikację
# i top-aplikacje. Wszystko względem $GeneratedAt (determinizm okna).
function Get-AgSignInAggregate {
    param($SignIns, [Parameter(Mandatory)] [datetime]$GeneratedAt, [int]$WindowDays = 30)
    $map = @{}
    $windowStart = $GeneratedAt.AddDays(-$WindowDays)
    foreach ($s in @($SignIns)) {
        $uid = [string](Get-AgProp $s 'userId')
        if (-not $uid) { continue }
        $whenIso = ConvertTo-AgIso (Get-AgProp $s 'createdDateTime')
        if (-not $whenIso) { continue }
        $when = [datetimeoffset]::Parse($whenIso).UtcDateTime
        if ($when -lt $windowStart) { continue }

        if (-not $map.ContainsKey($uid)) {
            $map[$uid] = [pscustomobject]@{
                SignInCount = 0; FailedCount = 0; NightCount = 0; RiskyCount = 0; LegacyCount = 0; LegacySuccess = 0
                LastWhen = $null; LastApp = $null; Apps = @{}; LegacyClients = @{}
            }
        }
        $e = $map[$uid]
        $e.SignInCount++

        # Status najpierw — potrzebny i do FailedCount, i do rozróżnienia legacy udane/zablokowane.
        $status = Get-AgProp $s 'status'
        $err = 0; try { $err = [int](Get-AgProp $status 'errorCode' 0) } catch { }
        if ($err -ne 0) { $e.FailedCount++ }

        # Legacy auth (omija MFA): wszystko poza klientami nowoczesnymi. Liczymy PER PROTOKÓŁ
        # (clientAppUsed) i osobno te UDANE (errorCode 0) — bo udane legacy = realne ominięcie MFA,
        # a zablokowane (np. przez Conditional Access) i tak figurują w logu, lecz nie są przejęciem.
        $clientApp = [string](Get-AgProp $s 'clientAppUsed')
        if ($clientApp -and $clientApp -notin @('Browser', 'Mobile Apps and Desktop clients')) {
            $e.LegacyCount++
            if ($err -eq 0) { $e.LegacySuccess++ }
            if (-not $e.LegacyClients.ContainsKey($clientApp)) { $e.LegacyClients[$clientApp] = [pscustomobject]@{ Count = 0; Success = 0 } }
            $e.LegacyClients[$clientApp].Count++
            if ($err -eq 0) { $e.LegacyClients[$clientApp].Success++ }
        }

        $hour = $when.Hour
        if ($hour -ge 20 -or $hour -lt 4) { $e.NightCount++ }

        $riskState = [string](Get-AgProp $s 'riskState')
        $riskLevel = [string](Get-AgProp $s 'riskLevelDuringSignIn')
        if (($riskState -and $riskState -notin @('none','dismissed','remediated')) -or ($riskLevel -and $riskLevel -notin @('none','hidden','unknownFutureValue'))) {
            $e.RiskyCount++
        }

        $app = [string](Get-AgProp $s 'appDisplayName')
        if ($app) {
            if (-not $e.Apps.ContainsKey($app)) { $e.Apps[$app] = 0 }
            $e.Apps[$app]++
        }
        if (-not $e.LastWhen -or $when -gt $e.LastWhen) { $e.LastWhen = $when; $e.LastApp = $app }
    }
    return $map
}

# --- Zdarzenia na poświadczeniach aplikacji (audit ApplicationManagement) ----
# Z wpisów category=ApplicationManagement wyciągamy te o sekretach/certach
# ("Update application – Certificates and secrets management", "Add service principal
# credentials" itp.) i mapujemy po id CELU (rejestracja LUB service principal) na listę
# zdarzeń {activity, actor, activityDateTime}. Dowód "kto dodał sekret" do raportu.
function Get-AgCredentialEventMap {
    param($Audit)
    $map = @{}
    foreach ($rec in @($Audit)) {
        if ([string](Get-AgProp $rec 'category') -ne 'ApplicationManagement') { continue }
        $activity = [string](Get-AgProp $rec 'activityDisplayName')
        if ($activity -notmatch '(?i)credential|certificates and secrets') { continue }
        $whenIso = ConvertTo-AgIso (Get-AgProp $rec 'activityDateTime')
        if (-not $whenIso) { continue }

        # initiatedBy: user (UPN) albo app (displayName) — kto wykonał operację.
        $by = Get-AgProp $rec 'initiatedBy'
        $actor = [string](Get-AgProp (Get-AgProp $by 'user') 'userPrincipalName')
        if (-not $actor) { $actor = [string](Get-AgProp (Get-AgProp $by 'app') 'displayName') }
        if (-not $actor) { $actor = $null }

        $event = [ordered]@{ activity = $activity; actor = $actor; activityDateTime = $whenIso }
        foreach ($t in @(Get-AgProp $rec 'targetResources')) {
            $tid = [string](Get-AgProp $t 'id')
            if (-not $tid) { continue }
            if (-not $map.ContainsKey($tid)) { $map[$tid] = [System.Collections.Generic.List[object]]::new() }
            $map[$tid].Add($event)
        }
    }
    return $map
}

function Build-AgDataset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ScannerVersion,
        [Parameter(Mandatory)] [string]$AuthMode,
        [string]$Operator,
        [bool]$PremiumLicense,
        [string[]]$VerifiedDomains,
        $Users, $Roles, $Apps, $Mfa, $Audit, $SignIns,
        $Groups,
        $RiskyUsers, $SpSignIns, $CaPolicies, $TenantPolicies,
        [int]$SignInWindowDays = 30,
        [string[]]$CollectorsRun,
        [System.Collections.Generic.List[string]]$Warnings
    )

    $generatedAt = (Get-Date).ToUniversalTime()
    $rubric  = Get-AgRubric
    $privSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$rubric.PrivilegedRoles, [System.StringComparer]::OrdinalIgnoreCase)
    $riskSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$rubric.HighRiskAppScopes, [System.StringComparer]::OrdinalIgnoreCase)
    $appRoleRiskSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$rubric.HighRiskAppRoles, [System.StringComparer]::OrdinalIgnoreCase)

    # --- Tożsamość tenanta (id + displayName + ewentualnie domeny) ----------
    $tenantId = ''; $tenantName = ''
    try { $tenantId = [string](Get-MgContext).TenantId } catch { }
    try {
        $org = @(Invoke-AgGraphPaged -Uri '/organization?$select=id,displayName,verifiedDomains')
        if ($org.Count -gt 0) {
            $tenantName = [string](Get-AgProp $org[0] 'displayName')
            if (-not $VerifiedDomains -or $VerifiedDomains.Count -eq 0) {
                $VerifiedDomains = @(@(Get-AgProp $org[0] 'verifiedDomains') | ForEach-Object { Get-AgProp $_ 'name' } | Where-Object { $_ })
            }
        }
    } catch { }

    # --- Mapy pomocnicze ----------------------------------------------------
    # SKU GUID -> partNumber (ładniejsze niż GUID) + inwentarz licencji tenanta
    # (prepaid/consumed) do sekcji "charakterystyka tenanta". 'Subskrypcje' = licencje M365.
    $skuMap = @{}
    $subscribedSkus = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($sku in @(Invoke-AgGraphPaged -Uri '/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits')) {
            $sid = [string](Get-AgProp $sku 'skuId'); $pn = [string](Get-AgProp $sku 'skuPartNumber')
            if ($sid) { $skuMap[$sid] = if ($pn) { $pn } else { $sid } }
            $prepaid = Get-AgProp $sku 'prepaidUnits'
            $subscribedSkus.Add([ordered]@{
                skuPartNumber = if ($pn) { $pn } else { $sid }
                skuId         = if ($sid) { $sid } else { $null }
                prepaidUnits  = [int](Get-AgProp $prepaid 'enabled' 0)
                consumedUnits = [int](Get-AgProp $sku 'consumedUnits' 0)
            })
        }
    } catch { }

    # userId -> mfaRegistered
    $mfaMap = @{}
    foreach ($m in @($Mfa)) {
        $uid = [string](Get-AgProp $m 'id')
        if ($uid) { $mfaMap[$uid] = [bool](Get-AgProp $m 'isMfaRegistered' $false) }
    }

    # id -> { Upn; Name } — do rozwiązywania principalId na czytelny UPN (członkowie aplikacji).
    $userIndex = @{}
    foreach ($u in @($Users)) {
        $uid = [string](Get-AgProp $u 'id')
        if ($uid) { $userIndex[$uid] = [pscustomobject]@{ Upn = [string](Get-AgProp $u 'userPrincipalName'); Name = [string](Get-AgProp $u 'displayName') } }
    }

    # @odata.type Graph -> krótki typ principala kontraktu.
    function script:Get-AgPrincipalType {
        param([string]$OdataType)
        switch -Wildcard ($OdataType) {
            '*user'             { 'user' }
            '*group'            { 'group' }
            '*servicePrincipal' { 'servicePrincipal' }
            '*device'           { 'device' }
            default             { 'other' }
        }
    }

    $auditMap = Get-AgAuditAggregate -Audit $Audit -GeneratedAt $generatedAt
    $signInMap = Get-AgSignInAggregate -SignIns $SignIns -GeneratedAt $generatedAt -WindowDays $SignInWindowDays
    $credEventMap = Get-AgCredentialEventMap -Audit $Audit

    # userId -> stan ryzyka Identity Protection (kolektor zwraca już tylko atRisk/confirmedCompromised).
    $riskyMap = @{}
    foreach ($ru in @($RiskyUsers)) {
        $uid = [string](Get-AgProp $ru 'id')
        if (-not $uid) { continue }
        $riskyMap[$uid] = [ordered]@{
            riskLevel                = [string](Get-AgProp $ru 'riskLevel' 'none')
            riskState                = [string](Get-AgProp $ru 'riskState' 'none')
            riskDetail               = if (Get-AgProp $ru 'riskDetail') { [string](Get-AgProp $ru 'riskDetail') } else { $null }
            riskLastUpdatedDateTime  = ConvertTo-AgIso (Get-AgProp $ru 'riskLastUpdatedDateTime')
        }
    }

    # appId -> ostatnie logowanie SP (beta servicePrincipalSignInActivities). Wypełnia
    # application.lastSignInDateTime — wcześniej zawsze null (TODO z iteracji 3).
    $spSignInMap = @{}
    foreach ($sa in @($SpSignIns)) {
        $aid = [string](Get-AgProp $sa 'appId')
        if (-not $aid) { continue }
        $last = ConvertTo-AgIso (Get-AgProp (Get-AgProp $sa 'lastSignInActivity') 'lastSignInDateTime')
        if (-not $last) { $last = ConvertTo-AgIso (Get-AgProp $sa 'lastSignInDateTime') }
        if ($last) { $spSignInMap[$aid] = $last }
    }

    # principalId -> lista ról (deduplikacja po roleName|assignmentType)
    $rolesByPrincipal = @{}
    foreach ($r in @($Roles)) {
        $principal = Get-AgProp $r 'principal'
        $prinId = [string](Get-AgProp $principal 'id')
        if (-not $prinId) { $prinId = [string](Get-AgProp $r 'principalId') }
        if (-not $prinId) { continue }
        $rd       = Get-AgProp $r 'roleDefinition'
        $roleName = [string](Get-AgProp $rd 'displayName')
        if (-not $roleName) { continue }
        $type = [string](Get-AgProp $r '__agType'); if (-not $type) { $type = 'permanent' }

        if (-not $rolesByPrincipal.ContainsKey($prinId)) { $rolesByPrincipal[$prinId] = [ordered]@{} }
        $dedupeKey = "$roleName|$type"
        if ($rolesByPrincipal[$prinId].Contains($dedupeKey)) { continue }
        $rolesByPrincipal[$prinId][$dedupeKey] = [pscustomobject]@{
            RoleName       = $roleName
            RoleTemplateId = [string](Get-AgProp $rd 'templateId')
            AssignmentType = $type
            GrantedDateTime = ConvertTo-AgIso (Get-AgProp $r 'createdDateTime')
        }
    }

    # principalId -> appGrants ; SP id -> displayName / wysokie ryzyko
    $grantsByPrincipal = @{}
    $spList   = @(Get-AgProp $Apps 'servicePrincipals')
    $grants   = @(Get-AgProp $Apps 'oauth2Grants')
    $spName   = @{}; foreach ($sp in $spList) { $id = [string](Get-AgProp $sp 'id'); if ($id) { $spName[$id] = [string](Get-AgProp $sp 'displayName') } }
    $spHighRisk = @{}   # SP id -> [set] wysokoryzykownych scope'ów (delegated)
    foreach ($g in $grants) {
        $prinId = [string](Get-AgProp $g 'principalId')      # pusty => admin consent tenant-wide (nie atrybuujemy do konta)
        $clientId = [string](Get-AgProp $g 'clientId')
        $scopeStr = [string](Get-AgProp $g 'scope')
        $scopes = @($scopeStr -split '\s+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $high = @($scopes | Where-Object { $riskSet.Contains($_) })
        if ($high.Count -gt 0 -and $clientId) {
            if (-not $spHighRisk.ContainsKey($clientId)) { $spHighRisk[$clientId] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
            foreach ($h in $high) { [void]$spHighRisk[$clientId].Add($h) }
        }
        if (-not $prinId) { continue }
        if (-not $grantsByPrincipal.ContainsKey($prinId)) { $grantsByPrincipal[$prinId] = [System.Collections.Generic.List[object]]::new() }
        $appName = if ($clientId -and $spName.ContainsKey($clientId)) { $spName[$clientId] } else { $clientId }
        $grantsByPrincipal[$prinId].Add([ordered]@{
            appDisplayName = [string]$appName
            grantType      = 'delegated'
            scopes         = @($scopes)
            isHighRisk     = [bool]($high.Count -gt 0)
        })
    }

    # --- Konta --------------------------------------------------------------
    $accounts = [System.Collections.Generic.List[object]]::new()
    foreach ($u in @($Users)) {
        $id  = [string](Get-AgProp $u 'id')
        $upn = [string](Get-AgProp $u 'userPrincipalName')
        $userType = [string](Get-AgProp $u 'userType'); if (-not $userType) { $userType = 'Member' }
        $category = Get-AgAccountCategory -UserType $userType -Upn $upn -VerifiedDomains $VerifiedDomains

        $sia = Get-AgProp $u 'signInActivity'
        $licenses = @(@(Get-AgProp $u 'assignedLicenses') | ForEach-Object {
            $sid = [string](Get-AgProp $_ 'skuId')
            if ($sid -and $skuMap.ContainsKey($sid)) { $skuMap[$sid] } elseif ($sid) { $sid }
        } | Where-Object { $_ })

        $mgr = Get-AgProp $u 'manager'
        $managerVal = $null
        if ($mgr) { $managerVal = [string](Get-AgProp $mgr 'userPrincipalName'); if (-not $managerVal) { $managerVal = [string](Get-AgProp $mgr 'displayName') } }
        if ([string]::IsNullOrEmpty($managerVal)) { $managerVal = $null }

        $mfaReg = $null
        if ($mfaMap.ContainsKey($id)) { $mfaReg = $mfaMap[$id] }

        # role konta + wzbogacenie auditem
        $aud = if ($auditMap.ContainsKey($id)) { $auditMap[$id] } else { $null }
        $roleObjs = @()
        if ($rolesByPrincipal.ContainsKey($id)) {
            $roleObjs = @($rolesByPrincipal[$id].Values | ForEach-Object {
                $granted = $_.GrantedDateTime
                if (-not $granted -and $aud) { $granted = $aud.LastGrant }
                [ordered]@{
                    roleName             = $_.RoleName
                    roleTemplateId       = if ($_.RoleTemplateId) { $_.RoleTemplateId } else { $null }
                    assignmentType       = $_.AssignmentType
                    isPrivileged         = [bool]$privSet.Contains($_.RoleName)
                    grantedDateTime      = $granted
                    lastActivationDateTime = if ($aud) { $aud.LastActivation } else { $null }
                    activationCount90d   = if ($aud) { [int]$aud.ActivationCount90d } else { 0 }
                }
            })
        }

        $appGrants = if ($grantsByPrincipal.ContainsKey($id)) { @($grantsByPrincipal[$id].ToArray()) } else { @() }

        # activity (1.1): agregat logowań z signIns. $null gdy brak danych dla konta.
        $activity = $null
        if ($signInMap.ContainsKey($id)) {
            $si = $signInMap[$id]
            $topApps = @($si.Apps.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5 | ForEach-Object {
                [ordered]@{ appDisplayName = [string]$_.Key; count = [int]$_.Value }
            })
            $legacyClients = @($si.LegacyClients.GetEnumerator() | Sort-Object -Property { $_.Value.Count } -Descending | ForEach-Object {
                [ordered]@{ clientApp = [string]$_.Key; count = [int]$_.Value.Count; successCount = [int]$_.Value.Success }
            })
            $activity = [ordered]@{
                windowDays         = $SignInWindowDays
                signInCount        = [int]$si.SignInCount
                failedSignInCount  = [int]$si.FailedCount
                nightSignInCount   = [int]$si.NightCount
                riskySignInCount   = [int]$si.RiskyCount
                legacyAuthCount    = [int]$si.LegacyCount
                legacySuccessCount = [int]$si.LegacySuccess
                legacyAuthClients  = @($legacyClients)
                lastSignInApp      = if ($si.LastApp) { [string]$si.LastApp } else { $null }
                topApplications    = @($topApps)
            }
        }

        $accounts.Add([ordered]@{
            id                = $id
            userPrincipalName = $upn
            displayName       = [string](Get-AgProp $u 'displayName')
            mail              = if (Get-AgProp $u 'mail') { [string](Get-AgProp $u 'mail') } else { $null }
            category          = $category
            accountEnabled    = [bool](Get-AgProp $u 'accountEnabled' $false)
            createdDateTime   = ConvertTo-AgIso (Get-AgProp $u 'createdDateTime')
            lastSignInDateTime = ConvertTo-AgIso (Get-AgProp $sia 'lastSignInDateTime')
            lastNonInteractiveSignInDateTime = ConvertTo-AgIso (Get-AgProp $sia 'lastNonInteractiveSignInDateTime')
            onPremisesSyncEnabled = $(if ($null -eq (Get-AgProp $u 'onPremisesSyncEnabled')) { $null } else { [bool](Get-AgProp $u 'onPremisesSyncEnabled') })
            externalUserState = if (Get-AgProp $u 'externalUserState') { [string](Get-AgProp $u 'externalUserState') } else { $null }
            externalUserStateChangeDateTime = ConvertTo-AgIso (Get-AgProp $u 'externalUserStateChangeDateTime')
            assignedLicenses  = @($licenses)
            mfaRegistered     = $mfaReg
            manager           = $managerVal
            lastPasswordChangeDateTime = ConvertTo-AgIso (Get-AgProp $u 'lastPasswordChangeDateTime')
            activity          = $activity
            roles             = @($roleObjs)
            appGrants         = @($appGrants)
            riskyUser         = if ($riskyMap.ContainsKey($id)) { $riskyMap[$id] } else { $null }
        })
    }

    # --- Inwentarz Service Principals --------------------------------------
    $spOut = [System.Collections.Generic.List[object]]::new()
    foreach ($sp in $spList) {
        $spId = [string](Get-AgProp $sp 'id')
        $hr = @()
        if ($spId -and $spHighRisk.ContainsKey($spId)) { $hr = @($spHighRisk[$spId]) }
        $spOut.Add([ordered]@{
            id                 = $spId
            displayName        = [string](Get-AgProp $sp 'displayName')
            appId              = if (Get-AgProp $sp 'appId') { [string](Get-AgProp $sp 'appId') } else { $null }
            accountEnabled     = $(if ($null -eq (Get-AgProp $sp 'accountEnabled')) { $null } else { [bool](Get-AgProp $sp 'accountEnabled') })
            appRoleAssignments = @()
            highRiskPermissions = @($hr)
        })
    }

    # --- Moduł GRUPY (1.2) --------------------------------------------------
    # Role NADANE grupie czytamy z tej samej mapy co dla kont (rolesByPrincipal[groupId]) —
    # role-assignable group jest principalem w roleAssignments. Stąd reużywamy wynik kolektora ról.
    $groupsOut = [System.Collections.Generic.List[object]]::new()
    foreach ($g in @($Groups)) {
        $gid = [string](Get-AgProp $g 'id')
        if (-not $gid) { continue }
        $groupTypes      = @(Get-AgProp $g 'groupTypes')
        $mailEnabled     = Get-AgProp $g 'mailEnabled'
        $securityEnabled = Get-AgProp $g 'securityEnabled'
        $isDynamic       = ($groupTypes -contains 'DynamicMembership')
        $isUnified       = ($groupTypes -contains 'Unified')
        $kind = if ($isUnified) { 'microsoft365' }
                elseif (($securityEnabled -eq $true) -and ($mailEnabled -eq $true)) { 'mailSecurity' }
                elseif ($securityEnabled -eq $true) { 'security' }
                else { 'distribution' }

        $gOwners = @(@(Get-AgProp $g 'owners') | ForEach-Object {
            $o = [string](Get-AgProp $_ 'userPrincipalName'); if (-not $o) { $o = [string](Get-AgProp $_ 'displayName') }; $o
        } | Where-Object { $_ })

        $gLic = @(@(Get-AgProp $g 'assignedLicenses') | ForEach-Object {
            $sid = [string](Get-AgProp $_ 'skuId')
            if ($sid -and $skuMap.ContainsKey($sid)) { $skuMap[$sid] } elseif ($sid) { $sid }
        } | Where-Object { $_ })

        $gRoles = @()
        if ($rolesByPrincipal.ContainsKey($gid)) {
            $gRoles = @($rolesByPrincipal[$gid].Values | ForEach-Object {
                [ordered]@{
                    roleName       = $_.RoleName
                    roleTemplateId = if ($_.RoleTemplateId) { $_.RoleTemplateId } else { $null }
                    assignmentType = $_.AssignmentType
                    isPrivileged   = [bool]$privSet.Contains($_.RoleName)
                }
            })
        }

        $mc = Get-AgProp $g '__memberCount'
        $gc = Get-AgProp $g '__guestCount'
        $created = ConvertTo-AgIso (Get-AgProp $g 'createdDateTime')
        if (-not $created) { $created = $generatedAt.ToString('o') }   # schema wymaga createdDateTime

        # Konkretni członkowie (do MemberCap) — czytelna lista do raportu.
        $gMembers = @(@(Get-AgProp $g '__members') | ForEach-Object {
            $upn = [string](Get-AgProp $_ 'userPrincipalName')
            $mid = [string](Get-AgProp $_ 'id')
            [ordered]@{
                id                = if ($mid) { $mid } else { $null }
                displayName       = [string](Get-AgProp $_ 'displayName')
                userPrincipalName = if ($upn) { $upn } else { $null }
                type              = Get-AgPrincipalType ([string](Get-AgProp $_ '@odata.type'))
            }
        })

        $groupsOut.Add([ordered]@{
            id                    = $gid
            displayName           = [string](Get-AgProp $g 'displayName')
            description           = if (Get-AgProp $g 'description') { [string](Get-AgProp $g 'description') } else { $null }
            mail                  = if (Get-AgProp $g 'mail') { [string](Get-AgProp $g 'mail') } else { $null }
            groupKind             = $kind
            mailEnabled           = $(if ($null -eq $mailEnabled) { $null } else { [bool]$mailEnabled })
            securityEnabled       = $(if ($null -eq $securityEnabled) { $null } else { [bool]$securityEnabled })
            membershipType        = if ($isDynamic) { 'dynamic' } else { 'assigned' }
            membershipRule        = if (Get-AgProp $g 'membershipRule') { [string](Get-AgProp $g 'membershipRule') } else { $null }
            visibility            = if (Get-AgProp $g 'visibility') { [string](Get-AgProp $g 'visibility') } else { $null }
            isAssignableToRole    = $(if ($null -eq (Get-AgProp $g 'isAssignableToRole')) { $null } else { [bool](Get-AgProp $g 'isAssignableToRole') })
            onPremisesSyncEnabled = $(if ($null -eq (Get-AgProp $g 'onPremisesSyncEnabled')) { $null } else { [bool](Get-AgProp $g 'onPremisesSyncEnabled') })
            createdDateTime       = $created
            renewedDateTime       = ConvertTo-AgIso (Get-AgProp $g 'renewedDateTime')
            memberCount           = $(if ($null -eq $mc) { $null } else { [int]$mc })
            guestCount            = $(if ($null -eq $gc) { $null } else { [int]$gc })
            ownerCount            = $gOwners.Count
            owners                = @($gOwners)
            assignedRoles         = @($gRoles)
            assignedLicenses      = @($gLic)
            members               = @($gMembers)
        })
    }

    # --- Moduł APLIKACJE (1.2) ---------------------------------------------
    # Mapy pomocnicze: SP po id/appId oraz appRoles (GUID uprawnienia -> czytelna nazwa 'value').
    $spById = @{}; $spByAppId = @{}; $appRolesByRes = @{}
    foreach ($sp in $spList) {
        $sid = [string](Get-AgProp $sp 'id'); $said = [string](Get-AgProp $sp 'appId')
        if ($sid)  { $spById[$sid] = $sp }
        if ($said) { $spByAppId[$said] = $sp }
        $rmap = @{}
        foreach ($ar in @(Get-AgProp $sp 'appRoles')) {
            $arid = [string](Get-AgProp $ar 'id'); $arval = [string](Get-AgProp $ar 'value')
            if ($arid) { $rmap[$arid] = $arval }
        }
        if ($sid) { $appRolesByRes[$sid] = $rmap }
    }

    # Scope'y delegowane per SP (clientId) — niezależnie od principala (zgoda admin/tenant-wide też się liczy).
    # Równolegle: którzy KONKRETNI użytkownicy wyrazili zgodę (principalId != null) — do listy "podpięci do aplikacji".
    $delegatedBySp = @{}
    $consentUsersBySp = @{}
    foreach ($gr in $grants) {
        $cid = [string](Get-AgProp $gr 'clientId'); if (-not $cid) { continue }
        $sc = @(([string](Get-AgProp $gr 'scope')) -split '\s+' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if (-not $delegatedBySp.ContainsKey($cid)) { $delegatedBySp[$cid] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
        foreach ($s in $sc) { [void]$delegatedBySp[$cid].Add($s) }
        $pid2 = [string](Get-AgProp $gr 'principalId')
        if ($pid2) {
            if (-not $consentUsersBySp.ContainsKey($cid)) { $consentUsersBySp[$cid] = [System.Collections.Generic.HashSet[string]]::new() }
            [void]$consentUsersBySp[$cid].Add($pid2)
        }
    }

    # Składanie listy podmiotów podpiętych do aplikacji: przypisani (appRoleAssignedTo) + ci, co dali zgodę.
    $resolveAssigned = {
        param($sp)
        $out = [System.Collections.Generic.List[object]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        if (-not $sp) { return $out }
        foreach ($a in @(Get-AgProp $sp 'appRoleAssignedTo')) {
            $pid3 = [string](Get-AgProp $a 'principalId')
            $key = "assign|$pid3"
            if ($pid3 -and -not $seen.Add($key)) { continue }
            $ptypeRaw = [string](Get-AgProp $a 'principalType')
            $ptype = switch ($ptypeRaw) { 'User' { 'user' } 'Group' { 'group' } 'ServicePrincipal' { 'servicePrincipal' } default { 'other' } }
            $name = [string](Get-AgProp $a 'principalDisplayName')
            $upn = $null
            if ($ptype -eq 'user' -and $pid3 -and $userIndex.ContainsKey($pid3)) {
                if (-not $name) { $name = $userIndex[$pid3].Name }
                $upn = $userIndex[$pid3].Upn
            }
            $out.Add([ordered]@{ id = if ($pid3) { $pid3 } else { $null }; displayName = if ($name) { $name } else { $pid3 }; userPrincipalName = $upn; type = $ptype; via = 'assignment' })
        }
        $spid = [string](Get-AgProp $sp 'id')
        if ($spid -and $consentUsersBySp.ContainsKey($spid)) {
            foreach ($pid4 in $consentUsersBySp[$spid]) {
                if (-not $seen.Add("consent|$pid4")) { continue }
                $name = $pid4; $upn = $null
                if ($userIndex.ContainsKey($pid4)) { $name = $userIndex[$pid4].Name; $upn = $userIndex[$pid4].Upn }
                $out.Add([ordered]@{ id = $pid4; displayName = $name; userPrincipalName = $upn; type = 'user'; via = 'consent' })
            }
        }
        return $out
    }

    # Złożenie uprawnień (app-only + delegated) dla danego SP. Scriptblock czyta zmienne rodzica.
    $resolvePerms = {
        param($sp)
        $perms = [System.Collections.Generic.List[object]]::new()
        if (-not $sp) { return $perms }
        foreach ($asg in @(Get-AgProp $sp 'appRoleAssignments')) {
            $resId   = [string](Get-AgProp $asg 'resourceId')
            $resName = [string](Get-AgProp $asg 'resourceDisplayName')
            $arId    = [string](Get-AgProp $asg 'appRoleId')
            $permVal = $null
            if ($resId -and $appRolesByRes.ContainsKey($resId)) { $permVal = $appRolesByRes[$resId][$arId] }
            if (-not $permVal) { $permVal = $arId }
            $perms.Add([ordered]@{
                resource   = if ($resName) { $resName } else { $null }
                permission = [string]$permVal
                grantType  = 'application'
                isHighRisk = [bool]$appRoleRiskSet.Contains([string]$permVal)
            })
        }
        $spid = [string](Get-AgProp $sp 'id')
        if ($spid -and $delegatedBySp.ContainsKey($spid)) {
            foreach ($s in $delegatedBySp[$spid]) {
                $perms.Add([ordered]@{ resource = $null; permission = [string]$s; grantType = 'delegated'; isHighRisk = [bool]$riskSet.Contains($s) })
            }
        }
        return $perms
    }

    # Poświadczenia (sekret/cert) z dat -> daysToExpiry / expired / lifetimeDays względem generatedAt.
    $buildCreds = {
        param($app)
        $creds = [System.Collections.Generic.List[object]]::new()
        $mk = {
            param($c, $kind)
            $endIso = ConvertTo-AgIso (Get-AgProp $c 'endDateTime')
            $startIso = ConvertTo-AgIso (Get-AgProp $c 'startDateTime')
            $d2e = $null; $expired = $false; $life = $null
            if ($endIso) {
                $end = [datetimeoffset]::Parse($endIso).UtcDateTime
                $d2e = [int][math]::Floor(($end - $generatedAt).TotalDays)
                $expired = ($end -lt $generatedAt)
            }
            if ($endIso -and $startIso) {
                $life = [int][math]::Floor(([datetimeoffset]::Parse($endIso).UtcDateTime - [datetimeoffset]::Parse($startIso).UtcDateTime).TotalDays)
            }
            [ordered]@{
                kind          = $kind
                displayName   = if (Get-AgProp $c 'displayName') { [string](Get-AgProp $c 'displayName') } else { $null }
                startDateTime = $startIso
                endDateTime   = $endIso
                daysToExpiry  = $d2e
                expired       = [bool]$expired
                lifetimeDays  = $life
            }
        }
        foreach ($pc in @(Get-AgProp $app 'passwordCredentials')) { $creds.Add((& $mk $pc 'secret')) }
        foreach ($kc in @(Get-AgProp $app 'keyCredentials'))      { $creds.Add((& $mk $kc 'certificate')) }
        return $creds
    }

    $appsOut = [System.Collections.Generic.List[object]]::new()
    $seenSp  = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($app in @(Get-AgProp $Apps 'applications')) {
        $aid = [string](Get-AgProp $app 'appId')
        $sp = $null
        if ($aid -and $spByAppId.ContainsKey($aid)) { $sp = $spByAppId[$aid] }
        if ($sp) { [void]$seenSp.Add([string](Get-AgProp $sp 'id')) }

        $aOwners = @(@(Get-AgProp $app 'owners') | ForEach-Object {
            $o = [string](Get-AgProp $_ 'userPrincipalName'); if (-not $o) { $o = [string](Get-AgProp $_ 'displayName') }; $o
        } | Where-Object { $_ })

        $vp = Get-AgProp $app 'verifiedPublisher'
        $vpName = if ($vp) { [string](Get-AgProp $vp 'displayName') } else { $null }

        # @() ujednolica wynik scriptblocka do tablicy (pipeline rozwija listę — bez @() pojedynczy element nie ma .ToArray()).
        $perms = @(& $resolvePerms $sp)
        $creds = @(& $buildCreds $app)
        $assigned = @(& $resolveAssigned $sp)

        # Zdarzenia na poświadczeniach: audit celuje raz w rejestrację, raz w SP — łączymy oba klucze.
        $regId = [string](Get-AgProp $app 'id')
        $credEvents = [System.Collections.Generic.List[object]]::new()
        foreach ($key in @($regId, $(if ($sp) { [string](Get-AgProp $sp 'id') } else { $null }))) {
            if ($key -and $credEventMap.ContainsKey($key)) { foreach ($e in $credEventMap[$key]) { $credEvents.Add($e) } }
        }

        $appsOut.Add([ordered]@{
            id                = $regId
            appId             = if ($aid) { $aid } else { $null }
            displayName       = [string](Get-AgProp $app 'displayName')
            description       = if (Get-AgProp $app 'description') { [string](Get-AgProp $app 'description') } else { $null }
            signInAudience    = if (Get-AgProp $app 'signInAudience') { [string](Get-AgProp $app 'signInAudience') } else { $null }
            publisherDomain   = if (Get-AgProp $app 'publisherDomain') { [string](Get-AgProp $app 'publisherDomain') } else { $null }
            verifiedPublisher = if ($vpName) { $vpName } else { $null }
            accountEnabled    = $(if ($sp -and $null -ne (Get-AgProp $sp 'accountEnabled')) { [bool](Get-AgProp $sp 'accountEnabled') } else { $null })
            createdDateTime   = ConvertTo-AgIso (Get-AgProp $app 'createdDateTime')
            lastSignInDateTime = if ($aid -and $spSignInMap.ContainsKey($aid)) { $spSignInMap[$aid] } else { $null }
            owners            = @($aOwners)
            credentials       = @($creds)
            permissions       = @($perms)
            assignedUsers     = @($assigned)
            credentialEvents  = @($credEvents.ToArray())
        })
    }
    # Aplikacje firm trzecich: SP z nadanym dostępem, ale bez lokalnej rejestracji (consented apps).
    foreach ($sp in $spList) {
        $sid = [string](Get-AgProp $sp 'id')
        if (-not $sid -or $seenSp.Contains($sid)) { continue }
        $perms = @(& $resolvePerms $sp)
        $assigned = @(& $resolveAssigned $sp)
        if ($perms.Count -eq 0 -and $assigned.Count -eq 0) { continue }   # tylko te, które faktycznie coś dostały / mają użytkowników
        $spAppId = if (Get-AgProp $sp 'appId') { [string](Get-AgProp $sp 'appId') } else { $null }
        $appsOut.Add([ordered]@{
            id                = $sid
            appId             = $spAppId
            displayName       = [string](Get-AgProp $sp 'displayName')
            description       = $null
            signInAudience    = $null
            publisherDomain   = $null
            verifiedPublisher = $null
            accountEnabled    = $(if ($null -eq (Get-AgProp $sp 'accountEnabled')) { $null } else { [bool](Get-AgProp $sp 'accountEnabled') })
            createdDateTime   = $null
            lastSignInDateTime = if ($spAppId -and $spSignInMap.ContainsKey($spAppId)) { $spSignInMap[$spAppId] } else { $null }
            owners            = @()
            credentials       = @()
            permissions       = @($perms)
            assignedUsers     = @($assigned)
            credentialEvents  = @($(if ($credEventMap.ContainsKey($sid)) { $credEventMap[$sid].ToArray() } else { @() }))
        })
    }

    # --- Polityki Conditional Access (1.3) -----------------------------------
    # Normalizujemy do płaskiego kształtu kontraktu: requiresMfa (builtInControls 'mfa' LUB
    # authenticationStrength), blocksLegacyAuth ('block' + clientAppTypes legacy), wykluczenia
    # jako surowe id (procesor rozwiązuje je przez własny indeks kont/grup).
    $caOut = [System.Collections.Generic.List[object]]::new()
    foreach ($pol in @($CaPolicies)) {
        $polId = [string](Get-AgProp $pol 'id')   # UWAGA: nie '$pid' — to read-only automatic variable
        if (-not $polId) { continue }
        $cond   = Get-AgProp $pol 'conditions'
        $usersC = Get-AgProp $cond 'users'
        $appsC  = Get-AgProp $cond 'applications'
        $grant  = Get-AgProp $pol 'grantControls'
        $controls = @(@(Get-AgProp $grant 'builtInControls') | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $clientApps = @(@(Get-AgProp $cond 'clientAppTypes') | ForEach-Object { [string]$_ } | Where-Object { $_ })
        $requiresMfa = ($controls -contains 'mfa') -or ($null -ne (Get-AgProp $grant 'authenticationStrength'))
        $legacyTargets = @('exchangeActiveSync', 'other')
        $blocksLegacy = ($controls -contains 'block') -and (@($clientApps | Where-Object { $_ -in $legacyTargets }).Count -gt 0)
        $toList = { param($v) @(@($v) | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
        $caOut.Add([ordered]@{
            id               = $polId
            displayName      = [string](Get-AgProp $pol 'displayName')
            state            = [string](Get-AgProp $pol 'state' 'disabled')
            requiresMfa      = [bool]$requiresMfa
            blocksLegacyAuth = [bool]$blocksLegacy
            clientAppTypes   = @($clientApps)
            includeUsers     = @(& $toList (Get-AgProp $usersC 'includeUsers'))
            excludeUsers     = @(& $toList (Get-AgProp $usersC 'excludeUsers'))
            includeGroups    = @(& $toList (Get-AgProp $usersC 'includeGroups'))
            excludeGroups    = @(& $toList (Get-AgProp $usersC 'excludeGroups'))
            includeRoles     = @(& $toList (Get-AgProp $usersC 'includeRoles'))
            excludeRoles     = @(& $toList (Get-AgProp $usersC 'excludeRoles'))
            includeApplications = @(& $toList (Get-AgProp $appsC 'includeApplications'))
            excludeApplications = @(& $toList (Get-AgProp $appsC 'excludeApplications'))
            grantControls    = @($controls)
            modifiedDateTime = ConvertTo-AgIso (Get-AgProp $pol 'modifiedDateTime')
        })
    }

    # --- Postawa tenanta (1.3) -----------------------------------------------
    $tenantPoliciesOut = $null
    if ($TenantPolicies) {
        $authPol = Get-AgProp $TenantPolicies 'Authorization'
        $secDef  = Get-AgProp $TenantPolicies 'SecurityDefaults'
        $authMet = Get-AgProp $TenantPolicies 'AuthMethods'
        $defPerms = Get-AgProp $authPol 'defaultUserRolePermissions'

        # Zgody użytkowników: niepusta lista permissionGrantPoliciesAssigned = użytkownicy mogą
        # sami nadawać zgody aplikacjom (czy to legacy-default, czy low-risk).
        $consent = $null
        if ($null -ne $defPerms) {
            $grantPolicies = @(Get-AgProp $defPerms 'permissionGrantPoliciesAssigned')
            $consent = ($grantPolicies.Count -gt 0)
        }

        # guestUserRoleId -> czytelny poziom dostępu gości (znane GUID-y ról systemowych).
        $guestAccess = $null
        switch ([string](Get-AgProp $authPol 'guestUserRoleId')) {
            'a0b1b346-4d3e-4e8b-98f8-753987be4970' { $guestAccess = 'memberLevel' }
            '10dae51f-b6af-4016-8d66-8c2a99b929b3' { $guestAccess = 'limited' }
            '2af84b1e-32c8-42b7-82bc-daa82404023b' { $guestAccess = 'restricted' }
        }

        # Słabe metody MFA (podatne na SIM-swap / phishing) włączone w polityce metod.
        $weakMethods = [System.Collections.Generic.List[string]]::new()
        foreach ($cfg in @(Get-AgProp $authMet 'authenticationMethodConfigurations')) {
            $cfgId = [string](Get-AgProp $cfg 'id')
            if ($cfgId -in @('Sms', 'Voice', 'Email') -and [string](Get-AgProp $cfg 'state') -eq 'enabled') {
                $weakMethods.Add($cfgId)
            }
        }

        $tenantPoliciesOut = [ordered]@{
            securityDefaultsEnabled = $(if ($null -eq (Get-AgProp $secDef 'isEnabled')) { $null } else { [bool](Get-AgProp $secDef 'isEnabled') })
            usersCanConsentToApps   = $consent
            usersCanRegisterApps    = $(if ($null -eq (Get-AgProp $defPerms 'allowedToCreateApps')) { $null } else { [bool](Get-AgProp $defPerms 'allowedToCreateApps') })
            guestUserAccess         = $guestAccess
            weakAuthMethodsEnabled  = @($weakMethods.ToArray())
        }
    }

    [ordered]@{
        schemaVersion = '1.4'
        generatedAt   = $generatedAt.ToString('o')
        tenant        = [ordered]@{
            id              = $tenantId
            displayName     = $tenantName
            verifiedDomains = @($VerifiedDomains)
        }
        scanContext   = [ordered]@{
            scannerVersion = $ScannerVersion
            authMode       = $AuthMode
            operator       = $Operator
            collectorsRun  = @($CollectorsRun)
            premiumLicense = [bool]$PremiumLicense
            warnings       = @($Warnings)
        }
        accounts          = @($accounts.ToArray())
        servicePrincipals = @($spOut.ToArray())
        subscribedSkus    = @($subscribedSkus.ToArray())
        groups            = @($groupsOut.ToArray())
        applications      = @($appsOut.ToArray())
        caPolicies        = @($caOut.ToArray())
        tenantPolicies    = $tenantPoliciesOut
    }
}
