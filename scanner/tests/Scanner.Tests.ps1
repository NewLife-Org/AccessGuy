#Requires -Modules Pester
<#
    Testy skanera. Uruchom: Invoke-Pester ./scanner/tests
    Skupiamy się na logice deterministycznej (klasyfikacja, kształt datasetu, paging,
    helpery) — Graph jest w pełni zamockowany (Invoke-MgGraphRequest / Get-MgContext),
    więc testy NIE dotykają tenanta.
#>
BeforeAll {
    Get-ChildItem -Path (Join-Path $PSScriptRoot '../lib') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

    # Placeholdery, żeby Pester miał co mockować (moduł Microsoft.Graph nie jest wymagany do testów).
    function Invoke-MgGraphRequest { param($Method, $Uri, $OutputType, $ErrorAction, $Headers) }
    function Get-MgContext { }

    # Wspólny stub odpowiedzi Graph wg URI (kształt jak z -OutputType Hashtable).
    function script:Get-AgMockGraph {
        param([string]$Uri)
        if ($Uri -match 'organization') {
            return @{ value = @(@{ id='t1'; displayName='Test Tenant'; verifiedDomains=@(@{name='contoso.pl'}) }) }
        }
        if ($Uri -match 'subscribedSkus')  { return @{ value = @(@{ skuId='sku1'; skuPartNumber='SPE_E5' }) } }
        if ($Uri -match '/users\?\$top=1') { return @{ value = @(@{ id='p'; signInActivity=@{ lastSignInDateTime='2026-05-01T00:00:00Z' } }) } }
        if ($Uri -match '/users\?') {
            return @{ value = @(
                @{ id='u1'; displayName='Jan'; userPrincipalName='jan@contoso.pl'; mail='jan@contoso.pl'; userType='Member';
                   accountEnabled=$true; createdDateTime='2021-01-01T00:00:00Z'; onPremisesSyncEnabled=$false;
                   assignedLicenses=@(@{skuId='sku1'}); signInActivity=@{lastSignInDateTime='2026-05-30T00:00:00Z'} },
                @{ id='u2'; displayName='Gosc'; userPrincipalName='ext@partner.com'; mail=$null; userType='Guest';
                   accountEnabled=$true; createdDateTime='2025-01-01T00:00:00Z'; externalUserState='PendingAcceptance';
                   assignedLicenses=@(); signInActivity=$null }
            ) }
        }
        if ($Uri -match 'roleAssignmentSchedules')  { return @{ value = @() } }
        if ($Uri -match 'roleEligibilitySchedules') { return @{ value = @() } }
        # Uwaga: zapytanie SP używa $expand=appRoleAssignments (URL zawiera 'roleAssignments'),
        # więc match musi celować w realny endpoint ról, nie w SP-expand.
        if ($Uri -match 'roleManagement/directory/roleAssignments') {
            return @{ value = @(
                @{ principal=@{id='u2'}; roleDefinition=@{displayName='Global Administrator'; templateId='62e90394'} },
                @{ principalId='grp1'; roleDefinition=@{displayName='Helpdesk Administrator'; templateId='729827e3'} }
            ) }
        }
        # $count (ConsistencyLevel: eventual) zwraca skalar — nie kolekcję.
        if ($Uri -match '/\$count') { if ($Uri -match 'Guest') { return 1 } else { return 3 } }
        # Konkretni członkowie grupy (heterogeniczni: user/guest/group).
        if ($Uri -match '/groups/[^/]+/members') {
            return @{ value = @(
                @{ '@odata.type'='#microsoft.graph.user'; id='u1'; displayName='Jan'; userPrincipalName='jan@contoso.pl'; userType='Member' },
                @{ '@odata.type'='#microsoft.graph.user'; id='u2'; displayName='Gosc'; userPrincipalName='ext@partner.com'; userType='Guest' },
                @{ '@odata.type'='#microsoft.graph.group'; id='gx'; displayName='Nested Group' }
            ) }
        }
        if ($Uri -match '/groups\?') {
            return @{ value = @(
                @{ id='grp1'; displayName='Helpdesk Operators'; description='ops'; mail=$null; mailEnabled=$false; securityEnabled=$true;
                   groupTypes=@(); visibility=$null; isAssignableToRole=$true; membershipRule=$null; onPremisesSyncEnabled=$false;
                   createdDateTime='2023-01-01T00:00:00Z'; renewedDateTime=$null; assignedLicenses=@(@{skuId='sku1'});
                   owners=@(@{ userPrincipalName='owner@contoso.pl'; displayName='Owner' }) },
                @{ id='grp2'; displayName='All Company'; description=$null; mail='all@contoso.pl'; mailEnabled=$true; securityEnabled=$false;
                   groupTypes=@('Unified','DynamicMembership'); visibility='Public'; isAssignableToRole=$false;
                   membershipRule='user.accountEnabled -eq true'; onPremisesSyncEnabled=$false;
                   createdDateTime='2022-01-01T00:00:00Z'; renewedDateTime='2024-01-01T00:00:00Z'; assignedLicenses=@(); owners=@() }
            ) }
        }
        if ($Uri -match 'servicePrincipals')      { return @{ value = @(@{ id='sp1'; appId='a1'; displayName='App'; accountEnabled=$true; appRoles=@(); appRoleAssignments=@(); appRoleAssignedTo=@(@{ principalId='u1'; principalDisplayName='Jan'; principalType='User' }) }) } }
        if ($Uri -match 'oauth2PermissionGrants') { return @{ value = @(@{ clientId='sp1'; principalId='u1'; scope='Mail.ReadWrite User.Read' }) } }
        if ($Uri -match '/applications') {
            return @{ value = @(@{
                id='app1'; appId='a1'; displayName='Backup Service'; description='backup'; signInAudience='AzureADMyOrg';
                createdDateTime='2022-01-01T00:00:00Z'; verifiedPublisher=$null; publisherDomain='contoso.pl';
                passwordCredentials=@(
                    @{ displayName='old'; startDateTime='2020-01-01T00:00:00Z'; endDateTime='2021-01-01T00:00:00Z' },
                    @{ displayName='cur'; startDateTime='2025-01-01T00:00:00Z'; endDateTime='2099-01-01T00:00:00Z' }
                );
                keyCredentials=@(); owners=@()
            }) }
        }
        if ($Uri -match 'userRegistrationDetails'){ return @{ value = @(@{ id='u1'; isMfaRegistered=$true }, @{ id='u2'; isMfaRegistered=$false }) } }
        if ($Uri -match 'directoryAudits')        { return @{ value = @() } }
        return @{ value = @() }
    }
}

Describe 'Get-AgAccountCategory' {
    It 'rozpoznaje gościa po userType' {
        Get-AgAccountCategory -UserType 'Guest' -Upn 'x@partner.com' -VerifiedDomains @('contoso.pl') | Should -Be 'guest'
    }
    It 'rozpoznaje membera wewnętrznego po domenie' {
        Get-AgAccountCategory -UserType 'Member' -Upn 'jan@contoso.pl' -VerifiedDomains @('contoso.pl') | Should -Be 'internal'
    }
    It 'rozpoznaje membera zewnętrznego po obcej domenie' {
        Get-AgAccountCategory -UserType 'Member' -Upn 'jan@inny.com' -VerifiedDomains @('contoso.pl') | Should -Be 'external'
    }
    It 'rozpoznaje membera zewnętrznego po #EXT#' {
        Get-AgAccountCategory -UserType 'Member' -Upn 'jan_inny.com#EXT#@contoso.onmicrosoft.com' -VerifiedDomains @('contoso.onmicrosoft.com') | Should -Be 'external'
    }
}

Describe 'ConvertTo-AgIso' {
    It 'zwraca null dla pustych' { ConvertTo-AgIso $null | Should -BeNullOrEmpty; ConvertTo-AgIso '' | Should -BeNullOrEmpty }
    It 'normalizuje datetime do UTC ISO' { ConvertTo-AgIso ([datetime]'2026-01-02T03:04:05Z') | Should -Match '^2026-01-02T03:04:05' }
    It 'parsuje string z offsetem do UTC' { ConvertTo-AgIso '2026-01-02T05:04:05+02:00' | Should -Match '^2026-01-02T03:04:05' }
}

Describe 'Get-AgProp (StrictMode-safe)' {
    It 'czyta klucz hashtable' { Get-AgProp @{ a = 1 } 'a' | Should -Be 1 }
    It 'zwraca default dla brakującego klucza' { Get-AgProp @{ a = 1 } 'b' 99 | Should -Be 99 }
    It 'czyta property PSObject' { Get-AgProp ([pscustomobject]@{ a = 7 }) 'a' | Should -Be 7 }
}

Describe 'Invoke-AgGraphPaged' {
    It 'spłaszcza wiele stron po @odata.nextLink' {
        $script:calls = 0
        Mock Invoke-MgGraphRequest {
            $script:calls++
            if ($script:calls -eq 1) { @{ value = @(@{id=1}, @{id=2}); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/next' } }
            else { @{ value = @(@{id=3}) } }
        }
        $r = Invoke-AgGraphPaged -Uri '/things'
        $r.Count | Should -Be 3
        Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
    }

    It 'ponawia po błędzie 429 i ostatecznie zwraca dane' {
        $script:n = 0
        Mock Start-Sleep { }   # bez realnego czekania
        Mock Invoke-MgGraphRequest {
            $script:n++
            if ($script:n -eq 1) { throw [System.Exception]::new('Request throttled (429)') }
            @{ value = @(@{id='ok'}) }
        }
        $r = Invoke-AgGraphPaged -Uri '/things'
        @($r).Count | Should -Be 1
        Should -Invoke Invoke-MgGraphRequest -Times 2 -Exactly
    }
}

Describe 'Get-AgRubric' {
    It 'wczytuje privilegedRoles i highRiskAppScopes z rules.yaml' {
        $r = Get-AgRubric
        $r.PrivilegedRoles | Should -Contain 'Global Administrator'
        $r.HighRiskAppScopes | Should -Contain 'Mail.ReadWrite'
    }
}

Describe 'Build-AgDataset' {
    BeforeEach {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 't1' } }
        Mock Invoke-MgGraphRequest { Get-AgMockGraph -Uri $Uri }
    }

    It 'produkuje wymagane pola najwyższego poziomu i kształt kontraktu' {
        $w = [System.Collections.Generic.List[string]]::new()
        $users = Get-AgUsers -PremiumLicense -Warnings $w
        $roles = Get-AgRoles -Warnings $w
        $apps  = Get-AgApps  -Warnings $w
        $mfa   = Get-AgAuthMethods -Warnings $w
        $audit = Get-AgAudit -Warnings $w
        $ds = Build-AgDataset -ScannerVersion '0.1.0' -AuthMode 'delegated' -Operator 'op@contoso.pl' `
            -PremiumLicense $true -VerifiedDomains @('contoso.pl') `
            -Users $users -Roles $roles -Apps $apps -Mfa $mfa -Audit $audit `
            -CollectorsRun @('users','roles','apps','authMethods','audit') -Warnings $w

        $ds.schemaVersion | Should -Be '1.4'
        $ds.tenant.displayName | Should -Be 'Test Tenant'
        $ds.accounts.Count | Should -Be 2
        $ds.scanContext.authMode | Should -Be 'delegated'
    }

    It 'klasyfikuje, oznacza role uprzywilejowane i high-risk grant' {
        $w = [System.Collections.Generic.List[string]]::new()
        $ds = Build-AgDataset -ScannerVersion '0.1.0' -AuthMode 'delegated' -Operator 'op@contoso.pl' `
            -PremiumLicense $true -VerifiedDomains @('contoso.pl') `
            -Users (Get-AgUsers -PremiumLicense -Warnings $w) -Roles (Get-AgRoles -Warnings $w) `
            -Apps (Get-AgApps -Warnings $w) -Mfa (Get-AgAuthMethods -Warnings $w) -Audit (Get-AgAudit -Warnings $w) `
            -CollectorsRun @('users') -Warnings $w

        $guest = $ds.accounts | Where-Object { $_.userPrincipalName -eq 'ext@partner.com' }
        $guest.category | Should -Be 'guest'
        $guest.roles[0].roleName | Should -Be 'Global Administrator'
        $guest.roles[0].isPrivileged | Should -BeTrue

        $jan = $ds.accounts | Where-Object { $_.userPrincipalName -eq 'jan@contoso.pl' }
        $jan.assignedLicenses | Should -Contain 'SPE_E5'      # GUID -> partNumber
        $jan.mfaRegistered | Should -BeTrue
        $jan.appGrants[0].isHighRisk | Should -BeTrue          # Mail.ReadWrite
    }

    It 'normalizuje Conditional Access: zakres aplikacji (1.4) + requiresMfa/wykluczenia' {
        $w = [System.Collections.Generic.List[string]]::new()
        $rawPol = @{
            id            = 'ca-1'
            displayName   = 'MFA for one app'
            state         = 'enabled'
            conditions    = @{
                users        = @{ includeUsers = @('All'); excludeUsers = @('u-2') }
                applications = @{ includeApplications = @('app-123'); excludeApplications = @() }
                clientAppTypes = @('all')
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $ds = Build-AgDataset -ScannerVersion '0.1.0' -AuthMode 'delegated' -Operator 'op@contoso.pl' `
            -PremiumLicense $true -VerifiedDomains @('contoso.pl') `
            -Users (Get-AgUsers -PremiumLicense -Warnings $w) -Roles (Get-AgRoles -Warnings $w) `
            -Apps (Get-AgApps -Warnings $w) -Mfa (Get-AgAuthMethods -Warnings $w) -Audit (Get-AgAudit -Warnings $w) `
            -CaPolicies @($rawPol) -CollectorsRun @('users','caPolicies') -Warnings $w

        $pol = $ds.caPolicies[0]
        $pol.requiresMfa | Should -BeTrue
        $pol.includeApplications | Should -Contain 'app-123'    # zakres aplikacji (1.4)
        @($pol.excludeApplications).Count | Should -Be 0
        $pol.includeUsers | Should -Contain 'All'
        $pol.excludeUsers | Should -Contain 'u-2'
    }
}

Describe 'Get-AgSignInAggregate — legacy auth udane vs zablokowane' {
    It 'liczy legacy per protokół i rozróżnia sukces (errorCode 0) od zablokowanych' {
        $gen = [datetime]'2026-06-01T00:00:00Z'
        $signins = @(
            @{ userId='u1'; createdDateTime='2026-05-20T10:00:00Z'; clientAppUsed='IMAP4'; status=@{ errorCode=0 }; appDisplayName='Office 365 Exchange Online' },
            @{ userId='u1'; createdDateTime='2026-05-21T10:00:00Z'; clientAppUsed='IMAP4'; status=@{ errorCode=0 }; appDisplayName='Office 365 Exchange Online' },
            @{ userId='u1'; createdDateTime='2026-05-22T10:00:00Z'; clientAppUsed='Authenticated SMTP'; status=@{ errorCode=53003 }; appDisplayName='Office 365 Exchange Online' },
            @{ userId='u1'; createdDateTime='2026-05-23T10:00:00Z'; clientAppUsed='Browser'; status=@{ errorCode=0 }; appDisplayName='Office 365 SharePoint Online' }
        )
        $map = Get-AgSignInAggregate -SignIns $signins -GeneratedAt $gen -WindowDays 30
        $e = $map['u1']
        $e.SignInCount  | Should -Be 4
        $e.LegacyCount  | Should -Be 3      # IMAP4 x2 + SMTP x1 (Browser nie jest legacy)
        $e.LegacySuccess | Should -Be 2      # tylko udane IMAP4
        $e.LegacyClients['IMAP4'].Count   | Should -Be 2
        $e.LegacyClients['IMAP4'].Success | Should -Be 2
        $e.LegacyClients['Authenticated SMTP'].Count   | Should -Be 1
        $e.LegacyClients['Authenticated SMTP'].Success | Should -Be 0   # zablokowane
    }
}

Describe 'Build-AgDataset — moduły Grupy i Aplikacje (1.2)' {
    BeforeEach {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 't1' } }
        Mock Invoke-MgGraphRequest { Get-AgMockGraph -Uri $Uri }
    }

    It 'normalizuje grupy: kind, owners, licencje, liczność i rolę nadaną grupie' {
        $w = [System.Collections.Generic.List[string]]::new()
        $ds = Build-AgDataset -ScannerVersion '0.1.0' -AuthMode 'delegated' -Operator 'op@contoso.pl' `
            -PremiumLicense $true -VerifiedDomains @('contoso.pl') `
            -Users (Get-AgUsers -PremiumLicense -Warnings $w) -Roles (Get-AgRoles -Warnings $w) `
            -Apps (Get-AgApps -Warnings $w) -Mfa (Get-AgAuthMethods -Warnings $w) -Audit (Get-AgAudit -Warnings $w) `
            -Groups (Get-AgGroups -Warnings $w) -CollectorsRun @('groups') -Warnings $w

        $ds.groups.Count | Should -Be 2

        $hd = $ds.groups | Where-Object { $_.id -eq 'grp1' }
        $hd.groupKind | Should -Be 'security'
        $hd.isAssignableToRole | Should -BeTrue
        $hd.owners | Should -Contain 'owner@contoso.pl'
        $hd.assignedLicenses | Should -Contain 'SPE_E5'
        $hd.memberCount | Should -Be 3
        $hd.guestCount | Should -Be 1
        # konkretni członkowie (lista) + typ principala z @odata.type
        $hd.members.Count | Should -Be 3
        @($hd.members | Where-Object { $_.userPrincipalName -eq 'jan@contoso.pl' }).Count | Should -Be 1
        @($hd.members | Where-Object { $_.type -eq 'group' }).Count | Should -Be 1
        @($hd.members | Where-Object { $_.id -eq 'u1' }).Count | Should -Be 1   # id potrzebne do powiązań
        # rola nadana grupie (principalId == grp1) -> assignedRoles + isPrivileged
        $hd.assignedRoles[0].roleName | Should -Be 'Helpdesk Administrator'
        $hd.assignedRoles[0].isPrivileged | Should -BeTrue

        $all = $ds.groups | Where-Object { $_.id -eq 'grp2' }
        $all.groupKind | Should -Be 'microsoft365'
        $all.membershipType | Should -Be 'dynamic'
        $all.visibility | Should -Be 'Public'
    }

    It 'normalizuje aplikacje: wygasanie poświadczeń i klasyfikacja uprawnień delegowanych' {
        $w = [System.Collections.Generic.List[string]]::new()
        $ds = Build-AgDataset -ScannerVersion '0.1.0' -AuthMode 'delegated' -Operator 'op@contoso.pl' `
            -PremiumLicense $true -VerifiedDomains @('contoso.pl') `
            -Users (Get-AgUsers -PremiumLicense -Warnings $w) -Roles (Get-AgRoles -Warnings $w) `
            -Apps (Get-AgApps -Warnings $w) -Mfa (Get-AgAuthMethods -Warnings $w) -Audit (Get-AgAudit -Warnings $w) `
            -Groups (Get-AgGroups -Warnings $w) -CollectorsRun @('apps','applications') -Warnings $w

        $app = $ds.applications | Where-Object { $_.appId -eq 'a1' }
        $app | Should -Not -BeNullOrEmpty
        $app.displayName | Should -Be 'Backup Service'
        # dwa poświadczenia: jedno wygasłe (2021), jedno ważne (2099).
        # @() jest konieczne: pojedynczy wynik Where to OrderedDictionary, a jego .Count = liczba kluczy.
        @($app.credentials | Where-Object { $_.expired }).Count | Should -Be 1
        @($app.credentials | Where-Object { -not $_.expired }).Count | Should -Be 1
        # podpięci użytkownicy: przypisany (appRoleAssignedTo) + zgoda (oauth principalId), UPN rozwiązany z userIndex
        @($app.assignedUsers | Where-Object { $_.via -eq 'assignment' }).Count | Should -BeGreaterThan 0
        @($app.assignedUsers | Where-Object { $_.via -eq 'consent' }).Count | Should -BeGreaterThan 0
        @($app.assignedUsers | Where-Object { $_.userPrincipalName -eq 'jan@contoso.pl' }).Count | Should -BeGreaterThan 0
        @($app.assignedUsers | Where-Object { $_.id -eq 'u1' }).Count | Should -BeGreaterThan 0   # id principala
        # delegowana zgoda Mail.ReadWrite -> isHighRisk
        $mail = $app.permissions | Where-Object { $_.permission -eq 'Mail.ReadWrite' }
        $mail.grantType | Should -Be 'delegated'
        $mail.isHighRisk | Should -BeTrue
    }
}
