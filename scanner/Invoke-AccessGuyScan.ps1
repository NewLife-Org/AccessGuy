#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    AccessGuy Scanner — read-only zbieranie danych Entra ID do kanonicznego dataset.json.
.DESCRIPTION
    Faza SKAN. Łączy się z tenantem (delegated lub app-only), uruchamia kolektory,
    normalizuje dane do kontraktu contracts/dataset.schema.json i zapisuje dataset.json.
    Opcjonalnie generuje LEKKI raport (ReportLite) gdy nie ma Pythona do pełnej obróbki.

    Pełny, ładny raport robi procesor w Pythonie (osobna faza). Skaner NIE liczy scoringu.
.PARAMETER AuthMode
    'Delegated' (domyślnie) — loguje się człowiek; audyt "z palca" u klienta.
    'App'                   — app-only (certyfikat / managed identity); cykl/automatyzacja.
.PARAMETER TenantId
    GUID tenanta (wymagany dla App; opcjonalny dla Delegated).
.PARAMETER OutputPath
    Ścieżka pliku dataset.json (domyślnie .\out\dataset.json).
.PARAMETER LiteReport
    Jeśli podane — generuje lekki raport HTML obok datasetu (fallback bez Pythona).
.EXAMPLE
    .\Invoke-AccessGuyScan.ps1                         # audyt u klienta, interactive
.EXAMPLE
    .\Invoke-AccessGuyScan.ps1 -AuthMode App -TenantId <guid> -ClientId <appId> -CertThumbprint <thumb>
.NOTES
    Autor: Daniel "NewLife" Budyn
#>
[CmdletBinding()]
param(
    [ValidateSet('Delegated', 'App')]
    [string]$AuthMode = 'Delegated',

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseManagedIdentity,
    [switch]$DeviceCode,

    [string]$OutputPath,            # pominięty => nazwa <tenant8>_<data>.json w .\out
    [int]$SignInWindowDays = 30,    # okno logów signIns (nocne logowania, top-apps); wymaga P1

    [ValidateSet('Users', 'Groups', 'Apps', 'All')]
    [string]$Scope = 'All',         # zakres: które moduły zebrać (jeden skan, wspólny dataset 1.2)

    [switch]$LiteReport
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Załaduj bibliotekę (dot-source, brak ceremonii modułu => łatwy "drop & run") ---
Get-ChildItem -Path (Join-Path $PSScriptRoot 'lib') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

$ScannerVersion = '0.1.0'

Write-AgBanner -Version $ScannerVersion   # ekran powitalny + lista wymaganych uprawnień

$conn = $null   # musi istnieć przed try — inaczej (StrictMode) finally wybucha, gdy auth padnie

try {
    # 1) AUTH ---------------------------------------------------------------------
    # Connect-MgGraph MUSI być wołany PŁASKO (na poziomie skryptu), nie w funkcji —
    # inaczej SDK buforuje komunikat device-code i URL+KOD się nie wypisują (logowanie
    # cicho wisi do timeoutu). Funkcja tylko przygotowuje parametry.
    $connArgs = Get-AgConnectArgs -Mode $AuthMode -TenantId $TenantId -ClientId $ClientId `
        -CertThumbprint $CertThumbprint -UseManagedIdentity:$UseManagedIdentity -DeviceCode:$DeviceCode
    Connect-MgGraph @connArgs
    $conn = Get-MgContext
    if (-not $conn) { throw "Połączenie z Microsoft Graph nie powiodło się." }
    Write-AgLog -Level OK -Message "Połączono. Tenant: $($conn.TenantId)  ·  AuthType: $($conn.AuthType)"

    # 2) PREFLIGHT (scope'y, P1/P2, kontekst) ------------------------------------
    $pre = Test-AgPreflight -Connection $conn

    # Logowanie się udało => efektowne "wyłonienie" AccessGuy Scanner (sygnał: jedziemy!).
    Show-AgReveal -Caption 'AccessGuy Scanner'
    Write-AgLog -Level OK -Message "Zalogowano. Zaczynam zbieranie danych (read-only)..."

    # 3) COLLECT (każdy kolektor zwraca surowe + znormalizowane fragmenty) -------
    # Zakres (Scope) decyduje, które moduły zbieramy. Role są wspólne dla Users i Groups
    # (potrzebne do wykrycia ról nadanych grupie role-assignable).
    $warnings = [System.Collections.Generic.List[string]]::new()
    $verifiedDomains = Get-AgVerifiedDomains

    $doUsers  = $Scope -in @('Users', 'All')
    $doGroups = $Scope -in @('Groups', 'All')
    $doApps   = $Scope -in @('Apps', 'All')
    $doRoles  = $doUsers -or $doGroups
    Write-AgLog -Level INFO -Message "Zakres skanu: $Scope"

    $users = @(); $roles = @(); $apps = $null; $mfa = @(); $audit = @(); $signIns = @(); $groups = @()
    $riskyUsers = @(); $spSignIns = @(); $caPolicies = @(); $tenantPolicies = $null
    $collectorsRun = [System.Collections.Generic.List[string]]::new()

    if ($doUsers) {
        $users   = Get-AgUsers  -PremiumLicense:$pre.PremiumLicense -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> złapano kont: {0}" -f @($users).Count)
        $mfa     = Get-AgAuthMethods -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> rejestracji MFA: {0}" -f @($mfa).Count)
        $audit   = Get-AgAudit  -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> wpisów audytu (PIM + app mgmt): {0}" -f @($audit).Count)
        $signIns = Get-AgSignIns -Warnings $warnings -Days $SignInWindowDays
        Write-AgLog -Level OK -Message ("  \-> logowań ({0} dni): {1}" -f $SignInWindowDays, @($signIns).Count)
        $riskyUsers = Get-AgRiskyUsers -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> kont z nieobsłużonym ryzykiem (Identity Protection): {0}" -f @($riskyUsers).Count)
        $collectorsRun.AddRange([string[]]@('users', 'authMethods', 'audit', 'signIns', 'riskyUsers'))
    }
    if ($doRoles) {
        $roles   = Get-AgRoles  -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> złapano przypisań ról: {0}" -f @($roles).Count)
        $collectorsRun.Add('roles')
    }
    if ($doGroups) {
        $groups  = Get-AgGroups -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> złapano grup: {0}" -f @($groups).Count)
        $collectorsRun.Add('groups')
    }
    if ($doApps) {
        $apps    = Get-AgApps   -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> złapano aplikacji/SP: {0}, rejestracji: {1}, zgód OAuth: {2}" -f `
            @(Get-AgProp $apps 'servicePrincipals').Count, @(Get-AgProp $apps 'applications').Count, @(Get-AgProp $apps 'oauth2Grants').Count)
        $spSignIns = Get-AgSpSignIns -Warnings $warnings
        Write-AgLog -Level OK -Message ("  \-> aktywności logowań SP: {0}" -f @($spSignIns).Count)
        $collectorsRun.AddRange([string[]]@('apps', 'applications', 'spSignIns'))
    }

    # Polityki tenanta (CA + postawa) — tenant-level, tanie, zbierane przy KAŻDYM zakresie:
    # wykluczenia z CA wzbogacają konta, brak blokady legacy / security defaults idzie do summary.
    $caPolicies = Get-AgCaPolicies -Warnings $warnings
    Write-AgLog -Level OK -Message ("  \-> polityk Conditional Access: {0}" -f @($caPolicies).Count)
    $collectorsRun.Add('caPolicies')
    $tenantPolicies = Get-AgTenantPolicies -Warnings $warnings
    if ($tenantPolicies) {
        Write-AgLog -Level OK -Message "  \-> postawa tenanta (authorization/security defaults/metody auth) odczytana"
        $collectorsRun.Add('tenantPolicies')
    }

    # 4) NORMALIZE -> kanoniczny dataset (zgodny z schema) -----------------------
    $dataset = Build-AgDataset `
        -ScannerVersion $ScannerVersion `
        -AuthMode $AuthMode.ToLower() `
        -Operator $pre.Operator `
        -PremiumLicense $pre.PremiumLicense `
        -VerifiedDomains $verifiedDomains `
        -Users $users -Roles $roles -Apps $apps -Mfa $mfa -Audit $audit -SignIns $signIns -Groups $groups `
        -RiskyUsers $riskyUsers -SpSignIns $spSignIns -CaPolicies $caPolicies -TenantPolicies $tenantPolicies `
        -SignInWindowDays $SignInWindowDays `
        -CollectorsRun @($collectorsRun.ToArray()) `
        -Warnings $warnings

    # 5) WRITE dataset -----------------------------------------------------------
    # Nazwa pliku: <pierwsze 8 znaków nazwy tenanta>_<data-godzina>.json (zamiast dataset.json),
    # żeby artefakty z różnych tenantów/skanów się nie myliły i builder mógł je wylistować.
    if (-not $OutputPath) {
        $tenantRaw = [string]$dataset.tenant.displayName
        if (-not $tenantRaw) { $tenantRaw = [string]$dataset.tenant.id }
        $slug = ($tenantRaw -replace '[^A-Za-z0-9]', '')
        if ($slug.Length -gt 8) { $slug = $slug.Substring(0, 8) }
        if (-not $slug) { $slug = 'tenant' }
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        # Wspólny katalog w KORZENIU repo (a nie scanner/out) — żeby builder czytał z tego samego miejsca.
        $repoRoot = Split-Path $PSScriptRoot -Parent
        $OutputPath = Join-Path $repoRoot ("out/{0}_{1}.json" -f $slug, $stamp)
    }
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $OutputPath -Parent)
    $dataset | ConvertTo-Json -Depth 12 | Out-File -FilePath $OutputPath -Encoding utf8
    Write-AgLog -Level INFO -Message "Dataset zapisany: $OutputPath"

    # 6) (opcjonalnie) LEKKI raport bez Pythona ----------------------------------
    if ($LiteReport) {
        $liteOut = [System.IO.Path]::ChangeExtension($OutputPath, '.lite.html')
        Export-AccessGuyReportLite -Dataset $dataset -OutputPath $liteOut
        Write-AgLog -Level INFO -Message "Lekki raport: $liteOut"
    }

    # 7) PODSUMOWANIE "co złapaliśmy" (hakerski box + podpis NewLife) -------------
    Show-AgScanSummary -WarningCount $warnings.Count -Counts @{
        users        = @($users).Count
        groups       = @($dataset.groups).Count
        roles        = @($dataset.accounts | ForEach-Object { @($_.roles).Count } | Measure-Object -Sum).Sum
        apps         = @(Get-AgProp $apps 'servicePrincipals').Count
        applications = @($dataset.applications).Count
        grants       = @(Get-AgProp $apps 'oauth2Grants').Count
        mfa          = @($mfa).Count
        audit        = @($audit).Count
        signins      = @($signIns).Count
        skus         = @($dataset.subscribedSkus).Count
        capolicies   = @($dataset.caPolicies).Count
        riskyusers   = @($riskyUsers).Count
    }
    Write-AgLog -Level INFO -Message "Dataset: $OutputPath"
    Write-AgLog -Level OK -Message "Skan zakończony. Następny krok: builder raportu (tryb [2] w NewLife-AccessGuy)."
}
catch {
    Write-AgLog -Level ERROR -Message "Skan przerwany: $($_.Exception.Message)"
    if ("$($_.Exception.Message)" -match '(?i)keyring|secret|libsecret') {
        Write-AgLog -Level WARN -Message "To problem keyringa Linuksa. Uruchom z logowaniem kodem: ./Invoke-AccessGuyScan.ps1 -DeviceCode  (token nie jest zapisywany na dysk — ContextScope Process)."
    }
    throw
}
finally {
    if ($conn) { Disconnect-AccessGuy -Connection $conn -ErrorAction SilentlyContinue }
}
