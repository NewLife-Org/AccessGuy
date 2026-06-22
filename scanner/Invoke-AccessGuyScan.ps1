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

    [ValidateSet('en', 'pl')]
    [string]$Lang = 'en',           # język lekkiego raportu (ReportLite). Domyślnie angielski.

    [switch]$LiteReport
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Załaduj bibliotekę (dot-source, brak ceremonii modułu => łatwy "drop & run") ---
Get-ChildItem -Path (Join-Path $PSScriptRoot 'lib') -Filter '*.ps1' | ForEach-Object { . $_.FullName }

# i18n: ustaw język sesji (Strings.ps1 z lib/ definiuje $script:AgStrings i helper T).
$script:AgLang = $Lang

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
    if (-not $conn) { throw (T 'scan.connect_fail') }
    Write-AgLog -Level OK -Message ((T 'scan.connected') -f $conn.TenantId, $conn.AuthType)

    # 2) PREFLIGHT (scope'y, P1/P2, kontekst) ------------------------------------
    $pre = Test-AgPreflight -Connection $conn

    # Logowanie się udało => efektowne "wyłonienie" AccessGuy Scanner (sygnał: jedziemy!).
    Show-AgReveal -Caption 'AccessGuy Scanner'
    Write-AgLog -Level OK -Message (T 'scan.collecting')

    # 3) COLLECT (każdy kolektor zwraca surowe + znormalizowane fragmenty) -------
    # Zakres (Scope) decyduje, które moduły zbieramy. Role są wspólne dla Users i Groups
    # (potrzebne do wykrycia ról nadanych grupie role-assignable).
    $warnings = [System.Collections.Generic.List[string]]::new()
    $verifiedDomains = Get-AgVerifiedDomains

    $doUsers  = $Scope -in @('Users', 'All')
    $doGroups = $Scope -in @('Groups', 'All')
    $doApps   = $Scope -in @('Apps', 'All')
    $doRoles  = $doUsers -or $doGroups
    Write-AgLog -Level INFO -Message ((T 'scan.scope_is') -f $Scope)

    $users = @(); $roles = @(); $apps = $null; $mfa = @(); $audit = @(); $signIns = @(); $groups = @()
    $riskyUsers = @(); $spSignIns = @(); $caPolicies = @(); $tenantPolicies = $null
    $collectorsRun = [System.Collections.Generic.List[string]]::new()

    # Mapa konektorów (endpoint Graph + po co) dla zakresu skanu — czytelna legenda przed akcją.
    $mapNames = [System.Collections.Generic.List[string]]::new()
    if ($doUsers)  { $mapNames.AddRange([string[]]@('users', 'authMethods', 'audit', 'signIns', 'riskyUsers')) }
    if ($doRoles)  { $mapNames.Add('roles') }
    if ($doGroups) { $mapNames.Add('groups') }
    if ($doApps)   { $mapNames.AddRange([string[]]@('apps', 'spSignIns')) }
    $mapNames.Add('caPolicies')
    Show-AgConnectorMap -Names @($mapNames.ToArray())

    if ($doUsers) {
        $users   = Get-AgUsers  -PremiumLicense:$pre.PremiumLicense -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.users') -f @($users).Count)
        $mfa     = Get-AgAuthMethods -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.mfa') -f @($mfa).Count)
        $audit   = Get-AgAudit  -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.audit') -f @($audit).Count)
        $signIns = Get-AgSignIns -Warnings $warnings -Days $SignInWindowDays
        Write-AgHarvest -Message ((T 'scan.got.signins') -f $SignInWindowDays, @($signIns).Count)
        $riskyUsers = Get-AgRiskyUsers -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.risky') -f @($riskyUsers).Count)
        $collectorsRun.AddRange([string[]]@('users', 'authMethods', 'audit', 'signIns', 'riskyUsers'))
    }
    if ($doRoles) {
        $roles   = Get-AgRoles  -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.roles') -f @($roles).Count)
        $collectorsRun.Add('roles')
    }
    if ($doGroups) {
        $groups  = Get-AgGroups -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.groups') -f @($groups).Count)
        $collectorsRun.Add('groups')
    }
    if ($doApps) {
        $apps    = Get-AgApps   -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.apps') -f `
            @(Get-AgProp $apps 'servicePrincipals').Count, @(Get-AgProp $apps 'applications').Count, @(Get-AgProp $apps 'oauth2Grants').Count)
        $spSignIns = Get-AgSpSignIns -Warnings $warnings
        Write-AgHarvest -Message ((T 'scan.got.spsignins') -f @($spSignIns).Count)
        $collectorsRun.AddRange([string[]]@('apps', 'applications', 'spSignIns'))
    }

    # Polityki tenanta (CA + postawa) — tenant-level, tanie, zbierane przy KAŻDYM zakresie:
    # wykluczenia z CA wzbogacają konta, brak blokady legacy / security defaults idzie do summary.
    $caPolicies = Get-AgCaPolicies -Warnings $warnings
    Write-AgHarvest -Message ((T 'scan.got.capolicies') -f @($caPolicies).Count)
    $collectorsRun.Add('caPolicies')
    $tenantPolicies = Get-AgTenantPolicies -Warnings $warnings
    if ($tenantPolicies) {
        Write-AgLog -Level OK -Message (T 'scan.got.posture')
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
    Write-AgLog -Level INFO -Message ((T 'scan.dataset_saved') -f $OutputPath)

    # 6) (opcjonalnie) LEKKI raport bez Pythona ----------------------------------
    $liteOut = $null   # musi istnieć przed użyciem w kroku ochrony (StrictMode)
    if ($LiteReport) {
        $liteOut = [System.IO.Path]::ChangeExtension($OutputPath, '.lite.html')
        Export-AccessGuyReportLite -Dataset $dataset -OutputPath $liteOut
        Write-AgLog -Level INFO -Message ((T 'scan.lite_saved') -f $liteOut)
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
    Write-AgLog -Level INFO -Message ((T 'scan.dataset_saved') -f $OutputPath)
    Write-AgLog -Level OK -Message (T 'scan.done')

    # 8) (OPCJONALNIE) OCHRONA datasetu — wybór użytkownika. Tylko interaktywnie (delegated);
    # w trybie App (automatyzacja) pomijamy. Informujemy, że builder (tryb [2]) też potrafi
    # zaszyfrować, oraz że zaszyfrowanie TERAZ uniemożliwi builderowi odczyt datasetu.
    if ($AuthMode -eq 'Delegated' -and (Get-Command Protect-AgArchive -ErrorAction SilentlyContinue)) {
        Write-Host ''
        Write-Host ('  ' + (T 'protect.r1_note')) -ForegroundColor DarkGray
        if (Read-AgYesNo -Prompt (T 'protect.ask')) {
            $files = @($OutputPath)
            if ($liteOut -and (Test-Path -LiteralPath $liteOut)) { $files += $liteOut }
            $archive = Join-Path (Split-Path $OutputPath -Parent) `
                ([System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_dataset.7z')
            $res = Protect-AgArchive -Files $files -ArchivePath $archive -RemovePlaintext
            if ($res.Ok) { Show-AgArchivePassword -Password $res.Password -Archive $res.Archive }
        }
        else {
            Write-AgLog -Level INFO -Message (T 'protect.r1_skipped')
        }
    }
}
catch {
    Write-AgLog -Level ERROR -Message ((T 'scan.aborted') -f $_.Exception.Message)
    if ("$($_.Exception.Message)" -match '(?i)keyring|secret|libsecret') {
        Write-AgLog -Level WARN -Message (T 'scan.keyring_hint')
    }
    throw
}
finally {
    if ($conn) { Disconnect-AccessGuy -Connection $conn -ErrorAction SilentlyContinue }
}
