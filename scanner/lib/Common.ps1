#Requires -Version 7.0
<#
    AccessGuy Scanner — Common.ps1
    Helpery współdzielone: logowanie z kolorami, ekran powitalny, paging Graph, retry na 429.
#>

function Write-AgLog {
    [CmdletBinding()]
    param(
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory)] [string]$Message
    )
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'DEBUG' { 'DarkGray' }
        default { 'Cyan' }
    }
    $ts = (Get-Date).ToString('HH:mm:ss')
    Write-Host ("[{0}] [{1,-5}] {2}" -f $ts, $Level, $Message) -ForegroundColor $color
}

function Write-AgBanner {
    param([string]$Version = '0.0.0')
    # ŻADNEGO brandingu AccessGuy przed logowaniem — logo "wyłania się" DOPIERO po udanym
    # logowaniu (Show-AgReveal). Tu tylko rzeczowa informacja: jakich uprawnień użyjemy.
    Write-Host ''
    Write-Host "  Łączenie z Microsoft Entra ID (read-only)..." -ForegroundColor DarkGray
    Write-Host ''
    Write-Host "WYMAGANE UPRAWNIENIA (Microsoft Graph):" -ForegroundColor White
    Write-Host "  [*] User.Read.All        Directory.Read.All" -ForegroundColor Gray
    Write-Host "  [*] AuditLog.Read.All    RoleManagement.Read.All" -ForegroundColor Gray
    Write-Host "  [+] Application.Read.All  UserAuthenticationMethod.Read.All (zalecane)" -ForegroundColor DarkGray
    Write-Host "  [+] Policy.Read.All       IdentityRiskyUser.Read.All        (zalecane)" -ForegroundColor DarkGray
    Write-Host "PREREKWIZYTY:" -ForegroundColor White
    Write-Host "  - Rola operatora: Global Reader (lub Security Reader + Reports Reader)" -ForegroundColor Gray
    Write-Host "  - Licencja tenanta: Entra ID P1/P2 (dla signInActivity), P2 dla pełnego PIM`n" -ForegroundColor Gray
}

# === Branding AccessGuy (do efektu po udanym logowaniu) ======================
$script:AG_ACCESS_GUY_LOGO = @"
                     ▄▄██████████▄▄.
                   .██████████████████.
                 .██████████████████████.
                .████████████████████████.
                ██████████████████████████
               ████████████████████████████
               ████▀▀▀██████████████▀▀▀████
               ██▀  ▄████████████████▄  ▀██
               ██   ██████████████████   ██
               ██   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀   ██
               ██                        ██
               ██▄             ▄▄▄▄     ▄██
                ██▄           ▀████▀   ▄██
                 ███▄▄              ▄▄███
                ▄████████████████████████▄
               ▄██████████████████████████▄
              ████████████  ████  ████████████
             ████████████   ████   ████████████
            ████████████    ████    ████████████
           ███████████▀     ████     ▀███████████
"@

$script:AG_ACCESS_GUY_TEXT = @"
   _____                                       ________
  /  _  \   ____  ____  ____   ______ ______  /  _____/ __ __ ___.__.
 /  /_\  \_/ ___\/ ___\/ __ \ /  ___//  ___/ /   \  ___|  |  <   |  |
/    |    \  \__\  \__\  ___/ \___ \ \___ \  \    \_\  \  |  /\___  |
\____|__  /\___  >___  >___  >____  >____  >  \______  /____/ / ____|
        \/     \/    \/    \/     \/     \/          \/       \/
"@

# Efekt "wyłaniania się" AccessGuy po UDANYM logowaniu (Daniel: ma wyglądać cool).
# Reveal linia-po-linii z delikatnym shimmerem; bez agresywnego glitchu, żeby art się nie rozjechał.
function Show-AgReveal {
    param([string]$Caption = 'AccessGuy Scanner')
    try { [Console]::CursorVisible = $false } catch { }
    Clear-Host
    Write-Host ''
    $glitch = '01<>#*+=:.'.ToCharArray()
    foreach ($line in ($script:AG_ACCESS_GUY_LOGO -split "`r?`n")) {
        for ($k = 0; $k -lt 2; $k++) {
            $noisy = -join ($line.ToCharArray() | ForEach-Object {
                if ($_ -eq ' ') { ' ' } elseif ((Get-Random -Maximum 100) -lt 45) { $glitch[(Get-Random -Maximum $glitch.Length)] } else { $_ }
            })
            Write-Host ("`r" + $noisy) -ForegroundColor DarkCyan -NoNewline
            Start-Sleep -Milliseconds 10
        }
        Write-Host ("`r" + $line) -ForegroundColor Cyan
    }
    foreach ($line in ($script:AG_ACCESS_GUY_TEXT -split "`r?`n")) { Write-Host $line -ForegroundColor White }
    Write-Host ''
    Write-Host ("                              >>  " + $Caption + "  <<") -ForegroundColor Green
    Write-Host ''
    Start-Sleep -Milliseconds 600
    try { [Console]::CursorVisible = $true } catch { }
}

# Hakerski box podsumowania: co skaner złapał + podpis NewLife.
function Show-AgScanSummary {
    param([hashtable]$Counts, [int]$WarningCount = 0)
    # Ordered: label -> klucz w $Counts. (Zwykła tablica par PS by spłaszczyła.)
    $rows = [ordered]@{
        'Konta (users)'      = 'users'
        'Grupy'              = 'groups'
        'Przypisania ról'    = 'roles'
        'Aplikacje / SP'     = 'apps'
        'Rejestracje app'    = 'applications'
        'Zgody OAuth'        = 'grants'
        'Rejestracje MFA'    = 'mfa'
        'Wpisy audytu (PIM)' = 'audit'
        'Logowania (30 dni)' = 'signins'
        'Licencje (SKU)'     = 'skus'
        'Polityki CA'        = 'capolicies'
        'Konta atRisk (IdP)' = 'riskyusers'
    }
    Write-Host ''
    Write-Host '  +======================================================================+' -ForegroundColor Green
    Write-Host '  |   SKAN ZAKOŃCZONY -- OTO CO UDALO SIE ZLAPAC                          |' -ForegroundColor Green
    Write-Host '  +======================================================================+' -ForegroundColor Green
    foreach ($label in $rows.Keys) {
        $key = $rows[$label]
        $val = if ($Counts -and $Counts.ContainsKey($key)) { [int]$Counts[$key] } else { 0 }
        $dots = '.' * [math]::Max(2, 24 - $label.Length)
        Write-Host '    [' -ForegroundColor DarkGray -NoNewline
        Write-Host '+' -ForegroundColor Green -NoNewline
        Write-Host ('] {0} {1} ' -f $label, $dots) -ForegroundColor Gray -NoNewline
        Write-Host $val -ForegroundColor White
    }
    $wc = if ($WarningCount -gt 0) { 'Yellow' } else { 'DarkGreen' }
    $dots = '.' * [math]::Max(2, 24 - 'Ostrzeżenia'.Length)
    Write-Host '    [' -ForegroundColor DarkGray -NoNewline
    Write-Host '!' -ForegroundColor $wc -NoNewline
    Write-Host ('] {0} {1} ' -f 'Ostrzeżenia', $dots) -ForegroundColor Gray -NoNewline
    Write-Host $WarningCount -ForegroundColor $wc
    Write-Host '  +======================================================================+' -ForegroundColor Green
    Write-Host ''
    Write-Host '   "Nie sprzedam Twoich danych. Ufasz mi?"  ' -ForegroundColor Cyan -NoNewline
    Write-Host '-- NewLife' -ForegroundColor White
    Write-Host ''
}

# Lista wymaganych scope'ów — jedno źródło prawdy dla auth i preflight.
function Get-AgRequiredScopes {
    @(
        'User.Read.All',
        'Directory.Read.All',
        'AuditLog.Read.All',
        'RoleManagement.Read.All',
        'Application.Read.All',
        'UserAuthenticationMethod.Read.All',
        'Policy.Read.All',
        'IdentityRiskyUser.Read.All'
    )
}

# --- Bezpieczne czytanie pól (StrictMode-safe) -------------------------------
# Graph z -OutputType Hashtable zwraca zagnieżdżone [hashtable]; dostęp indeksowy
# do brakującego klucza jest bezpieczny pod Set-StrictMode -Version Latest,
# w przeciwieństwie do dostępu po kropce. Ten helper ujednolica odczyt z hashtable
# i z PSObject (tak, żeby mocki w testach mogły zwracać jedno lub drugie).
function Get-AgProp {
    param($Object, [Parameter(Mandatory)] [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $Default
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $Default
}

# --- Daty -> ISO 8601 UTC ----------------------------------------------------
# Graph oddaje daty jako [datetime]/[datetimeoffset] lub string; kontrakt wymaga
# jednolitego ISO 8601 w UTC ('o'). Zwraca $null dla pustych/niedających się sparsować.
function ConvertTo-AgIso {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime])       { return ([datetime]$Value).ToUniversalTime().ToString('o') }
    if ($Value -is [datetimeoffset]) { return ([datetimeoffset]$Value).UtcDateTime.ToString('o') }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $dt = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$dt)) {
        return $dt.ToUniversalTime().ToString('o')
    }
    return $null
}

# --- Rubryka jako jedno źródło prawdy ----------------------------------------
# Skaner musi oznaczyć isPrivileged / isHighRisk po nazwie. Listy żyją w
# contracts/rules.yaml (czyta je też procesor). Zamiast zależności od modułu YAML
# wyciągamy dwie proste sekwencje stringów regexem; przy braku pliku — bezpieczny
# fallback z wbudowaną listą (procesor i tak weryfikuje ostatecznie).
function Get-AgYamlStringList {
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]]$Lines, [Parameter(Mandatory)] [string]$Key)
    $out = [System.Collections.Generic.List[string]]::new()
    $inBlock = $false
    foreach ($line in $Lines) {
        if ($line -match ("^\s*" + [regex]::Escape($Key) + "\s*:\s*$")) { $inBlock = $true; continue }
        if (-not $inBlock) { continue }
        if ($line -match '^\s*-\s*(.+?)\s*$') {
            $out.Add($matches[1].Trim().Trim('"').Trim("'"))
        }
        elseif ($line -match '^\s*#') { continue }   # komentarz wewnątrz bloku
        elseif (-not [string]::IsNullOrWhiteSpace($line)) { break }  # koniec sekwencji
    }
    return $out.ToArray()
}

function Get-AgRubric {
    [CmdletBinding()]
    param([string]$RulesPath)
    if (-not $RulesPath) { $RulesPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../contracts/rules.yaml')) }

    $priv = @(); $scopes = @(); $appRoles = @()
    try {
        if (Test-Path -LiteralPath $RulesPath) {
            $lines    = Get-Content -LiteralPath $RulesPath
            $priv     = Get-AgYamlStringList -Lines $lines -Key 'privilegedRoles'
            $scopes   = Get-AgYamlStringList -Lines $lines -Key 'highRiskAppScopes'
            $appRoles = Get-AgYamlStringList -Lines $lines -Key 'highRiskAppRoles'
        }
    }
    catch { Write-AgLog -Level WARN -Message "Nie udało się odczytać rules.yaml ($RulesPath) — używam wbudowanej listy." }

    if (-not $priv -or $priv.Count -eq 0) {
        $priv = @('Global Administrator','Privileged Role Administrator','Privileged Authentication Administrator',
                  'Security Administrator','Application Administrator','Cloud Application Administrator',
                  'Exchange Administrator','SharePoint Administrator','User Administrator',
                  'Conditional Access Administrator','Authentication Administrator','Helpdesk Administrator','Intune Administrator')
    }
    if (-not $scopes -or $scopes.Count -eq 0) {
        $scopes = @('Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory','Mail.ReadWrite',
                    'Mail.Send','Files.ReadWrite.All','User.ReadWrite.All')
    }
    if (-not $appRoles -or $appRoles.Count -eq 0) {
        $appRoles = @('Directory.ReadWrite.All','RoleManagement.ReadWrite.Directory','AppRoleAssignment.ReadWrite.All',
                      'Application.ReadWrite.All','Application.ReadWrite.OwnedBy','Group.ReadWrite.All','GroupMember.ReadWrite.All',
                      'User.ReadWrite.All','Mail.ReadWrite','Mail.Send','MailboxSettings.ReadWrite','Files.ReadWrite.All',
                      'Sites.ReadWrite.All','Sites.FullControl.All')
    }
    [pscustomobject]@{ PrivilegedRoles = @($priv); HighRiskAppScopes = @($scopes); HighRiskAppRoles = @($appRoles) }
}

function Get-AgCount {
    <#
        Zwraca skalar z endpointu Graph $count (np. /groups/{id}/members/$count).
        Wymaga nagłówka ConsistencyLevel: eventual (advanced query). Best-effort:
        przy błędzie/braku uprawnień zwraca $null (liczność pozostaje nieznana).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$Uri)
    if ($Uri -notmatch '^https?://') { $Uri = 'https://graph.microsoft.com/v1.0/' + $Uri.TrimStart('/') }
    try {
        $val = Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers @{ ConsistencyLevel = 'eventual' } -ErrorAction Stop
        return [int]$val
    }
    catch { return $null }
}

function Invoke-AgGraphPaged {
    <#
        Pobiera wszystkie strony zapytania Graph (obsługa @odata.nextLink) z retry/backoff
        na 429 i 5xx (poszanowanie Retry-After). Zwraca płaską tablicę elementów 'value'
        jako [hashtable] (-OutputType Hashtable => bezpieczny dostęp indeksowy pod StrictMode).
        $Uri może być względny (np. '/users?...') — wtedy doklejamy host i wersję (v1.0/beta).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [switch]$Beta,
        [int]$MaxRetries = 5,
        [int]$MaxItems = 0      # 0 = bez limitu; >0 = przerwij paging po zebraniu tylu elementów (ochrona przy wielkich kolekcjach)
    )
    if ($Uri -notmatch '^https?://') {
        $base = if ($Beta) { 'https://graph.microsoft.com/beta' } else { 'https://graph.microsoft.com/v1.0' }
        $Uri  = $base.TrimEnd('/') + '/' + $Uri.TrimStart('/')
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        $attempt = 0
        $resp = $null
        while ($true) {
            try {
                $resp = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType Hashtable -ErrorAction Stop
                break
            }
            catch {
                $status = 0
                try { if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } } catch { }
                $isRetryable = ($status -eq 429 -or $status -ge 500 -or ($status -eq 0 -and $_.Exception.Message -match '429|throttl|timeout|temporarily'))
                $attempt++
                if ($isRetryable -and $attempt -le $MaxRetries) {
                    $wait = 0
                    try { $wait = [int]$_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds } catch { }
                    if ($wait -le 0) { $wait = [int][math]::Min(60, [math]::Pow(2, $attempt)) }
                    Write-AgLog -Level WARN -Message ("Graph $status — ponawiam $attempt/$MaxRetries za ${wait}s ...")
                    Start-Sleep -Seconds $wait
                    continue
                }
                throw
            }
        }

        $val = Get-AgProp $resp 'value'
        if ($null -ne $val) {
            foreach ($item in @($val)) { $results.Add($item) }
        }
        elseif ($null -ne $resp -and -not ($resp -is [System.Collections.IDictionary] -and $resp.Contains('@odata.context'))) {
            # Pojedynczy obiekt (np. /organization/{id}) zamiast kolekcji.
            $results.Add($resp)
        }
        $next = Get-AgProp $resp '@odata.nextLink'
        if ($MaxItems -gt 0 -and $results.Count -ge $MaxItems) { break }   # ochrona: nie ciągnij wielkich kolekcji bez końca
    }
    return $results.ToArray()
}
