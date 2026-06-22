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

# Mapa: kolektor -> endpoint Microsoft Graph, który za niego odpowiada (pokazywany w outpucie
# po zalogowaniu — operator widzi DOKŁADNIE skąd lecą dane). Krótkie ścieżki względem /v1.0
# (lub /beta gdzie zaznaczono); pełne URI żyją w Collectors.ps1.
$script:AgConnectorApi = @{
    users        = 'GET /users (+$expand manager, beta signInActivity)'
    roles        = 'GET /roleManagement/directory/roleAssignments (+schedules)'
    groups       = 'GET /groups (+/members)'
    apps         = 'GET /servicePrincipals + /applications + /oauth2PermissionGrants'
    authMethods  = 'GET /reports/authenticationMethods/userRegistrationDetails'
    signIns      = 'GET /auditLogs/signIns'
    audit        = 'GET /auditLogs/directoryAudits'
    spSignIns    = 'GET beta/reports/servicePrincipalSignInActivities'
    riskyUsers   = 'GET /identityProtection/riskyUsers'
    caPolicies   = 'GET /identity/conditionalAccess/policies'
}

# Tabela "CONNECTOR MAP" — drukowana RAZ przed zbieraniem: dla każdego aktywnego kolektora
# pokazuje endpoint Microsoft Graph, który za niego odpowiada, oraz jedno zdanie PO CO go ruszamy.
# To czytelna "legenda" hakerskiego skanu (API żyje tu, w górnej części outputu).
function Show-AgConnectorMap {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
    $rule = '  ' + [char]0x250C + [char]0x2500 + ' ' + (T 'conn.map_title') + ' '
    $rule += [string]([char]0x2500) * [math]::Max(3, 70 - $rule.Length) + [char]0x2510
    Write-Host ''
    Write-Host $rule -ForegroundColor Green
    foreach ($name in $Names) {
        $api = $script:AgConnectorApi[$name]
        if (-not $api) { continue }
        Write-Host '   ' -NoNewline
        Write-Host ([char]0x25B8 + ' ') -ForegroundColor Cyan -NoNewline                          # ▸
        Write-Host ("{0,-12}" -f $name.ToUpper()) -ForegroundColor Cyan -NoNewline
        Write-Host $api -ForegroundColor DarkGray
        foreach ($wline in (Split-AgWrap -Text ([char]0x203A + ' ' + (T "conn.why.$name")) -Width 78 -Indent 7)) {
            Write-Host $wline -ForegroundColor Gray
        }
    }
    Write-Host ('  ' + [char]0x2514 + [string]([char]0x2500) * 68 + [char]0x2518) -ForegroundColor Green  # └───┘
}

# Hakerska linia "konektor wchodzi do akcji" — drukowana, gdy odpala się kolektor.
# Zwięzła (endpoint Graph + opis żyją w tabeli CONNECTOR MAP wyżej): nazwa + "podpinam…".
function Write-AgConnector {
    param([Parameter(Mandatory)][string]$Name)
    Write-Host '   ' -NoNewline
    Write-Host ([string]([char]0x2504) * 2 + [char]0x25B6) -ForegroundColor DarkCyan -NoNewline  # ┄┄▶
    Write-Host (' ' + [char]0x27E6 + ' ') -ForegroundColor DarkGray -NoNewline                   #  ⟦
    Write-Host ("{0,-12}" -f $Name.ToUpper()) -ForegroundColor Cyan -NoNewline
    Write-Host ([char]0x27E7 + ' ') -ForegroundColor DarkGray -NoNewline                          #  ⟧
    Write-Host (T 'conn.engage') -ForegroundColor DarkGray
}

# Deszyfrujący "reveal" pojedynczej linii wyniku: z losowego szumu znaków wyłania się właściwy
# tekst (jak łamanie szyfru) — spójny hakerski sznyt z Show-AgReveal. Gdy output jest
# przekierowany (CI/plik), animację pomijamy i drukujemy od razu czysty wiersz.
function Write-AgHarvest {
    param([Parameter(Mandatory)][string]$Message, [string]$Marker = '+')
    # Usuń ewentualny prefiks "  \-> " z gotowych stringów scan.got.* — marker [+] go zastępuje.
    $msg = $Message -replace '^\s*\\->\s*', ''
    $redirected = $false
    try { $redirected = [Console]::IsOutputRedirected } catch { $redirected = $true }
    if ($redirected) {
        Write-Host ("   [{0}] {1}" -f $Marker, $msg) -ForegroundColor Green
        return
    }
    $glitch = '0123456789ABCDEF#%&$*<>/\|=+-~'.ToCharArray()
    $chars = $msg.ToCharArray()
    $n = $chars.Length
    $resolved = [bool[]]::new($n)
    # Dwa razy wolniej niż wcześniej (więcej klatek + dłuższy odstęp) — efekt "łamania szyfru"
    # ma być czytelny i widowiskowy, nie migać.
    $steps = 10
    $dwell = 52
    for ($s = 1; $s -le $steps; $s++) {
        $sb = [System.Text.StringBuilder]::new($n)
        for ($i = 0; $i -lt $n; $i++) {
            if ($chars[$i] -eq ' ') { [void]$sb.Append(' ') }
            elseif ($resolved[$i]) { [void]$sb.Append($chars[$i]) }
            elseif ((Get-Random -Maximum $steps) -lt $s) { $resolved[$i] = $true; [void]$sb.Append($chars[$i]) }
            else { [void]$sb.Append($glitch[(Get-Random -Maximum $glitch.Length)]) }
        }
        Write-Host ("`r   [" + $Marker + '] ') -ForegroundColor DarkGray -NoNewline
        Write-Host $sb.ToString() -ForegroundColor DarkCyan -NoNewline
        Start-Sleep -Milliseconds $dwell
    }
    Write-Host ("`r   [" + $Marker + '] ') -ForegroundColor DarkGray -NoNewline
    Write-Host $msg -ForegroundColor Green
}

function Write-AgBanner {
    param([string]$Version = '0.0.0')
    # ŻADNEGO brandingu AccessGuy przed logowaniem — logo "wyłania się" DOPIERO po udanym
    # logowaniu (Show-AgReveal). Tu tylko rzeczowa informacja: jakich uprawnień użyjemy.
    Write-Host ''
    Write-Host (T 'banner.connecting') -ForegroundColor DarkGray
    Write-Host ''
    Write-Host (T 'banner.perms_title') -ForegroundColor White
    Write-Host "  [*] User.Read.All        Directory.Read.All" -ForegroundColor Gray
    Write-Host "  [*] AuditLog.Read.All    RoleManagement.Read.All" -ForegroundColor Gray
    Write-Host ("  [+] Application.Read.All  UserAuthenticationMethod.Read.All $(T 'banner.recommended')") -ForegroundColor DarkGray
    Write-Host ("  [+] Policy.Read.All       IdentityRiskyUser.Read.All        $(T 'banner.recommended')") -ForegroundColor DarkGray
    Write-Host (T 'banner.prereq_title') -ForegroundColor White
    Write-Host (T 'banner.prereq_role') -ForegroundColor Gray
    Write-Host ((T 'banner.prereq_lic') + "`n") -ForegroundColor Gray
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

# Hakerski box podsumowania: co skaner złapał + krótki "intel" o konektorach + podpis NewLife.
function Show-AgScanSummary {
    param([hashtable]$Counts, [int]$WarningCount = 0)
    # Kolejność prezentacji konektorów. Każdy wiersz: klucz w $Counts -> etykieta (sum.row.*) + intel (intel.*).
    # [ordered] tablica par; zwykła by się spłaszczyła pod PowerShellem.
    $order = @('users','groups','roles','apps','applications','grants','mfa','audit','signins','skus','capolicies','riskyusers')

    Write-Host ''
    Write-Host '  +======================================================================+' -ForegroundColor Green
    Write-Host ('  |   {0,-66} |' -f (T 'sum.title')) -ForegroundColor Green
    Write-Host '  +======================================================================+' -ForegroundColor Green
    foreach ($key in $order) {
        $label = T ("sum.row.$key")
        $val = if ($Counts -and $Counts.ContainsKey($key)) { [int]$Counts[$key] } else { 0 }
        $dots = '.' * [math]::Max(2, 24 - $label.Length)
        Write-Host '    [' -ForegroundColor DarkGray -NoNewline
        Write-Host '+' -ForegroundColor Green -NoNewline
        Write-Host ('] {0} {1} ' -f $label, $dots) -ForegroundColor Gray -NoNewline
        Write-Host $val -ForegroundColor White
    }
    $wLabel = T 'sum.warnings'
    $wc = if ($WarningCount -gt 0) { 'Yellow' } else { 'DarkGreen' }
    $dots = '.' * [math]::Max(2, 24 - $wLabel.Length)
    Write-Host '    [' -ForegroundColor DarkGray -NoNewline
    Write-Host '!' -ForegroundColor $wc -NoNewline
    Write-Host ('] {0} {1} ' -f $wLabel, $dots) -ForegroundColor Gray -NoNewline
    Write-Host $WarningCount -ForegroundColor $wc
    Write-Host '  +======================================================================+' -ForegroundColor Green

    # (Sekcja INTEL z 2-zdaniowymi opisami per konektor USUNIĘTA — przeniesiona w zwięzłej formie
    # do tabeli CONNECTOR MAP na górze skanu; tu zostaje sam podpis.)
    Write-Host ''
    Write-Host (T 'sum.quote') -ForegroundColor Cyan -NoNewline
    Write-Host '-- NewLife' -ForegroundColor White
    Write-Host ''
}

# Proste zawijanie tekstu po słowach (do stałej szerokości, ze wcięciem) — dla sekcji INTEL.
function Split-AgWrap {
    param([Parameter(Mandatory)][string]$Text, [int]$Width = 80, [int]$Indent = 7)
    $pad = ' ' * $Indent
    $max = [math]::Max(20, $Width - $Indent)
    $out = [System.Collections.Generic.List[string]]::new()
    $cur = ''
    foreach ($word in ($Text -split '\s+')) {
        if ($cur -and (($cur.Length + 1 + $word.Length) -gt $max)) {
            $out.Add($pad + $cur); $cur = $word
        }
        elseif ($cur) { $cur = "$cur $word" }
        else { $cur = $word }
    }
    if ($cur) { $out.Add($pad + $cur) }
    return $out.ToArray()
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
                    Write-AgLog -Level WARN -Message ((T 'graph.retry') -f $status, $attempt, $MaxRetries, $wait)
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
