#Requires -Version 7.0
<#
    AccessGuy Scanner — ReportLite.ps1
    LEKKI raport "surowy klimat" generowany bez Pythona. To NIE jest pełny raport audytowy
    (pełny scoring + ładny HTML/PDF robi procesor Python). Tu pokazujemy oczywiste sygnały:
    kategoria, status, dni od logowania, role uprzywilejowane, MFA — z prostym kolorowaniem.

    Zasada: ReportLite NIE reimplementuje pełnej rubryki scoringu (to byłaby duplikacja i źródło błędów).
    Liczy tylko trywialne, jednoznaczne sygnały na potrzeby "szybkiego oka".
#>

function Get-AgLiteRisk {
    # Bardzo prosty, hardcoded "traffic light" — świadomie minimalny.
    param($Account, [datetime]$GeneratedAt)

    $signals = [System.Collections.Generic.List[string]]::new()
    $hasPriv = @($Account.roles | Where-Object { $_.isPrivileged }).Count -gt 0

    $days = $null
    if ($Account.lastSignInDateTime) {
        $days = [int]([math]::Floor(($GeneratedAt - [datetime]$Account.lastSignInDateTime).TotalDays))
    }

    if ($Account.category -in @('guest', 'external') -and $hasPriv) { $signals.Add('PRIV+EXTERNAL') }
    if ($hasPriv -and $Account.mfaRegistered -eq $false)            { $signals.Add('PRIV bez MFA') }
    if ($null -ne $days -and $days -ge 180)                          { $signals.Add("nieaktywne $days d") }
    elseif ($null -ne $days -and $days -ge 90)                       { $signals.Add("nieaktywne $days d") }
    if ($null -eq $Account.lastSignInDateTime -and $Account.accountEnabled) { $signals.Add('nigdy nie logowane') }

    $level = if ($signals -match 'PRIV') { 'high' } elseif ($signals.Count -gt 0) { 'medium' } else { 'ok' }
    [pscustomobject]@{ Level = $level; Signals = ($signals -join ', '); Days = $days; HasPriv = $hasPriv }
}

function Export-AccessGuyReportLite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Dataset,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    $gen = [datetime]$Dataset.generatedAt
    $rows = foreach ($a in $Dataset.accounts) {
        $r = Get-AgLiteRisk -Account $a -GeneratedAt $gen
        $rowColor = switch ($r.Level) { 'high' { '#ff5555' } 'medium' { '#f1fa8c' } default { '#50fa7b' } }
        @"
<tr>
  <td>$($a.displayName)</td>
  <td>$($a.userPrincipalName)</td>
  <td>$($a.category)</td>
  <td>$(if ($a.accountEnabled) { 'enabled' } else { 'disabled' })</td>
  <td>$(if ($null -ne $r.Days) { "$($r.Days) d" } else { '—' })</td>
  <td>$(if ($r.HasPriv) { 'TAK' } else { '' })</td>
  <td style="color:$rowColor;font-weight:600">$($r.Signals)</td>
</tr>
"@
    }

    $html = @"
<!doctype html><html lang="pl"><head><meta charset="utf-8">
<title>AccessGuy — raport LITE</title>
<style>
  body{background:#0a0a0f;color:#e6e6e6;font-family:Segoe UI,Arial,sans-serif;margin:24px}
  h1{color:#8be9fd} .meta{color:#888;font-size:13px;margin-bottom:16px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 10px;border-bottom:1px solid #222;text-align:left}
  th{color:#bd93f9;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
  .note{margin-top:18px;color:#777;font-size:12px}
</style></head><body>
<h1>AccessGuy — raport LITE (fallback bez Pythona)</h1>
<div class="meta">Tenant: $($Dataset.tenant.displayName) · Wygenerowano: $($Dataset.generatedAt) · Tryb: $($Dataset.scanContext.authMode) · Kont: $($Dataset.accounts.Count)</div>
<table>
<thead><tr><th>Nazwa</th><th>UPN</th><th>Kategoria</th><th>Status</th><th>Od logowania</th><th>Priv</th><th>Sygnały</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table>
<div class="note">To uproszczony podgląd. Pełny scoring (rules.yaml), severity i rekomendacje + ładny HTML/PDF generuje procesor Python z dataset.json.<br>Autor: Daniel "NewLife" Budyn.</div>
</body></html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding utf8
}
