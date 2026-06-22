#Requires -Version 7.0
<#
.SYNOPSIS
    NewLife-AccessGuy — główny launcher/sterownik AccessGuy.
.DESCRIPTION
    Jeden punkt wejścia, który steruje całością. Pokazuje znak towarowy (animacja),
    panel AccessGuy, jednorazowo "odblokowuje" wszystkie skrypty pakietu (koniec z
    pięciokrotnym potwierdzaniem tej samej komendy) i daje wybór trybu:

      [1] AccessGuy-EntraID-Scanner   — faza SKAN (PowerShell, read-only Entra ID)
      [2] AccessGuy-Report-Builder    — faza RAPORT (Python 3, raport idealny do przeglądu dla zarządu)

    Read-only zawsze. Skaner łączy się z tenantem tylko do odczytu; builder nie dotyka
    tenanta — bierze sam plik z danymi.
.PARAMETER Mode
    'Scan' albo 'Report'. Pominięty => menu interaktywne.
.PARAMETER NoAnimate
    Pomija animację intro (szybsze testy / środowiska bez TTY).
.NOTES
    Autor: Daniel "NewLife" Budyn
#>
[CmdletBinding()]
param(
    [ValidateSet('Scan', 'Report')]
    [string]$Mode,
    [ValidateSet('en', 'pl')]
    [string]$Lang = 'en',
    [switch]$NoAnimate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# UTF-8 na wyjściu konsoli — KLUCZOWE, żeby logo (znaki blokowe ▄█ i ramki) się nie
# rozjeżdżało. Bez tego wieloбajtowe znaki zajmują złą liczbę kolumn i art "tańczy".
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$script:VERSION  = '2.0.0'
$script:ROOT     = $PSScriptRoot
$script:LINKEDIN = 'https://www.linkedin.com/in/daniel-b-4295a421a/'
$script:GITHUB   = 'https://github.com/NewLife-Org/AccessGuy'
$script:YOUTUBE  = 'https://www.youtube.com/@NewLife-org-pl'

# i18n: domyślnie EN, przełączalny w menu [L] albo parametrem -Lang. Dot-source zasobu napisów.
. (Join-Path $script:ROOT 'scanner/lib/Strings.ps1')
# Ochrona wyniku (7-Zip / AES-256) — używana po zbudowaniu raportu. Self-contained (własny logger),
# więc nie wymaga reszty biblioteki skanera w kontekście launchera.
. (Join-Path $script:ROOT 'scanner/lib/Protect.ps1')
# Common.ps1 — KANONiczna lista scope'ów Graph (Get-AgRequiredScopes) dla ekranu [D] Dependencies,
# żeby nie duplikować listy uprawnień. Definiuje same funkcje (bez efektów ubocznych przy load).
. (Join-Path $script:ROOT 'scanner/lib/Common.ps1')
$script:AgLang = $Lang

# === ZNAK TOWAROWY (skopiowany 1:1 z XDR-Creeper) ============================
$script:TATTOO_LOGO = @"
                                             :       ====:.-:..........
                             .==:     =--+-+-:+ .. :=-+=--=.-          .
                      :+=-  +-  .+=+--+   -====#-   +##= :+=+==+====++ +-
                -   :+:  .=-   ++ ===-==+=- +#=++++*- -*#===:          *.
              -= --+-   =- :+=  --+ -=*+####+*****- ++==-*#:=======+=-=======
            -+   =:   ++   +=.++:-==+:###-+##--=-------:--=##-      -=      =:::::::::::-+.
          ++   +=            +==:+-**##+     *#*====------=:*##=+.+--+ ++    ==+++-.  -:
 ==                            --++##+        *#*#========++=
-+-#****************************-###=          +##+-=-+=====:+:=.=:==.+=:+=:+=-+=
 -===+==+================+-==- --###=        =##+*:=-=+: ==-=
       *  =  ------------== -= -::- +###-  =##+*-+-=:=-=-=-
       + =+                =----=-==:==##*##**:===-=--                       =
    ==:=-=--=:=-==.=-:=-==:=-==:=+=+=-==*#**-========:-=:  -+   :=   -+  -*:=-
                   =+=+===+-     =-  =-+- -=-+-==-=-    =.=-  :=: ==*: :+:+-
                           .====-    +- =-  =:  =:+-=-  +-+  +-      .+:=.
                                      :+   -=:-=      +=   --
                                             -  =+
"@

# === access_guy_logo =========================================================
$script:ACCESS_GUY_LOGO = @"
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

$script:ACCESS_GUY_TEXT = @"
   _____                                       ________
  /  _  \   ____  ____  ____   ______ ______  /  _____/ __ __ ___.__.
 /  /_\  \_/ ___\/ ___\/ __ \ /  ___//  ___/ /   \  ___|  |  <   |  |
/    |    \  \__\  \__\  ___/ \___ \ \___ \  \    \_\  \  |  /\___  |
\____|__  /\___  >___  >___  >____  >____  >  \______  /____/ / ____|
        \/     \/    \/    \/     \/     \/          \/       \/
 _______                .__  .__  _____
 \      \   ______  _  _|  | |__|/ ____\____
 /   |   \_/ __ \ \/ \/ /  | |  \   __\/ __ \
/    |    \  ___/\     /|  |_|  ||  | \  ___/
\____|__  /\___  >\/\_/ |____/__||__|  \___  >
        \/     \/                          \/
"@

# --- Bezpieczne wypisanie artu: linia po linii, od czystego wiersza ----------
# Daniel zgłosił, że w XDR pierwsza linia logo bywa rozjechana. Powody: kursor nie
# stoi na początku wiersza albo terminal zawija. Tu wymuszamy świeży wiersz, tniemy
# po `n i wypisujemy każdą linię osobno — żaden -NoNewline nie doklei się przed art.
function Write-AgArt {
    param([Parameter(Mandatory)] [string]$Art, [ConsoleColor]$Color = [ConsoleColor]::Cyan)
    Write-Host ''                                  # gwarantowany start od kolumny 0
    foreach ($line in ($Art -split "`r?`n")) {
        Write-Host $line -ForegroundColor $Color
    }
}

# Interpolacja koloru (t: 0..1) start->end w 24-bit truecolor (ANSI). Daje PŁYNNE przejście
# barw, czego 16-kolorowe ConsoleColor nie potrafi (stąd dawny SKOKOWY DarkCyan->Cyan->White).
$script:AnsiReset = "$([char]27)[0m"
function Get-AgAnsiColor {
    param([double]$T, [int[]]$From = @(40, 120, 255), [int[]]$To = @(240, 248, 255))
    if ($T -lt 0) { $T = 0 } elseif ($T -gt 1) { $T = 1 }
    $r = [int][math]::Round($From[0] + ($To[0] - $From[0]) * $T)
    $g = [int][math]::Round($From[1] + ($To[1] - $From[1]) * $T)
    $b = [int][math]::Round($From[2] + ($To[2] - $From[2]) * $T)
    return "$([char]27)[38;2;$r;$g;${b}m"
}

# === ANIMACJA INTRO (port z XDR-Creeper, z poprawką startu wiersza) ==========
function Show-AgIntro {
    [Console]::CursorVisible = $false
    $glitch    = "accessguy01<>"
    $logoLines = $script:TATTOO_LOGO -split "`r?`n"
    $duration  = 3000
    $frameDelay = 50
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while ($sw.ElapsedMilliseconds -lt $duration) {
        $progress = [int]($sw.ElapsedMilliseconds * 100 / $duration)
        $frameColor = Get-AgAnsiColor -T ($progress / 100.0)   # płynny niebieski -> biały wg postępu
        Clear-Host
        Write-Host ''                              # świeży wiersz — anty-rozjazd 1. linii
        foreach ($line in $logoLines) {
            $outLine = ''
            for ($j = 0; $j -lt $line.Length; $j++) {
                $ch = $line[$j]
                if ($ch -eq ' ') {
                    if ((Get-Random -Minimum 0 -Maximum 50) -eq 0) { $outLine += $glitch[(Get-Random -Maximum $glitch.Length)] }
                    else { $outLine += ' ' }
                }
                elseif ((Get-Random -Minimum 0 -Maximum 100) -lt $progress) { $outLine += $ch }
                elseif ((Get-Random -Minimum 0 -Maximum 100) -lt 80) { $outLine += $ch }
                else { $outLine += $glitch[(Get-Random -Maximum $glitch.Length)] }
            }
            Write-Host ($frameColor + $outLine + $script:AnsiReset)
        }
        Start-Sleep -Milliseconds $frameDelay
    }
    $sw.Stop()

    Clear-Host
    Write-AgArt -Art $script:TATTOO_LOGO -Color White
    Write-Host ''
    Write-Host '                              -- N E W L I F E   //   A C C E S S   G U Y --' -ForegroundColor Cyan
    Start-Sleep -Milliseconds 700
    [Console]::CursorVisible = $true
}

# === ODBLOKOWANIE SKRYPTÓW (fix "5x ta sama komenda") ========================
# Na Windows pliki ściągnięte z internetu mają "Mark of the Web" => każde odpalenie
# pyta/blokuje. Skoro launcher i tak zna lokalizację repo, jednym ruchem zdejmujemy
# blokadę ze WSZYSTKICH skryptów pakietu i podnosimy ExecutionPolicy w procesie.
function Unblock-AgScripts {
    $unblocked = [System.Collections.Generic.List[string]]::new()

    # Set-ExecutionPolicy / Unblock-File mają sens TYLKO na Windows (Mark of the Web + polityka).
    # Na Linux/macOS skrypty i tak odpalają się swobodnie — uznajemy je za "dopuszczone" od razu.
    if ($IsWindows) {
        try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue } catch { }
    }

    $files = Get-ChildItem -Path $script:ROOT -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        $unblocked.Add($f.Name)        # najpierw oznacz jako dopuszczony (niezależnie od OS)
        if ($IsWindows) {
            try { Unblock-File -LiteralPath $f.FullName -ErrorAction SilentlyContinue } catch { }
        }
    }
    return $unblocked
}

# === PANEL AccessGuy =========================================================
function Show-AgPanel {
    param([string[]]$Authorized)

    Clear-Host
    Write-AgArt -Art $script:ACCESS_GUY_LOGO -Color Cyan
    Write-AgArt -Art $script:ACCESS_GUY_TEXT -Color White

    Write-Host ''
    Write-Host "  $(T 'panel.subtitle')" -ForegroundColor Gray
    Write-Host ''
    Write-Host "  $(T 'panel.author')" -ForegroundColor DarkGray -NoNewline; Write-Host 'Daniel "NewLife" Budyn' -ForegroundColor White
    Write-Host '  LinkedIn: ' -ForegroundColor DarkGray -NoNewline; Write-Host $script:LINKEDIN -ForegroundColor Blue
    Write-Host '  GitHub:   ' -ForegroundColor DarkGray -NoNewline; Write-Host $script:GITHUB -ForegroundColor Blue
    Write-Host '  YouTube:  ' -ForegroundColor DarkGray -NoNewline; Write-Host $script:YOUTUBE -ForegroundColor Red
    Write-Host ''
    # Status komponentów/autoryzacji + diagnostyka przeniesione do [D] Dependencies (czystszy panel).
    Write-Host "  $(T 'panel.deps_hint')" -ForegroundColor DarkGray
    Write-Host ''
}

# === [D] DEPENDENCIES / KOMPONENTY (sprawdzenie przed skanem) ================
# Wiersz statusu ✔/✘ z etykietą, szczegółem i opcjonalną notą.
function Write-AgDepRow {
    param([bool]$Ok, [string]$Label, [string]$Detail, [string]$Note, [int]$LabelWidth = 16)
    $mark = if ($Ok) { '✔' } else { '✘' }
    $mc = if ($Ok) { [ConsoleColor]::Green } else { [ConsoleColor]::Red }
    Write-Host '      [' -ForegroundColor DarkGray -NoNewline
    Write-Host $mark -ForegroundColor $mc -NoNewline
    Write-Host '] ' -ForegroundColor DarkGray -NoNewline
    Write-Host ("{0,-$LabelWidth} " -f $Label) -ForegroundColor White -NoNewline
    Write-Host $Detail -ForegroundColor Gray
    if ($Note) { Write-Host ('          ' + $Note) -ForegroundColor DarkGray }
}

# Test realnego dostępu zapisu (tworzy katalog jeśli brak, pisze i kasuje plik-próbkę).
function Test-AgWritable {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -ItemType Directory -Force -Path $Path -ErrorAction Stop }
        $probe = Join-Path $Path ('.agwrite_' + [guid]::NewGuid().ToString('N'))
        Set-Content -LiteralPath $probe -Value 'ag' -ErrorAction Stop
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch { return $false }
}

function Show-AgDependencies {
    param([string[]]$Authorized)
    Clear-Host
    Write-Host ''
    Write-Host ('  ' + (T 'deps.title')) -ForegroundColor Cyan
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkCyan

    # 1) KOMPONENTY pakietu (dawny box z panelu) ------------------------------
    Write-Host ''
    Write-Host ('  [#] ' + (T 'deps.sec.components')) -ForegroundColor White
    if ($Authorized -and $Authorized.Count -gt 0) {
        foreach ($name in ($Authorized | Sort-Object -Unique)) {
            Write-Host '      [' -ForegroundColor DarkGray -NoNewline
            Write-Host '✔' -ForegroundColor Green -NoNewline
            Write-Host '] ' -ForegroundColor DarkGray -NoNewline
            Write-Host ("{0,-26}" -f $name) -ForegroundColor Gray -NoNewline
            Write-Host (T 'panel.unblocked') -ForegroundColor DarkGreen
        }
        Write-Host ('      ' + ((T 'panel.consents') -f $Authorized.Count)) -ForegroundColor DarkGreen
    }
    else {
        Write-Host ('      ' + (T 'panel.none_unblock')) -ForegroundColor DarkGray
    }

    # 2) GRAPH API — które uprawnienia i po co ---------------------------------
    Write-Host ''
    Write-Host ('  [#] ' + (T 'deps.sec.graph')) -ForegroundColor White
    $required = @('User.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.All')
    $purpose = @{
        'User.Read.All'                     = 'deps.scope.user'
        'Directory.Read.All'                = 'deps.scope.directory'
        'AuditLog.Read.All'                 = 'deps.scope.audit'
        'RoleManagement.Read.All'           = 'deps.scope.role'
        'Application.Read.All'              = 'deps.scope.app'
        'UserAuthenticationMethod.Read.All' = 'deps.scope.authmethod'
        'Policy.Read.All'                   = 'deps.scope.policy'
        'IdentityRiskyUser.Read.All'        = 'deps.scope.risky'
    }
    $scopes = if (Get-Command Get-AgRequiredScopes -ErrorAction SilentlyContinue) { Get-AgRequiredScopes } else { @($purpose.Keys) }
    foreach ($s in $scopes) {
        $tag = if ($required -contains $s) { T 'deps.required' } else { T 'banner.recommended' }
        Write-Host ('      [*] ' + ("{0,-34}" -f $s)) -ForegroundColor Gray -NoNewline
        Write-Host (' ' + ("{0,-13}" -f $tag)) -ForegroundColor DarkCyan -NoNewline
        $desc = if ($purpose.ContainsKey($s)) { '  — ' + (T $purpose[$s]) } else { '' }
        Write-Host $desc -ForegroundColor DarkGray
    }

    # 3) ŚRODOWISKO / narzędzia zewnętrzne ------------------------------------
    Write-Host ''
    Write-Host ('  [#] ' + (T 'deps.sec.runtime')) -ForegroundColor White
    $py = Get-AgPython
    if ($py) { Write-AgDepRow -Ok $true  -Label 'Python 3.11+' -Detail ("{0}  ({1})" -f $py.Version, $py.Exe) -Note (T 'deps.python_purpose') }
    else { Write-AgDepRow -Ok $false -Label 'Python 3.11+' -Detail (T 'deps.notfound') -Note (T 'deps.python_purpose') }
    $sevenZip = if (Get-Command Find-Ag7Zip -ErrorAction SilentlyContinue) { Find-Ag7Zip } else { $null }
    if ($sevenZip) { Write-AgDepRow -Ok $true  -Label '7-Zip' -Detail $sevenZip -Note (T 'deps.sevenzip_purpose') }
    else { Write-AgDepRow -Ok $false -Label '7-Zip' -Detail (T 'deps.notfound') -Note (T 'deps.sevenzip_purpose') }

    # 4) DOSTĘP DO FOLDERÓW WYJŚCIOWYCH (read/write) ---------------------------
    Write-Host ''
    Write-Host ('  [#] ' + (T 'deps.sec.output')) -ForegroundColor White
    foreach ($pair in @(
            @{ Path = (Join-Path $script:ROOT 'out');     Label = (T 'deps.out_dir') },
            @{ Path = (Join-Path $script:ROOT 'reports'); Label = (T 'deps.reports_dir') }
        )) {
        $w = Test-AgWritable -Path $pair.Path
        $detail = if ($w) { T 'deps.writable' } else { T 'deps.not_writable' }
        Write-AgDepRow -Ok $w -Label $pair.Label -Detail ("{0}   {1}" -f $detail, $pair.Path) -LabelWidth 28
    }

    Write-Host ''
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkCyan
}

# === WYKRYCIE PYTHONA ========================================================
function Get-AgPython {
    foreach ($cand in @('python3', 'python', 'py')) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $ver = & $cmd.Source --version 2>&1
            if ($ver -match 'Python\s+3\.(\d+)') {
                if ([int]$matches[1] -ge 11) { return [pscustomobject]@{ Exe = $cmd.Source; Version = "$ver".Trim() } }
            }
        } catch { }
    }
    return $null
}

# === TRYB 1: SKANER ==========================================================
function Invoke-AgScanMode {
    $scanner = Join-Path $script:ROOT 'scanner/Invoke-AccessGuyScan.ps1'
    if (-not (Test-Path -LiteralPath $scanner)) {
        Write-Host ((T 'scan.not_found') -f $scanner) -ForegroundColor Red
        return
    }
    Write-Host (T 'scan.header') -ForegroundColor Cyan
    Write-Host (T 'scan.login_hint') -ForegroundColor DarkGray
    Write-Host ''

    # Zakres skanu — które moduły zebrać (jeden skan, wspólny dataset 1.2).
    Write-Host (T 'scan.scope_title') -ForegroundColor White
    Write-Host '    [1] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'scan.scope_all') -ForegroundColor White -NoNewline; Write-Host (T 'scan.scope_all_d') -ForegroundColor DarkGray
    Write-Host '    [2] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'scan.scope_users') -ForegroundColor White -NoNewline; Write-Host (T 'scan.scope_users_d') -ForegroundColor DarkGray
    Write-Host '    [3] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'scan.scope_groups') -ForegroundColor White -NoNewline; Write-Host (T 'scan.scope_groups_d') -ForegroundColor DarkGray
    Write-Host '    [4] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'scan.scope_apps') -ForegroundColor White -NoNewline; Write-Host (T 'scan.scope_apps_d') -ForegroundColor DarkGray
    $scopeChoice = (Read-Host (T 'scan.scope_prompt')).Trim()
    $scope = switch ($scopeChoice) { '2' { 'Users' } '3' { 'Groups' } '4' { 'Apps' } default { 'All' } }
    Write-Host ''

    Write-Host (T 'scan.login_title') -ForegroundColor White
    Write-Host '    [1] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'scan.login_browser') -ForegroundColor White -NoNewline; Write-Host (T 'scan.login_browser_d') -ForegroundColor DarkGray
    Write-Host '    [2] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'scan.login_device') -ForegroundColor White -NoNewline; Write-Host (T 'scan.login_device_d') -ForegroundColor DarkGray
    $loginChoice = (Read-Host (T 'scan.login_prompt')).Trim()
    Write-Host ''
    if ($loginChoice -eq '2') {
        & $scanner -LiteReport -DeviceCode -Scope $scope -Lang $script:AgLang
    }
    else {
        & $scanner -LiteReport -Scope $scope -Lang $script:AgLang
    }
}

# === TRYB 2: BUILDER RAPORTU =================================================
function Invoke-AgReportMode {
    Write-Host (T 'report.header') -ForegroundColor Cyan
    Write-Host (T 'report.requires') -ForegroundColor DarkGray
    Write-Host ''

    $py = Get-AgPython
    if (-not $py) {
        Write-Host (T 'report.no_python') -ForegroundColor Red
        Write-Host (T 'report.install_hint') -ForegroundColor DarkGray
        return
    }
    Write-Host ((T 'report.detected') -f $py.Version, $py.Exe) -ForegroundColor Green

    $processor = Join-Path $script:ROOT 'processor'
    if (-not (Test-Path -LiteralPath $processor)) {
        Write-Host ((T 'report.no_proc') -f $processor) -ForegroundColor Red
        return
    }

    Push-Location $processor
    try {
        # KLUCZOWE na Debian/Kali (PEP 668): system Python jest "externally-managed" i
        # globalny `pip install` po cichu odmawia. Dlatego builder działa we WŁASNYM venv
        # (processor/.venv) — izolacja, zero zaśmiecania systemu, działa pod sudo i bez.
        $venvPy = if ($IsWindows) { Join-Path $processor '.venv/Scripts/python.exe' } else { Join-Path $processor '.venv/bin/python' }

        if (-not (Test-Path -LiteralPath $venvPy)) {
            Write-Host (T 'report.venv_create') -ForegroundColor Cyan
            & $py.Exe -m venv .venv 2>&1 | Out-Null
            if (-not (Test-Path -LiteralPath $venvPy)) {
                Write-Host (T 'report.venv_fail') -ForegroundColor Red
                Write-Host (T 'report.venv_fail_cmd') -ForegroundColor Yellow
                return
            }
        }

        Write-Host (T 'report.deps') -ForegroundColor Cyan
        & $venvPy -m pip install --quiet --upgrade pip 2>&1 | Out-Null
        & $venvPy -m pip install --quiet -e '.[pdf]' 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host (T 'report.pdf_fail') -ForegroundColor Yellow
            & $venvPy -m pip install --quiet -e '.' 2>&1 | Out-Null
        }
        # Twardy sanity-check: czy moduł faktycznie się zainstalował?
        & $venvPy -c 'import accessguy_processor' 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host (T 'report.install_fail') -ForegroundColor Red
            Write-Host (T 'report.try_manual') -ForegroundColor DarkGray
            return
        }
        Write-Host (T 'report.ready') -ForegroundColor Green
        Write-Host ''

        # Builder czyta ze WSPÓLNEGO katalogu out/ (tam pisze skaner) i pozwala wybrać plik.
        # Przekazujemy --lang, żeby raport i hakerski przebieg były w wybranym języku.
        $sharedOut = Join-Path $script:ROOT 'out'
        $reportsDir = Join-Path $script:ROOT 'reports'
        & $venvPy -m accessguy_processor build --dir $sharedOut --out $reportsDir --lang $script:AgLang

        # OCHRONA WYNIKU (OPCJONALNA, krok końcowy PO odczycie danych przez builder — pipeline nienaruszony):
        # builder zostawił .ag-manifest.json ze spisem raportów + użytego datasetu. Pytamy użytkownika
        # czy zaszyfrować; jeśli tak — pakujemy w JEDNO archiwum (7-Zip/AES-256), kasujemy jawne kopie
        # i pokazujemy hasło RAZ. Jeśli nie — zostawiamy jawne i sprzątamy manifest.
        if ($LASTEXITCODE -eq 0) {
            $manifest = Join-Path $reportsDir '.ag-manifest.json'
            if (Test-Path -LiteralPath $manifest) {
                Write-Host ''
                Write-Host ('  ' + (T 'protect.r2_note')) -ForegroundColor DarkGray
                if (Read-AgYesNo -Prompt (T 'protect.ask')) {
                    [void](Invoke-AgProtectFromManifest -ManifestPath $manifest)
                }
                else {
                    Remove-Item -LiteralPath $manifest -Force -ErrorAction SilentlyContinue
                    Write-Host ('  ' + (T 'protect.skipped')) -ForegroundColor DarkGray
                }
            }
        }
    }
    finally {
        Pop-Location
    }
}

# === MENU ====================================================================
function Show-AgMenu {
    Write-Host (T 'menu.choose') -ForegroundColor White
    Write-Host '    [1] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'menu.scan') -ForegroundColor White -NoNewline; Write-Host (T 'menu.scan_desc') -ForegroundColor DarkGray
    Write-Host '    [2] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'menu.report') -ForegroundColor White -NoNewline; Write-Host (T 'menu.report_desc') -ForegroundColor DarkGray
    Write-Host '    [D] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'menu.deps') -ForegroundColor White -NoNewline; Write-Host (T 'menu.deps_desc') -ForegroundColor DarkGray
    Write-Host '    [L] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'menu.language') -ForegroundColor White -NoNewline; Write-Host ("  $((T 'menu.lang_current') -f $script:AgLanguages[$script:AgLang])") -ForegroundColor DarkGray
    Write-Host '    [Q] ' -ForegroundColor Cyan -NoNewline; Write-Host (T 'menu.quit') -ForegroundColor White
    Write-Host ''
    return (Read-Host '  >')
}

# Wybór języka — przełącza $script:AgLang dla CAŁEJ sesji (panel, menu, skaner, builder).
function Set-AgLanguage {
    Write-Host ''
    $i = 0
    $codes = @()
    foreach ($code in $script:AgLanguages.Keys) {
        $i++
        $codes += $code
        $mark = if ($code -eq $script:AgLang) { '*' } else { ' ' }
        Write-Host "    [$i]$mark " -ForegroundColor Cyan -NoNewline
        Write-Host $script:AgLanguages[$code] -ForegroundColor White
    }
    $pick = (Read-Host "  $(T 'menu.lang_prompt')").Trim()
    if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $codes.Count) {
        $script:AgLang = $codes[[int]$pick - 1]
    }
}

# === MAIN ====================================================================
if (-not $NoAnimate) { Show-AgIntro }

$authorized = Unblock-AgScripts
Show-AgPanel -Authorized $authorized

if ($Mode -eq 'Scan')   { Invoke-AgScanMode;   return }
if ($Mode -eq 'Report') { Invoke-AgReportMode; return }

while ($true) {
    $choice = (Show-AgMenu).Trim().ToUpper()
    switch ($choice) {
        '1' { Invoke-AgScanMode;   break }
        '2' { Invoke-AgReportMode; break }
        'D' { Show-AgDependencies -Authorized $authorized; Write-Host ''; [void](Read-Host ('  ' + (T 'deps.back'))); Show-AgPanel -Authorized $authorized; continue }
        'L' { Set-AgLanguage; Show-AgPanel -Authorized $authorized; continue }
        'Q' { Write-Host "  $(T 'menu.bye')" -ForegroundColor Cyan; return }
        default { Write-Host "  $(T 'menu.unknown')" -ForegroundColor Yellow; continue }
    }
    Write-Host ''
    $again = Read-Host "  $(T 'menu.return')"
    if ($again.Trim().ToLower() -ne (T 'menu.return_yes')) { break }
    Show-AgPanel -Authorized $authorized
}
