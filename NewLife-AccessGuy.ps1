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
            if ($progress -lt 33)     { Write-Host $outLine -ForegroundColor DarkCyan }
            elseif ($progress -lt 66) { Write-Host $outLine -ForegroundColor Cyan }
            else                      { Write-Host $outLine -ForegroundColor White }
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
    Write-Host '  Read-only przegląd uprawnień Microsoft Entra ID' -ForegroundColor Gray
    Write-Host '  Autor: ' -ForegroundColor DarkGray -NoNewline; Write-Host 'Daniel "NewLife" Budyn' -ForegroundColor White
    Write-Host '  LinkedIn: ' -ForegroundColor DarkGray -NoNewline; Write-Host $script:LINKEDIN -ForegroundColor Blue
    Write-Host '  GitHub:   ' -ForegroundColor DarkGray -NoNewline; Write-Host $script:GITHUB -ForegroundColor Blue
    Write-Host ''

    # Status zgód/autoryzacji — Daniel chce widzieć, że WSZYSTKIE elementy są dopuszczone.
    Write-Host '  +--------------------------------------------------------------+' -ForegroundColor DarkGray
    Write-Host '  | STATUS AUTORYZACJI ELEMENTÓW PAKIETU                         |' -ForegroundColor White
    Write-Host '  +--------------------------------------------------------------+' -ForegroundColor DarkGray
    if ($Authorized -and $Authorized.Count -gt 0) {
        foreach ($name in ($Authorized | Sort-Object -Unique)) {
            Write-Host '    [' -ForegroundColor DarkGray -NoNewline
            Write-Host '✔' -ForegroundColor Green -NoNewline
            Write-Host '] ' -ForegroundColor DarkGray -NoNewline
            Write-Host "$name " -ForegroundColor Gray -NoNewline
            Write-Host '— odblokowany / dopuszczony' -ForegroundColor DarkGreen
        }
        Write-Host ''
        Write-Host "  Zgody uzyskane dla $($Authorized.Count) elementów — nie musisz już potwierdzać ręcznie." -ForegroundColor Green
    }
    else {
        Write-Host '    (nie znaleziono dodatkowych skryptów do odblokowania)' -ForegroundColor DarkGray
    }
    Write-Host ''
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
        Write-Host "  [-] Nie znaleziono skanera: $scanner" -ForegroundColor Red
        return
    }
    Write-Host '  >> AccessGuy-EntraID-Scanner — faza SKAN (read-only)' -ForegroundColor Cyan
    Write-Host '     Zaloguj się jako operator z rolą Global Reader (MFA OK).' -ForegroundColor DarkGray
    Write-Host ''

    # Zakres skanu — które moduły zebrać (jeden skan, wspólny dataset 1.2).
    Write-Host '  Zakres skanu (co zebrać):' -ForegroundColor White
    Write-Host '    [1] ' -ForegroundColor Cyan -NoNewline; Write-Host 'Wszystko' -ForegroundColor White -NoNewline; Write-Host '       — konta + grupy + aplikacje (zalecane)' -ForegroundColor DarkGray
    Write-Host '    [2] ' -ForegroundColor Cyan -NoNewline; Write-Host 'Konta' -ForegroundColor White -NoNewline; Write-Host '          — użytkownicy, role, MFA, logowania' -ForegroundColor DarkGray
    Write-Host '    [3] ' -ForegroundColor Cyan -NoNewline; Write-Host 'Grupy' -ForegroundColor White -NoNewline; Write-Host '          — inwentarz grup, właściciele, role/licencje grupowe' -ForegroundColor DarkGray
    Write-Host '    [4] ' -ForegroundColor Cyan -NoNewline; Write-Host 'Aplikacje' -ForegroundColor White -NoNewline; Write-Host '      — rejestracje, poświadczenia, uprawnienia app/delegated' -ForegroundColor DarkGray
    $scopeChoice = (Read-Host '  > [Enter = 1]').Trim()
    $scope = switch ($scopeChoice) { '2' { 'Users' } '3' { 'Groups' } '4' { 'Apps' } default { 'All' } }
    Write-Host ''

    Write-Host '  Metoda logowania:' -ForegroundColor White
    Write-Host '    [1] ' -ForegroundColor Cyan -NoNewline; Write-Host 'Przeglądarka' -ForegroundColor White -NoNewline; Write-Host '  — otworzy okno logowania (wymaga GUI)' -ForegroundColor DarkGray
    Write-Host '    [2] ' -ForegroundColor Cyan -NoNewline; Write-Host 'Kod (device code)' -ForegroundColor White -NoNewline; Write-Host ' — dostaniesz URL + kod, potwierdzasz w Authenticatorze (zalecane na Linux)' -ForegroundColor DarkGray
    $loginChoice = (Read-Host '  >').Trim()
    Write-Host ''
    if ($loginChoice -eq '2') {
        & $scanner -LiteReport -DeviceCode -Scope $scope
    }
    else {
        & $scanner -LiteReport -Scope $scope
    }
}

# === TRYB 2: BUILDER RAPORTU =================================================
function Invoke-AgReportMode {
    Write-Host '  >> AccessGuy-Report-Builder — faza RAPORT  (raport idealny do przeglądu dla zarządu)' -ForegroundColor Cyan
    Write-Host '     Wymaga: Python 3.11+' -ForegroundColor DarkGray
    Write-Host ''

    $py = Get-AgPython
    if (-not $py) {
        Write-Host '  [-] Nie wykryto Pythona 3.11+ . Zainstaluj Python 3 i uruchom tryb [2] ponownie.' -ForegroundColor Red
        Write-Host '      Windows: winget install Python.Python.3.12   ·   Linux: sudo apt install python3 python3-venv' -ForegroundColor DarkGray
        return
    }
    Write-Host "  [+] Wykryto: $($py.Version)  ($($py.Exe))" -ForegroundColor Green

    $processor = Join-Path $script:ROOT 'processor'
    if (-not (Test-Path -LiteralPath $processor)) {
        Write-Host "  [-] Nie znaleziono katalogu procesora: $processor" -ForegroundColor Red
        return
    }

    Push-Location $processor
    try {
        # KLUCZOWE na Debian/Kali (PEP 668): system Python jest "externally-managed" i
        # globalny `pip install` po cichu odmawia. Dlatego builder działa we WŁASNYM venv
        # (processor/.venv) — izolacja, zero zaśmiecania systemu, działa pod sudo i bez.
        $venvPy = if ($IsWindows) { Join-Path $processor '.venv/Scripts/python.exe' } else { Join-Path $processor '.venv/bin/python' }

        if (-not (Test-Path -LiteralPath $venvPy)) {
            Write-Host '  [*] Tworzę środowisko (venv) buildera (jednorazowo)...' -ForegroundColor Cyan
            & $py.Exe -m venv .venv 2>&1 | Out-Null
            if (-not (Test-Path -LiteralPath $venvPy)) {
                Write-Host '  [-] Nie udało się utworzyć venv. Na Kali/Debian doinstaluj:' -ForegroundColor Red
                Write-Host '      sudo apt install -y python3-venv' -ForegroundColor Yellow
                return
            }
        }

        Write-Host '  [*] Instaluję zależności buildera (jednorazowo)...' -ForegroundColor Cyan
        & $venvPy -m pip install --quiet --upgrade pip 2>&1 | Out-Null
        & $venvPy -m pip install --quiet -e '.[pdf]' 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host '  [!] Wariant [pdf] nieudany (brak bibliotek systemowych dla PDF). Instaluję bez PDF (HTML i tak ładniejszy)...' -ForegroundColor Yellow
            & $venvPy -m pip install --quiet -e '.' 2>&1 | Out-Null
        }
        # Twardy sanity-check: czy moduł faktycznie się zainstalował?
        & $venvPy -c 'import accessguy_processor' 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host '  [-] Instalacja buildera nie powiodła się (moduł accessguy_processor niedostępny).' -ForegroundColor Red
            Write-Host '      Spróbuj ręcznie:  cd processor && python3 -m venv .venv && .venv/bin/pip install -e .' -ForegroundColor DarkGray
            return
        }
        Write-Host '  [+] Builder gotowy.' -ForegroundColor Green
        Write-Host ''

        # Builder czyta ze WSPÓLNEGO katalogu out/ (tam pisze skaner) i pozwala wybrać plik.
        $sharedOut = Join-Path $script:ROOT 'out'
        $reportsDir = Join-Path $script:ROOT 'reports'
        & $venvPy -m accessguy_processor build --dir $sharedOut --out $reportsDir
    }
    finally {
        Pop-Location
    }
}

# === MENU ====================================================================
function Show-AgMenu {
    Write-Host '  Wybierz tryb:' -ForegroundColor White
    Write-Host '    [1] ' -ForegroundColor Cyan -NoNewline; Write-Host 'AccessGuy-EntraID-Scanner   ' -ForegroundColor White -NoNewline; Write-Host '— skan tenanta (PowerShell, read-only)' -ForegroundColor DarkGray
    Write-Host '    [2] ' -ForegroundColor Cyan -NoNewline; Write-Host 'AccessGuy-Report-Builder    ' -ForegroundColor White -NoNewline; Write-Host '— raport dla zarządu (python3 required)' -ForegroundColor DarkGray
    Write-Host '    [Q] ' -ForegroundColor Cyan -NoNewline; Write-Host 'Wyjście' -ForegroundColor White
    Write-Host ''
    return (Read-Host '  >')
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
        'Q' { Write-Host '  Do zobaczenia!' -ForegroundColor Cyan; return }
        default { Write-Host '  Nieznana opcja. Wpisz 1, 2 albo Q.' -ForegroundColor Yellow; continue }
    }
    Write-Host ''
    $again = Read-Host '  Wrócić do menu? [t/N]'
    if ($again.Trim().ToLower() -ne 't') { break }
    Show-AgPanel -Authorized $authorized
}
