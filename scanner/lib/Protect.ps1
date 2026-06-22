#Requires -Version 7.0
<#
    AccessGuy — Protect.ps1
    Ochrona wyniku: pakuje wskazane pliki w JEDNO zaszyfrowane archiwum (7-Zip, AES-256) z losowym
    hasłem. Hasło pokazujemy RAZ w konsoli i NIGDZIE nie zapisujemy — zgubione = archiwum nie do
    odzyskania. Krypto leży po stronie PowerShella (7-Zip), żeby Python pozostał OPCJONALNY:
    skaner działa i chroni dane bez Pythona.

    Filozofia bezpiecznego usuwania: kasujemy JAWNE pliki źródłowe DOPIERO po pomyślnym dodaniu
    ORAZ weryfikacji archiwum (7z t). Katalog staging to nasz własny temp (sprzątany w finally) —
    nigdy nie ruszamy plików spoza przekazanej listy. Brak 7-Zip => grzecznie pomijamy (ostrzeżenie),
    zostawiając pliki jawne (nie wywalamy procesu).
#>

# Logger odporny na kontekst: w skanerze użyje Write-AgLog (Common.ps1), w launcherze — Write-Host.
function Write-AgProtectLog {
    param([string]$Level = 'INFO', [Parameter(Mandatory)][string]$Message, [ConsoleColor]$Color = 'Cyan')
    if (Get-Command Write-AgLog -ErrorAction SilentlyContinue) { Write-AgLog -Level $Level -Message $Message }
    else { Write-Host ("  [{0,-5}] {1}" -f $Level, $Message) -ForegroundColor $Color }
}

# Prosty prompt tak/nie zgodny z językiem sesji (odpowiedź twierdząca = T 'protect.yes': y/t).
function Read-AgYesNo {
    param([Parameter(Mandatory)][string]$Prompt)
    $ans = (Read-Host ('  ' + $Prompt)).Trim().ToLower()
    return ($ans -eq (T 'protect.yes'))
}

function Find-Ag7Zip {
    # Binarka 7-Zip: PATH (7z/7za/7zz) + domyślne lokalizacje na Windows.
    foreach ($cand in @('7z', '7za', '7zz')) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    if ($IsWindows) {
        $paths = @()
        if ($env:ProgramFiles)        { $paths += (Join-Path $env:ProgramFiles '7-Zip\7z.exe') }
        if (${env:ProgramFiles(x86)}) { $paths += (Join-Path ${env:ProgramFiles(x86)} '7-Zip\7z.exe') }
        foreach ($p in $paths) { if (Test-Path -LiteralPath $p) { return $p } }
    }
    return $null
}

function New-AgPassword {
    # Silne losowe hasło (CSPRNG, bez biasu) z alfabetu bez znaków mylących i problematycznych dla shella.
    param([int]$Length = 28)
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#%+=?'
    -join (1..$Length | ForEach-Object {
        $alphabet[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($alphabet.Length)]
    })
}

function Protect-AgArchive {
    <#
        Pakuje $Files do zaszyfrowanego .7z (AES-256, -mhe=on => szyfrowane także nazwy plików).
        Pliki trafiają płasko (przez katalog staging), więc w archiwum są same nazwy bez ścieżek.
        Zwraca [pscustomobject] @{ Ok; Archive; Password }. Hasło pokazuje wołający (Show-AgArchivePassword).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]]$Files,
        [Parameter(Mandatory)] [string]$ArchivePath,
        [switch]$RemovePlaintext
    )
    $existing = @($Files | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -Unique)
    if ($existing.Count -eq 0) {
        Write-AgProtectLog -Level WARN -Message (T 'protect.nothing') -Color Yellow
        return [pscustomobject]@{ Ok = $false; Archive = $null; Password = $null }
    }

    $sevenZip = Find-Ag7Zip
    if (-not $sevenZip) {
        Write-AgProtectLog -Level WARN -Message (T 'protect.no7z') -Color Yellow
        return [pscustomobject]@{ Ok = $false; Archive = $null; Password = $null }
    }

    Write-AgProtectLog -Level INFO -Message (T 'protect.packing')
    $password = New-AgPassword
    $absArchive = [System.IO.Path]::GetFullPath($ArchivePath)
    if (Test-Path -LiteralPath $absArchive) { Remove-Item -LiteralPath $absArchive -Force -ErrorAction SilentlyContinue }
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $absArchive -Parent)

    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ('ag-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Force -Path $stage
    try {
        # Kopiujemy do staging płasko; kolizje nazw rozróżniamy prefiksem licznika.
        $used = @{}; $i = 0
        foreach ($f in $existing) {
            $name = Split-Path $f -Leaf
            if ($used.ContainsKey($name)) { $i++; $name = "${i}_$name" }
            $used[$name] = $true
            Copy-Item -LiteralPath $f -Destination (Join-Path $stage $name) -Force
        }

        # 7z a -t7z -mhe=on -p<hasło> -mx=5  (ciche: -bso0 -bsp0). cwd=staging => płaskie nazwy.
        Push-Location $stage
        try {
            & $sevenZip a -t7z -mhe=on "-p$password" -mx=5 -bso0 -bsp0 -- $absArchive '*' | Out-Null
            $okAdd = ($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $absArchive)
        }
        finally { Pop-Location }

        # Weryfikacja (integralność + poprawność hasła) ZANIM cokolwiek skasujemy.
        $okTest = $false
        if ($okAdd) {
            & $sevenZip t "-p$password" -bso0 -bsp0 -- $absArchive | Out-Null
            $okTest = ($LASTEXITCODE -eq 0)
        }

        if (-not ($okAdd -and $okTest)) {
            Write-AgProtectLog -Level ERROR -Message ((T 'protect.fail') -f "7z exit $LASTEXITCODE") -Color Red
            if (Test-Path -LiteralPath $absArchive) { Remove-Item -LiteralPath $absArchive -Force -ErrorAction SilentlyContinue }
            return [pscustomobject]@{ Ok = $false; Archive = $null; Password = $null }
        }

        Write-AgProtectLog -Level OK -Message ((T 'protect.done') -f $absArchive) -Color Green
        if ($RemovePlaintext) {
            foreach ($f in $existing) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
            Write-AgProtectLog -Level OK -Message (T 'protect.removed') -Color Green
        }
        return [pscustomobject]@{ Ok = $true; Archive = $absArchive; Password = $password }
    }
    finally {
        # Sprzątamy WYŁĄCZNIE własny katalog tymczasowy.
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Pokaż hasło RAZ, wyraźnie. Nigdzie go nie zapisujemy ani nie logujemy ponownie.
function Show-AgArchivePassword {
    param([Parameter(Mandatory)][string]$Password, [Parameter(Mandatory)][string]$Archive)
    Write-Host ''
    Write-Host '  +======================================================================+' -ForegroundColor Yellow
    Write-Host ('  |   {0,-66} |' -f (T 'protect.pw_title')) -ForegroundColor Yellow
    Write-Host '  +======================================================================+' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '      ' -NoNewline
    Write-Host $Password -ForegroundColor Black -BackgroundColor White
    Write-Host ''
    Write-Host ('    ' + (T 'protect.pw_warn')) -ForegroundColor DarkYellow
    Write-Host ('    -> ' + $Archive) -ForegroundColor DarkGray
    Write-Host '  +======================================================================+' -ForegroundColor Yellow
    Write-Host ''
}

# Orkiestracja: czyta .ag-manifest.json (zapisany przez procesor), pakuje raporty + dataset
# w jedno zaszyfrowane archiwum, usuwa jawne pliki i pokazuje hasło RAZ. Zwraca $true gdy ochrona OK.
function Invoke-AgProtectFromManifest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ManifestPath)

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $false }
    try { $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json }
    catch { return $false }

    $files = [System.Collections.Generic.List[string]]::new()
    foreach ($o in @($manifest.outputs)) { if ($o) { $files.Add([string]$o) } }
    $src = [string]$manifest.sourceDataset
    if ($src) {
        $files.Add($src)
        # Dołączamy też lekki raport ze skanera obok datasetu (jeśli jest) — to też dane tenanta.
        $lite = [System.IO.Path]::ChangeExtension($src, '.lite.html')
        if (Test-Path -LiteralPath $lite -PathType Leaf) { $files.Add($lite) }
    }

    # Nazwa archiwum: <baza raportu>_accessguy.7z (baza = nazwa pliku raportu bez sekcji), inaczej z czasem.
    $base = $null
    foreach ($o in @($manifest.outputs)) {
        $n = Split-Path ([string]$o) -Leaf
        if ($n -match '^(.*)_(summary|users|groups|apps|scored)\.[A-Za-z0-9]+$') { $base = $matches[1]; break }
    }
    if (-not $base) { $base = 'AccessGuy_' + (Get-Date).ToString('yyyyMMdd-HHmmss') }
    $reportsDir = Split-Path $ManifestPath -Parent
    $archivePath = Join-Path $reportsDir ("{0}_accessguy.7z" -f $base)

    $res = Protect-AgArchive -Files @($files.ToArray()) -ArchivePath $archivePath -RemovePlaintext
    # Manifest zawiera ścieżki — kasujemy go niezależnie od wyniku (to tylko spis, nie dane).
    Remove-Item -LiteralPath $ManifestPath -Force -ErrorAction SilentlyContinue
    if ($res.Ok) {
        Show-AgArchivePassword -Password $res.Password -Archive $res.Archive
        return $true
    }
    return $false
}
