#Requires -Version 7.0
<#
    AccessGuy Scanner — Auth.ps1
    Spójny interfejs auth niezależny od trybu. Cała logika "skąd token" jest tutaj;
    reszta skanera nie wie i nie musi wiedzieć, jak się zalogowaliśmy.

    Delegated -> audyt "z palca" u klienta (człowiek, MFA, nic nie zostaje).
    App       -> cykl/automatyzacja (Managed Identity zalecane; certyfikat z Key Vault; secret w ostateczności).
#>

# KLUCZOWE (Linux/device-code): Connect-MgGraph MUSI być wołany PŁASKO, na poziomie skryptu.
# Gdy jest zagnieżdżony w funkcjach, SDK buforuje komunikat device-code (URL+KOD) i nigdy go nie
# pokazuje — logowanie cicho wisi (potwierdzone: wariant płaski wypisuje kod, zagnieżdżony nie).
# Dlatego ta funkcja TYLKO przygotowuje hashtable parametrów; samo Connect-MgGraph @args robi
# skaner na swoim poziomie. Zwraca też pomocniczo opis trybu do logu.
function Get-AgConnectArgs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('Delegated', 'App')] [string]$Mode,
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertThumbprint,
        [switch]$UseManagedIdentity,
        [switch]$DeviceCode
    )

    switch ($Mode) {
        'Delegated' {
            Write-AgLog -Level INFO -Message (T 'auth.delegated')
            # ContextScope=Process => token TYLKO w pamięci procesu (bez zapisu na dysk).
            # Na Linux to omija GNOME keyring/libsecret (źródło natrętnego promptu o keyring).
            $params = @{ Scopes = (Get-AgRequiredScopes); NoWelcome = $true; ContextScope = 'Process' }
            if ($TenantId)  { $params.TenantId = $TenantId }
            if ($ClientId)  { $params.ClientId = $ClientId }
            if ($DeviceCode){
                $params.UseDeviceAuthentication = $true
                Write-AgLog -Level INFO -Message (T 'auth.devicecode')
            }
            return $params
        }
        'App' {
            if ($UseManagedIdentity) {
                Write-AgLog -Level INFO -Message (T 'auth.mi')
                return @{ Identity = $true; NoWelcome = $true }
            }
            if ($CertThumbprint) {
                if (-not $TenantId -or -not $ClientId) { throw (T 'auth.cert_needs') }
                Write-AgLog -Level INFO -Message (T 'auth.cert')
                return @{ TenantId = $TenantId; ClientId = $ClientId; CertificateThumbprint = $CertThumbprint; NoWelcome = $true }
            }
            throw (T 'auth.app_needs')
        }
    }
}

function Test-AgPreflight {
    <#
        Walidacja przed kolekcją: brakujące scope'y, dostępność signInActivity (P1/P2), kontekst operatora.
        Zwraca obiekt: @{ Operator; PremiumLicense; MissingScopes }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Connection)

    $granted = @($Connection.Scopes)
    $required = Get-AgRequiredScopes
    $missing = $required | Where-Object { $_ -notin $granted }
    if ($missing) {
        Write-AgLog -Level WARN -Message ((T 'auth.missing_scopes') -f ($missing -join ', '))
    }

    # Operator (delegated) lub null (app-only).
    $operator = $null
    if ($Connection.AuthType -eq 'Delegated') { $operator = $Connection.Account }

    # Test P1/P2: czy signInActivity zwraca dane (dostępne tylko z licencją premium).
    $premium = $false
    try {
        $probe = @(Invoke-AgGraphPaged -Uri '/users?$top=1&$select=id,signInActivity' -Beta)
        $premium = ($probe.Count -gt 0 -and $null -ne (Get-AgProp $probe[0] 'signInActivity'))
    }
    catch {
        Write-AgLog -Level WARN -Message (T 'auth.p2_unconfirmed')
    }
    if (-not $premium) {
        Write-AgLog -Level WARN -Message (T 'auth.no_p2')
    }

    [pscustomobject]@{
        Operator       = $operator
        PremiumLicense = $premium
        MissingScopes  = $missing
    }
}

function Get-AgVerifiedDomains {
    # Zweryfikowane domeny organizacji — podstawa klasyfikacji internal/external.
    try {
        $org = @(Invoke-AgGraphPaged -Uri '/organization?$select=verifiedDomains')
        if ($org.Count -gt 0) {
            return @(@(Get-AgProp $org[0] 'verifiedDomains') | ForEach-Object { Get-AgProp $_ 'name' } | Where-Object { $_ })
        }
    }
    catch {
        Write-AgLog -Level WARN -Message ((T 'auth.domains_fail') -f $_.Exception.Message)
    }
    return @()
}

function Disconnect-AccessGuy {
    param($Connection)
    try { Disconnect-MgGraph | Out-Null } catch { }
}
