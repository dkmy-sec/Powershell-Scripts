<#
.SYNOPSIS
  Find likely "ghost SPNs" in Active Directory.

.DESCRIPTION
  Flags SPNs that:
    - Point to hostnames that do not resolve in DNS
    - Point to hosts that do not exist in AD
    - Are attached to disabled principals
    - Are duplicated across multiple principals

.PARAMETER Domain
  Optional AD domain (defaults to current).

.PARAMETER SearchBase
  Optional LDAP search base to limit scope.

.PARAMETER CsvPath
  Optional path to export results as CSV.

.PARAMETER SkipDns
  Skip DNS lookups (useful when DNS is firewalled). Still checks AD existence & duplicates.

.PARAMETER TimeoutMs
  Milliseconds to wait for DNS resolution before failing.

.EXAMPLE
  .\Find-GhostSpns.ps1 -CsvPath .\ghost_spns.csv

.NOTES
  Author: Kei Nova
  Insturctions:  Run with Windows PowerShell 
#>
[CmdletBinding()]
param(
  [string]$Domain,
  [string]$SearchBase,
  [string]$CsvPath,
  [switch]$SkipDns,
  [int]$TimeoutMs = 1500
)

function Resolve-HostSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [int]$TimeoutMs = 1500
    )
    if ([string]::IsNullOrWhiteSpace($Name)) {
        return [pscustomobject]@{
            Name       = $Name
            Resolves   = $false
            Canonical  = $null
            Addresses  = @()
            Error      = "Empty hostname"
        }
    }

    if ($Name -match '^\d{1,3}(\.\d{1,3}){3}$') {
        # It's an IPv4 literal; consider it "resolves"
        return [pscustomobject]@{
            Name       = $Name
            Resolves   = $true
            Canonical  = $Name
            Addresses  = @($Name)
            Error      = $null
        }
    }

    try {
        $resolved = Resolve-DnsName -Name $Name -Type A -ErrorAction Stop
        $ips = $resolved | Where-Object {$_.Type -eq 'A'} | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue
        return [pscustomobject]@{
            Name       = $Name
            Resolves   = ($ips -and $ips.Count -gt 0)
            Canonical  = ($resolved | Select-Object -First 1).NameHost
            Addresses  = $ips
            Error      = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Name       = $Name
            Resolves   = $false
            Canonical  = $null
            Addresses  = @()
            Error      = $_.Exception.Message
        }
    }
}

function Parse-Spn {
    param(
        [Parameter(Mandatory)]
        [string]$Spn
    )
    # Accept formats: service/host, service/host:port, service/host/extra
    $service,$rest = $Spn.Split('/',2)
    if (-not $rest) {
        return [pscustomobject]@{
            Service = $service
            Host    = $null
            Port    = $null
            Raw     = $Spn
        }
    }

    $hostPort = $rest.Split('/',2)[0]
    $spnHost = $null
    $spnPort = $null

    $tmp = $hostPort.Split(':',2)
    if ($tmp.Count -ge 1) { $spnHost = $tmp[0] }
    if ($tmp.Count -ge 2) { $spnPort = $tmp[1] }

    return [pscustomobject]@{
        Service = $service
        Host    = $spnHost
        Port    = $spnPort
        Raw     = $Spn
    }
}

# --- Gather principals with SPNs ---
Write-Verbose "Querying AD for objects with servicePrincipalName..."
$commonParams = @{}
if ($Domain)     { $commonParams['Server'] = $Domain }
if ($SearchBase) { $commonParams['SearchBase'] = $SearchBase }

try {
    $principals = Get-ADObject -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, samAccountName, objectClass, userAccountControl, enabled, dnsHostName, distinguishedName @commonParams
}
catch {
    Write-Error "Failed to query AD. Ensure RSAT AD module is installed and you have permissions. $_"
    return
}

# Index AD computers by dnsHostName and Name
Write-Verbose "Building AD computer index..."
$computers = Get-ADComputer -Filter * -Properties dnsHostName, distinguishedName, enabled @commonParams
$byDns   = @{}
$byName  = @{}
foreach ($c in $computers) {
    if ($c.dnsHostName) { $byDns[$c.dnsHostName.ToLower()] = $c }
    if ($c.Name)        { $byName[$c.Name.ToLower()]        = $c }
}

# Flatten SPNs
$rows = New-Object System.Collections.Generic.List[object]
foreach ($p in $principals) {
    $spns = @()
    if ($p.servicePrincipalName) { $spns = $p.servicePrincipalName }
    foreach ($spn in $spns) {
        $parsed = Parse-Spn -Spn $spn

        $fqdn = $null
        $adComputer = $null
        $dns = $null
        $reasons = New-Object System.Collections.Generic.List[string]

        if ($parsed.Host) {
            # If short host and Domain supplied, append to try as FQDN
            if ($parsed.Host -notmatch '\.' -and $Domain) {
                $fqdn = ("{0}.{1}" -f $parsed.Host, $Domain).ToLower()
            } else {
                $fqdn = $parsed.Host.ToLower()
            }

            if (-not $SkipDns -and -not [string]::IsNullOrWhiteSpace($fqdn)) {
                $dns = Resolve-HostSafe -Name $fqdn -TimeoutMs $TimeoutMs
                if (-not $dns.Resolves) { $reasons.Add("DNS_NOT_RESOLVING") | Out-Null }
            }

            # Check AD computer existence (by FQDN then short name)
            if (-not [string]::IsNullOrWhiteSpace($fqdn) -and $byDns.ContainsKey($fqdn)) {
                $adComputer = $byDns[$fqdn]
            } elseif ($byName.ContainsKey($parsed.Host.ToLower())) {
                $adComputer = $byName[$parsed.Host.ToLower()]
            }

            if (-not $adComputer) {
                $reasons.Add("NO_MATCHING_AD_COMPUTER") | Out-Null
            } else {
                if ($adComputer.Enabled -eq $false) {
                    $reasons.Add("TARGET_COMPUTER_DISABLED") | Out-Null
                }
            }
        } else {
            $reasons.Add("SPN_MISSING_HOST") | Out-Null
        }

        # Principal disabled?
        $isDisabled = $false
        if ($null -ne $p.Enabled) {
            $isDisabled = -not [bool]$p.Enabled
        } elseif ($p.userAccountControl) {
            $isDisabled = ([int]$p.userAccountControl -band 0x2) -ne 0
        }
        if ($isDisabled) { $reasons.Add("PRINCIPAL_DISABLED") | Out-Null }

        # Precompute optional fields (no inline if in hashtables)
        $dnsResolves   = $null
        $dnsAddresses  = $null
        if ($dns) {
            $dnsResolves  = $dns.Resolves
            if ($dns.Addresses) { $dnsAddresses = ($dns.Addresses -join ';') }
        }
        $adComputerDN        = $null
        $adComputerDisabled  = $null
        if ($adComputer) {
            $adComputerDN       = $adComputer.distinguishedName
            $adComputerDisabled = -not [bool]$adComputer.Enabled
        }

        $rows.Add([pscustomobject]@{
            SPN                 = $spn
            Service             = $parsed.Service
            Host                = $parsed.Host
            Port                = $parsed.Port
            PrincipalDN         = $p.distinguishedName
            PrincipalSAM        = $p.samAccountName
            PrincipalClass      = $p.objectClass
            PrincipalDisabled   = $isDisabled
            FQDN                = $fqdn
            DNSResolves         = $dnsResolves
            DNSAddresses        = $dnsAddresses
            ADComputerDN        = $adComputerDN
            ADComputerDisabled  = $adComputerDisabled
            Reasons             = ($reasons -join ';')
        }) | Out-Null
    }
}

# Duplicate detection (same SPN on multiple principals)
$dupes = $rows | Group-Object -Property SPN | Where-Object { $_.Count -gt 1 }
$dupeMap = @{}
foreach ($g in $dupes) { $dupeMap[$g.Name] = $true }

# Final projection with Flag + SuggestedFix
$report = $rows | ForEach-Object {
    $isDuplicate = $false
    if ($dupeMap.ContainsKey($_.SPN)) { $isDuplicate = $true }

    $reasonList = @()
    if ($_.Reasons) { $reasonList += $_.Reasons.Split(';') }
    if ($isDuplicate) { $reasonList += "DUPLICATE_SPN" }

    $suggest = @()
    if ($reasonList -contains 'DNS_NOT_RESOLVING' -or $reasonList -contains 'NO_MATCHING_AD_COMPUTER') {
        $suggest += "Verify host exists & DNS A record. If decommissioned, remove SPN."
    }
    if ($reasonList -contains 'PRINCIPAL_DISABLED' -or $reasonList -contains 'TARGET_COMPUTER_DISABLED') {
        $suggest += "Consider removing SPN from disabled account or re-enable if intended."
    }
    if ($reasonList -contains 'DUPLICATE_SPN') {
        $suggest += "Keep SPN on intended principal only; remove duplicates."
    }
    if ($reasonList -contains 'SPN_MISSING_HOST') {
        $suggest += "Correct malformed SPN or remove."
    }
    if ($suggest.Count -eq 0) { $suggest += "None" }

    [pscustomobject]@{
        SPN                = $_.SPN
        Service            = $_.Service
        Host               = $_.Host
        PrincipalSAM       = $_.PrincipalSAM
        PrincipalClass     = $_.PrincipalClass
        PrincipalDisabled  = $_.PrincipalDisabled
        FQDN               = $_.FQDN
        DNSResolves        = $_.DNSResolves
        ADComputerFound    = [bool]$_.ADComputerDN
        Reasons            = ($reasonList -join ';')
        SuggestedFix       = ($suggest -join ' ')
        PrincipalDN        = $_.PrincipalDN
        ADComputerDN       = $_.ADComputerDN
    }
}

# Sort: flaggiest first
$report = $report | Sort-Object @{Expression='Reasons';Descending=$true}, SPN, PrincipalSAM

# Output
$report | Format-Table -AutoSize SPN,PrincipalSAM,PrincipalClass,Reasons,FQDN,DNSResolves,ADComputerFound

if ($CsvPath) {
    $report | Export-Csv -NoTypeInformation -Path $CsvPath -Encoding UTF8
    Write-Host "Report saved to $CsvPath"
}

# --- Safe remediation helpers (copy/paste as needed) ---
<#
# Remove a single SPN from a specific account:
# Set-ADUser <samAccountName> -ServicePrincipalName @{Remove="HTTP/oldhost.corp.contoso.com"}

# Or using setspn.exe:
# setspn -D HTTP/oldhost.corp.contoso.com <samAccountName>

# Move (transfer) an SPN to a target account:
# Set-ADUser <targetSAM> -ServicePrincipalName @{Add="HTTP/host.corp.contoso.com"}
# Set-ADUser <sourceSAM> -ServicePrincipalName @{Remove="HTTP/host.corp.contoso.com"}

# Verify duplicates before removal:
# setspn -X
# setspn -Q SPN/host.corp.contoso.com
#>