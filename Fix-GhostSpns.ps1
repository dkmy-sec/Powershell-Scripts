<#
.SYNOPSIS
  Find and optionally fix likely "ghost SPNs" in Active Directory.

.DESCRIPTION
  Detection flags SPNs that:
    - Point to hostnames that do not resolve in DNS
    - Point to hosts that do not exist in AD
    - Are attached to disabled principals
    - Are duplicated across multiple principals

  With -Fix (and optional -WhatIf), the script can:
    - Remove SPNs with strong ghost evidence
    - Resolve duplicates per policy

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

.PARAMETER Fix
  Attempt auto-remediation (removing ghost/duplicate SPNs). Honors -WhatIf/-Confirm.

.PARAMETER GhostCriteria
  'Strong' (default) => requires DNS_NOT_RESOLVING AND NO_MATCHING_AD_COMPUTER
  'Any'               => DNS_NOT_RESOLVING OR NO_MATCHING_AD_COMPUTER

.PARAMETER Services
  Limit remediation to specific service prefixes (e.g., 'HTTP','MSSQLSvc'). Detection still scans all.

.PARAMETER SafeList
  Principals (SAM or DN) to exclude from remediation (case-insensitive).

.PARAMETER DuplicatePolicy
  How to auto-resolve duplicates: 'None','KeepEnabled','KeepPreferredClass' (default: KeepEnabled)

.PARAMETER PreferredClass
  Preferred class when DuplicatePolicy='KeepPreferredClass': 'ComputerFirst' (default) or 'UserFirst'.

.EXAMPLE
  # Discover only
  .\Find-GhostSpns.ps1 -CsvPath .\ghost_spns.csv

.EXAMPLE
  # Dry-run remediation with strong-evidence ghosts only
  .\Find-GhostSpns.ps1 -Fix -WhatIf

.EXAMPLE
  # Actually remove ghost SPNs for HTTP & MSSQLSvc, keep duplicates on enabled computers if unique
  .\Find-GhostSpns.ps1 -Fix -Services HTTP,MSSQLSvc -DuplicatePolicy KeepPreferredClass -PreferredClass ComputerFirst

.NOTES
  Author: Atlas for Kyle Lewis
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$Domain,
  [string]$SearchBase,
  [string]$CsvPath,
  [switch]$SkipDns,
  [int]$TimeoutMs = 1500,

  [switch]$Fix,
  [ValidateSet('Strong','Any')]
  [string]$GhostCriteria = 'Strong',
  [string[]]$Services,
  [string[]]$SafeList,

  [ValidateSet('None','KeepEnabled','KeepPreferredClass')]
  [string]$DuplicatePolicy = 'KeepEnabled',
  [ValidateSet('ComputerFirst','UserFirst')]
  [string]$PreferredClass = 'ComputerFirst'
)

# ------------------ Helpers ------------------

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
    param([Parameter(Mandatory)][string]$Spn)
    $service,$rest = $Spn.Split('/',2)
    if (-not $rest) {
        return [pscustomobject]@{ Service=$service; Host=$null; Port=$null; Raw=$Spn }
    }
    $hostPort = $rest.Split('/',2)[0]
    $spnHost = $null; $spnPort = $null
    $tmp = $hostPort.Split(':',2)
    if ($tmp.Count -ge 1) { $spnHost = $tmp[0] }
    if ($tmp.Count -ge 2) { $spnPort = $tmp[1] }
    [pscustomobject]@{ Service=$service; Host=$spnHost; Port=$spnPort; Raw=$Spn }
}

function Get-PrincipalKind {
    param([string]$ObjectClass)
    switch -Regex ($ObjectClass) {
        '^computer$'                       { 'Computer'; break }
        '^user$'                           { 'User'; break }
        'GroupManagedServiceAccount|ManagedServiceAccount' { 'ServiceAccount'; break }
        default                            { 'Other' }
    }
}

function Remove-SpnFromPrincipal {
    param(
        [Parameter(Mandatory)][string]$PrincipalSAM,
        [Parameter(Mandatory)][string]$PrincipalDN,
        [Parameter(Mandatory)][string]$PrincipalClass,
        [Parameter(Mandatory)][string]$SPN
    )
    $kind = Get-PrincipalKind -ObjectClass $PrincipalClass
    $target = if ($PrincipalSAM) { $PrincipalSAM } else { $PrincipalDN }

    $serverParam = @{}
    if ($Domain) { $serverParam['Server'] = $Domain }

    $actionDesc = "Remove SPN '$SPN' from $kind '$target'"

    if (-not $PSCmdlet.ShouldProcess($target, $actionDesc)) { return [pscustomobject]@{Target=$target; SPN=$SPN; Result='Skipped-ShouldProcess'} }

    try {
        switch ($kind) {
            'Computer' {
                Set-ADComputer -Identity $target -ServicePrincipalName @{Remove=$SPN} -Confirm:$false -WhatIf:$WhatIfPreference @serverParam
            }
            'User' {
                Set-ADUser -Identity $target -ServicePrincipalName @{Remove=$SPN} -Confirm:$false -WhatIf:$WhatIfPreference @serverParam
            }
            'ServiceAccount' {
                Set-ADServiceAccount -Identity $target -ServicePrincipalName @{Remove=$SPN} -Confirm:$false -WhatIf:$WhatIfPreference @serverParam
            }
            default {
                # Fallback: generic attempt via Set-ADObject (value remove)
                Set-ADObject -Identity $PrincipalDN -Remove @{servicePrincipalName=$SPN} -Confirm:$false -WhatIf:$WhatIfPreference @serverParam
            }
        }
        [pscustomobject]@{Target=$target; SPN=$SPN; Result='Requested'}
    }
    catch {
        Write-Warning "Failed: $actionDesc | $_"
        [pscustomobject]@{Target=$target; SPN=$SPN; Result='Error'; Error=$_.Exception.Message}
    }
}

function In-SafeList {
    param([string]$SAM,[string]$DN,[string[]]$Safe)
    if (-not $Safe -or $Safe.Count -eq 0) { return $false }
    $safes = $Safe | ForEach-Object { $_.ToLower() }
    if ($SAM -and $safes -contains $SAM.ToLower()) { return $true }
    if ($DN  -and $safes -contains $DN.ToLower())  { return $true }
    return $false
}

# ------------------ Discovery ------------------

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
            if ($parsed.Host -notmatch '\.' -and $Domain) {
                $fqdn = ("{0}.{1}" -f $parsed.Host, $Domain).ToLower()
            } else {
                $fqdn = $parsed.Host.ToLower()
            }

            if (-not $SkipDns -and -not [string]::IsNullOrWhiteSpace($fqdn)) {
                $dns = Resolve-HostSafe -Name $fqdn -TimeoutMs $TimeoutMs
                if (-not $dns.Resolves) { $reasons.Add("DNS_NOT_RESOLVING") | Out-Null }
            }

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

        $isDisabled = $false
        if ($null -ne $p.Enabled) {
            $isDisabled = -not [bool]$p.Enabled
        } elseif ($p.userAccountControl) {
            $isDisabled = ([int]$p.userAccountControl -band 0x2) -ne 0
        }
        if ($isDisabled) { $reasons.Add("PRINCIPAL_DISABLED") | Out-Null }

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

# Sort: flaggiest first for readability
$report = $report | Sort-Object @{Expression='Reasons';Descending=$true}, SPN, PrincipalSAM

# ------------------ Output (always) ------------------
$report | Format-Table -AutoSize SPN,PrincipalSAM,PrincipalClass,Reasons,FQDN,DNSResolves,ADComputerFound

if ($CsvPath) {
    $report | Export-Csv -NoTypeInformation -Path $CsvPath -Encoding UTF8
    Write-Host "Report saved to $CsvPath"
}

# ------------------ Remediation (optional) ------------------
if ($Fix) {
    Write-Host "`n=== Auto-remediation phase (WhatIf=$WhatIfPreference) ==="

    $svcFilter = $null
    if ($Services -and $Services.Count -gt 0) {
        $svcFilter = $Services | ForEach-Object { $_.ToLower() }
    }

    # Helper predicates
    function Is-GhostByCriteria {
        param([string[]]$Reasons,[string]$Criteria)
        $hasDns   = $Reasons -contains 'DNS_NOT_RESOLVING'
        $hasNoAD  = $Reasons -contains 'NO_MATCHING_AD_COMPUTER'
        switch ($Criteria) {
            'Strong' { return ($hasDns -and $hasNoAD) }
            'Any'    { return ($hasDns -or  $hasNoAD) }
            default  { return $false }
        }
    }

    $actions = New-Object System.Collections.Generic.List[object]

    # 1) Remove SPNs meeting "ghost" criteria (non-duplicates)
    $ghostCandidates = $report | Where-Object {
        ($_ -ne $null) -and
        ($_.Reasons -notmatch 'DUPLICATE_SPN') -and
        (Is-GhostByCriteria -Reasons ($_.Reasons -split ';') -Criteria $GhostCriteria) -and
        (-not (In-SafeList -SAM $_.PrincipalSAM -DN $_.PrincipalDN -Safe $SafeList)) -and
        (-not $svcFilter -or $svcFilter -contains $_.Service.ToLower())
    }

    foreach ($item in $ghostCandidates) {
        $res = Remove-SpnFromPrincipal -PrincipalSAM $item.PrincipalSAM -PrincipalDN $item.PrincipalDN -PrincipalClass $item.PrincipalClass -SPN $item.SPN
        $actions.Add([pscustomobject]@{Type='Ghost'; Target=$res.Target; SPN=$res.SPN; Result=$res.Result; Error=$res.Error}) | Out-Null
    }

    # 2) Resolve duplicates per policy
    if ($DuplicatePolicy -ne 'None') {
        $dupGroups = $report | Where-Object { $_.Reasons -match 'DUPLICATE_SPN' } | Group-Object -Property SPN
        foreach ($g in $dupGroups) {
            $members = $g.Group

            # Skip if service filter excludes
            if ($svcFilter -and ($members[0].Service -and ($svcFilter -notcontains $members[0].Service.ToLower()))) { continue }

            # Exclude SafeList upfront
            $membersEff = $members | Where-Object { -not (In-SafeList -SAM $_.PrincipalSAM -DN $_.PrincipalDN -Safe $SafeList) }

            if ($membersEff.Count -le 1) { continue } # nothing to do or only safelisted left

            $enabled = $membersEff | Where-Object { -not $_.PrincipalDisabled }
            $disabled = $membersEff | Where-Object { $_.PrincipalDisabled }

            $keep = $null

            switch ($DuplicatePolicy) {
                'KeepEnabled' {
                    if ($enabled.Count -eq 1) { $keep = $enabled[0] }
                }
                'KeepPreferredClass' {
                    $candidates = if ($enabled.Count -gt 0) { $enabled } else { $membersEff }
                    if ($PreferredClass -eq 'ComputerFirst') {
                        $keep = $candidates | Where-Object { (Get-PrincipalKind -ObjectClass $_.PrincipalClass) -eq 'Computer' } | Select-Object -First 1
                        if (-not $keep) { $keep = $candidates | Where-Object { (Get-PrincipalKind -ObjectClass $_.PrincipalClass) -eq 'User' } | Select-Object -First 1 }
                        if (-not $keep) { $keep = $candidates | Select-Object -First 1 }
                    } else {
                        $keep = $candidates | Where-Object { (Get-PrincipalKind -ObjectClass $_.PrincipalClass) -eq 'User' } | Select-Object -First 1
                        if (-not $keep) { $keep = $candidates | Where-Object { (Get-PrincipalKind -ObjectClass $_.PrincipalClass) -eq 'Computer' } | Select-Object -First 1 }
                        if (-not $keep) { $keep = $candidates | Select-Object -First 1 }
                    }
                }
            }

            if (-not $keep) {
                Write-Host "Duplicate '$($g.Name)': ambiguous or multiple enabled principals — skipped (policy=$DuplicatePolicy)."
                continue
            }

            # Remove from all except the chosen keeper
            foreach ($m in $membersEff) {
                if ($m.PrincipalDN -eq $keep.PrincipalDN) { continue }
                $res2 = Remove-SpnFromPrincipal -PrincipalSAM $m.PrincipalSAM -PrincipalDN $m.PrincipalDN -PrincipalClass $m.PrincipalClass -SPN $g.Name
                $actions.Add([pscustomobject]@{Type='Duplicate'; Target=$res2.Target; SPN=$res2.SPN; Keep=$keep.PrincipalSAM; Result=$res2.Result; Error=$res2.Error}) | Out-Null
            }
        }
    }

    # Summary
    $total = $actions.Count
    $requested = ($actions | Where-Object {$_.Result -eq 'Requested'}).Count
    $skipped   = ($actions | Where-Object {$_.Result -eq 'Skipped-ShouldProcess'}).Count
    $errors    = ($actions | Where-Object {$_.Result -eq 'Error'}).Count
    Write-Host "`n=== Remediation summary ==="
    Write-Host ("Actions considered: {0}, requested: {1}, skipped: {2}, errors: {3}" -f $total,$requested,$skipped,$errors)
    if ($WhatIfPreference) {
        Write-Host "NOTE: -WhatIf was used. No changes were made."
    }
}