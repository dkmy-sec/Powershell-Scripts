# Import Active Directory Module
Import-Module ActiveDirectory

# Define privileged groups
$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Schema Admins",
    "Account Operators",
    "Server Operators",
    "Backup Operators"
)

# Get all privileged users
$privilegedUsers = @()
foreach ($group in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.objectClass -eq "user" }
        $privilegedUsers += $members
    } catch {
        Write-Warning "Could not retrieve members of $group"
    }
}

# Get all FGPPs
$fgpps = Get-ADFineGrainedPasswordPolicy -Filter *

# Get default domain policy
$domainPolicy = Get-ADDefaultDomainPasswordPolicy

# Check each privileged user
foreach ($user in $privilegedUsers | Sort-Object SamAccountName -Unique) {
    $policy = $null
    $policyName = "Default Domain Policy"

    # Check if FGPP applies
    foreach ($fgpp in $fgpps) {
        $applies = Get-ADFineGrainedPasswordPolicySubject -Identity $fgpp.Name | Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
        if ($applies) {
            $policy = $fgpp
            $policyName = $fgpp.Name
            break
        }
    }

    if (-not $policy) {
        $policy = $domainPolicy
    }

    # Evaluate policy strength
    $minLength = $policy.MinPasswordLength
    $maxAge = $policy.MaxPasswordAge.Days

    if ($minLength -lt 8 -or $maxAge -gt 1095) {
        Write-Output "⚠️ User: $($user.SamAccountName)"
        Write-Output "   Policy: $policyName"
        Write-Output "   Min Length: $minLength"
        Write-Output "   Max Age (days): $maxAge"
        Write-Output ""
    }
}
