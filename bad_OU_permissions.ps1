
# Import the Active Directory module
Import-Module ActiveDirectory

# Define dangerous permissions
$dangerousRights = @("CreateChild", "GenericAll", "WriteDACL", "WriteOwner")

# Get all OUs in the domain
$OUs = Get-ADOrganizationalUnit -Filter *

foreach ($OU in $OUs) {
    $acl = Get-Acl -Path ("AD:\" + $OU.DistinguishedName)
    foreach ($ace in $acl.Access) {
        if ($dangerousRights -contains $ace.ActiveDirectoryRights.ToString()) {
            # Filter out built-in privileged accounts
            if ($ace.IdentityReference -notmatch "^(NT AUTHORITY|BUILTIN|Domain Admins|Enterprise Admins|SYSTEM)") {
                Write-Output "⚠️ OU: $($OU.DistinguishedName)"
                Write-Output "   Identity: $($ace.IdentityReference)"
                Write-Output "   Rights: $($ace.ActiveDirectoryRights)"
                Write-Output "   Type: $($ace.AccessControlType)"
                Write-Output ""
            }
        }
    }
}

# Check the domain root (NC head)
$domainDN = (Get-ADDomain).DistinguishedName
$domainACL = Get-Acl -Path ("AD:\" + $domainDN)

foreach ($ace in $domainACL.Access) {
    if ($dangerousRights -contains $ace.ActiveDirectoryRights.ToString()) {
        if ($ace.IdentityReference -notmatch "^(NT AUTHORITY|BUILTIN|Domain Admins|Enterprise Admins|SYSTEM)") {
            Write-Output "⚠️ NC Head: $domainDN"
            Write-Output "   Identity: $($ace.IdentityReference)"
            Write-Output "   Rights: $($ace.ActiveDirectoryRights)"
            Write-Output "   Type: $($ace.AccessControlType)"
            Write-Output ""
        }
    }
}

