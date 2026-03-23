
# Import the Active Directory module
Import-Module ActiveDirectory

# Define privileged groups to check
$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Administrators",
    "Schema Admins",
    "Account Operators",
    "Server Operators",
    "Backup Operators"
)

# Loop through each group and check for computer accounts
foreach ($group in $privilegedGroups) {
    Write-Output "`nChecking group: $group"
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive
        foreach ($member in $members) {
            if ($member.objectClass -eq "computer") {
                Write-Output "Computer account '$($member.Name)' is a member of '$group'"
            }
        }
    } catch {
        Write-Warning "Failed to query group: $group. Error: $_"
    }
}
