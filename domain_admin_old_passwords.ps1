# Import the Active Directory module
Import-Module ActiveDirectory

# Set the threshold in days
$daysThreshold = 180
$cutoffDate = (Get-Date).AddDays(-$daysThreshold)

# Get members of the Domain Admins group
$adminGroup = Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Filter and check password age
foreach ($admin in $adminGroup) {
    if ($admin.objectClass -eq "user") {
        $user = Get-ADUser -Identity $admin.SamAccountName -Properties PasswordLastSet, Enabled
        if ($user.Enabled -and $user.PasswordLastSet -lt $cutoffDate) {
            Write-Output "Domain Admin '$($user.SamAccountName)' has not changed password since $($user.PasswordLastSet)"
        }
    }
}
