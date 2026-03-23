# Get all enabled user accounts with relevant properties
$users = Get-ADUser -Filter {Enabled -eq $true} -Properties Name, PasswordNeverExpires, Description, whenCreated, LastLogonDate

# Define keywords that might indicate a shared account
$sharedKeywords = @("shared", "svc", "admin", "generic", "service", "team")

# Collect results
$results = @()

foreach ($user in $users) {
    $isPasswordNeverExpires = $user.PasswordNeverExpires
    $isSharedAccount = $false

    foreach ($keyword in $sharedKeywords) {
        if ($user.Name -match $keyword -or $user.Description -match $keyword) {
            $isSharedAccount = $true
            break
        }
    }

    if ($isPasswordNeverExpires -or $isSharedAccount) {
        $results += [PSCustomObject]@{
            Name                  = $user.Name
            PasswordNeverExpires = $isPasswordNeverExpires
            SharedAccount        = $isSharedAccount
            CreatedDate          = $user.whenCreated
            LastLogonDate        = $user.LastLogonDate
        }
    }
}

# Output to console
$results | Format-Table -AutoSize

# Optional: Export to CSV
$results | Export-Csv -Path "SharedAccountsReport.csv" -NoTypeInformation
