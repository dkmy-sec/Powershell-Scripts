# Powershell-Scripts
 A collection of various powershell scripts I have created.  Mostly to aid in my day-to-day sys admin tasks.

- ## Find-GhostSpns.ps1 & Fix-GhostSpns.ps1
-  ### These scripts go through active directory and find likely Ghost SPNs.
-   Flags SPNs that:
    - Point to hostnames that do not resolve in DNS
    - Point to hosts that do not exist in AD
    - Are attached to disabled principals
    - Are duplicated across multiple principal
Find-GhostSpns.ps1 is tested and just finds likey Ghotst SPNs.  Fix-GhostSpns.ps1 will just find if you use -WhatIf it will also try to automaticially fix them.

EXAMPLE
  ### Discover only
  ```powershell
.\Find-GhostSpns.ps1 -CsvPath .\ghost_spns.csv
```

EXAMPLE
  ### Dry-run remediation with strong-evidence ghosts only
  ```powershell
  .\Find-GhostSpns.ps1 -Fix -WhatIf
  ```

EXAMPLE
  ### Actually remove ghost SPNs for HTTP & MSSQLSvc, keep duplicates on enabled computers if unique
  ```powershell
   .\Find-GhostSpns.ps1 -Fix -Services HTTP,MSSQLSvc -DuplicatePolicy KeepPreferredClass -PreferredClass ComputerFirst
  ```

- ## bad_OU_permissions.ps1
- ### Checks OU's for bad permissions

EXAMPLE
  ```powershell
  .\bad_OU_permissions.ps1
  ```

- ## computers_privileged_groups.ps1
- ### Checks groups like Domain Admin, Enterprise Admin, Adminsitators, Schema Admins, etc... for computers/machine accounts.
EXAMPLE
  ```powershell
  .\computers_privileged_groups.ps1
  ```

- ## domain_admin_old_passwords.ps1
- ### Checks domain admin accounts to see if they haven't changed there password in x amount of days (default=180 days from current day)
EXAMPLE
  ```powershell
  .\domain_admin_old_passwords.ps1
  ```

- ## password_never_expires_and_possibly_shared_account.ps1
- ### Checks to see what accounts have password never expires checked.  Also checles to see account is possibly a shared account.
EXAMPLE
  ```powershell
  .\password_never_expires_and_possibly_shared_account.ps1
  ```

- ## privileged_user_weak_password_policy.ps1
- ### Checks to see what password policy privileged accounts have.
  ```powershell
  .\privileged_user_weak_password_policy.ps1
  ```
