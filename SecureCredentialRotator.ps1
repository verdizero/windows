#requires -Modules ActiveDirectory

#   -Mode Inventory = only gathers information, no changes
#   -Mode Enroll = enrolls accounts for rotation, no changes
#   -Mode Review = shows the registry of enrolled accounts, no changes
#   -Mode Policy -Account (someone) = shows the effective password policy for that account, no changes
#   -Mode Rotate -Apply = rotates the enrolled accounts, requires per-account confirmation, 
#        and requires -Apply to actually perform the resets
#
# - Only explicitly enrolled accounts can be rotated!!!
# - The registry contains identifiers, not passwords and each acc gets a unique password
# - Requires per-account confirmation
# - Passwords aren't written to logs to stop red team from potentially seeing them
# - Test in a disposable lab

[CmdletBinding()]
param(
    [ValidateSet("Inventory", "Enroll", "Review", "Policy", "Rotate")]
    [string]$Mode = "Review",

    [string]$Account,

    [string]$Server,

    [switch]$Apply
)

$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory -ErrorAction Stop

$RegistryPath = Join-Path $PSScriptRoot "rotation-registry.csv"
$LogPath = Join-Path $PSScriptRoot "rotation-results.csv"

# Registry

function Get-Registry {
    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        return @()
    }

    $rows = @(Import-Csv -LiteralPath $RegistryPath)

    foreach ($row in $rows) {
        if (-not $row.ObjectGuid -or
            -not $row.SamAccountName -or
            -not $row.Category) {
            throw "Invalid registry entry. No rotation performed"
        }
    }

    return $rows
}

function Save-Registry {
    param([object[]]$Entries)

    $Entries |
        Export-Csv -LiteralPath $RegistryPath `
            -NoTypeInformation -Encoding UTF8
}

function Write-Result {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail
    )

    # Never include passwords or password material here
    $entry = [pscustomobject]@{
        TimeUtc = [DateTime]::UtcNow.ToString("o")
        Account = $Name
        Status  = $Status
        Detail  = $Detail
    }

    if (Test-Path -LiteralPath $LogPath) {
        $entry | Export-Csv -LiteralPath $LogPath `
            -Append -NoTypeInformation -Encoding UTF8
    }
    else {
        $entry | Export-Csv -LiteralPath $LogPath `
            -NoTypeInformation -Encoding UTF8
    }
}

function Get-DirectoryUser {
    param([string]$Identity)

    if ($Server) {
        return Get-ADUser -Identity $Identity `
            -Server $Server -Properties Enabled, ObjectGuid, SID, `
                ServicePrincipalName, PasswordLastSet
    }

    return Get-ADUser -Identity $Identity `
        -Properties Enabled, ObjectGuid, SID, `
            ServicePrincipalName, PasswordLastSet
}

# Inventory

function Show-Inventory {
    Write-Host "`nEnabled AD users (inventory only):`n"

    $users = Get-ADUser -Filter 'Enabled -eq $true' `
        -Properties DisplayName, PasswordLastSet, ServicePrincipalName

    $users |
        Sort-Object SamAccountName |
        Select-Object SamAccountName, DisplayName, PasswordLastSet,
            @{N="HasSPN";E={ @($_.ServicePrincipalName).Count -gt 0 }} |
        Format-Table -AutoSize

    Write-Host "`nInventory only mode, nothing was changed"
}

# Enrollment

function Enroll-Users {
    $registry = @(Get-Registry)

    $users = Get-ADUser -Filter 'Enabled -eq $true' `
        -Properties DisplayName, ObjectGuid, SID, ServicePrincipalName |
        Sort-Object SamAccountName

    foreach ($user in $users) {
        $guid = $user.ObjectGuid.Guid

        if (@($registry | Where-Object {
            $_.ObjectGuid -eq $guid
        }).Count -gt 0) {
            continue
        }

        # Never automatically enroll the built-in Administrator.
        if ($user.SID.Value -match '-500$') {
            continue
        }

        Write-Host "`nAccount: $($user.SamAccountName)"
        Write-Host "Display name: $($user.DisplayName)"
        Write-Host "Has SPN: $(@($user.ServicePrincipalName).Count -gt 0)"

        if (@($user.ServicePrincipalName).Count -gt 0) {
            Write-Warning "SPN detected! Review as a possible service account!"
            Write-Host "This account will not be enrolled by this workflow."
            continue
        }

        $answer = Read-Host "Enroll as PrivilegedHuman? Type ENROLL"

        if ($answer -cne "ENROLL") {
            continue
        }

        $registry += [pscustomobject]@{
            ObjectGuid     = $guid
            SamAccountName = $user.SamAccountName
            Category       = "PrivilegedHuman"
            EnrolledUtc    = [DateTime]::UtcNow.ToString("o")
        }

        Save-Registry $registry
        Write-Host "Enrolled: $($user.SamAccountName)"
    }

    Write-Host "`nEnrollment finished - double check the registry before rotation"
}

# Registry review

function Show-Registry {
    $registry = @(Get-Registry)

    if ($registry.Count -eq 0) {
        Write-Host "Nobody enrolled!"
        return
    }

    $results = foreach ($entry in $registry) {
        try {
            $user = Get-DirectoryUser -Identity $entry.ObjectGuid

            [pscustomobject]@{
                RegisteredName = $entry.SamAccountName
                CurrentName    = $user.SamAccountName
                Enabled        = $user.Enabled
                Category       = $entry.Category
                ObjectGuid     = $entry.ObjectGuid
                Status         = "Resolved"
            }
        }
        catch {
            [pscustomobject]@{
                RegisteredName = $entry.SamAccountName
                CurrentName    = ""
                Enabled        = $false
                Category       = $entry.Category
                ObjectGuid     = $entry.ObjectGuid
                Status         = "MissingOrUnresolvable"
            }
        }
    }

    if ($null -ne $results -and $results.Count -gt 0) {
        $results | Format-Table -AutoSize
    }
    else {
        Write-Host "No valid registry entries found!"
    }
}

# Effective password policy

function Get-AccountPolicy {
    param([string]$Identity)

    $user = Get-DirectoryUser -Identity $Identity

    if ($Server) {
        $policy = Get-ADUserResultantPasswordPolicy `
            -Identity $user -Server $Server -ErrorAction Stop
    }
    else {
        $policy = Get-ADUserResultantPasswordPolicy `
            -Identity $user -ErrorAction Stop
    }

    if ($null -eq $policy) {
        if ($Server) {
            $policy = Get-ADDefaultDomainPasswordPolicy `
                -Server $Server -ErrorAction Stop
        }
        else {
            $policy = Get-ADDefaultDomainPasswordPolicy `
                -ErrorAction Stop
        }
    }

    return $policy
}

function Show-Policy {
    if (-not $Account) {
        throw "Supply -Account with -Mode Policy"
    }

    $user = Get-DirectoryUser -Identity $Account
    $policy = Get-AccountPolicy -Identity $user.ObjectGuid.Guid

    [pscustomobject]@{
        Account             = $user.SamAccountName
        Enabled             = $user.Enabled
        PolicyName          = $policy.Name
        MinimumLength       = $policy.MinPasswordLength
        ComplexityEnabled   = $policy.ComplexityEnabled
        HistoryCount        = $policy.PasswordHistoryCount
        MinimumPasswordAge  = $policy.MinPasswordAge
        MaximumPasswordAge  = $policy.MaxPasswordAge
    } | Format-List
}

# Cryptographically secure password generation
# Requires pwsh 7.2

function New-SecurePassword {
    param(
        [int]$MinimumLength = 20
    )

    if (-not [System.Security.Cryptography.RandomNumberGenerator].GetMethods() |
        Where-Object {
            $_.Name -eq 'GetInt32' -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType -eq [int]
        }) {
        throw "Use PowerShell 7.2+ for password generation"
    }

    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ".ToCharArray()
    $lower   = "abcdefghijkmnopqrstuvwxyz".ToCharArray()
    $digits  = "23456789".ToCharArray()
    $special = "!#$%&()*+,-./:;<=>?@[]^_{|}~".ToCharArray()

    $all = @($upper) + @($lower) + @($digits) + @($special)

    $length = [Math]::Max(20, $MinimumLength)
    $chars = [System.Collections.Generic.List[char]]::new()

    # Guarantee at least one character from each class of ASCII
    foreach ($set in @($upper, $lower, $digits, $special)) {
        $chars.Add($set[
            [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(
                $set.Length
            )
        ])
    }

    while ($chars.Count -lt $length) {
        $chars.Add($all[
            [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(
                $all.Count
            )
        ])
    }

    # Fisher-Yates shuffle
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(
            $i + 1
        )
        $tmp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $tmp
    }

    return -join $chars
}

function Invoke-Rotation {
    if (-not $Apply) {
        Write-Host "PREVIEW ONLY! No password changes will be made!"
        Write-Host "Run with -Mode Rotate -Apply to enable per-account resets"
    }

    $registry = @(Get-Registry)

    if ($registry.Count -eq 0) {
        throw "Registry is empty, enroll and review accounts first."
    }

    $targets = @($registry | Where-Object {
        $_.Category -eq "PrivilegedHuman"
    })

    if ($targets.Count -eq 0) {
        throw "No PrivilegedHuman accounts found in registry"
    }

    Write-Host "`nTargets: $($targets.Count)"
    Write-Host "DC: $(if ($Server) { $Server } else { 'Default DC selection' })"
    Write-Host "Unique passwords will be generated for each account :)"

    foreach ($entry in $targets) {
        $password = $null
        $securePassword = $null

        try {
            $user = Get-DirectoryUser -Identity $entry.ObjectGuid

            if (-not $user.Enabled) {
                Write-Warning "$($entry.SamAccountName): disabled; skipped."
                Write-Result $entry.SamAccountName "Skipped" "Disabled account"
                continue
            }

            if ($user.SID.Value -match '-500$') {
                Write-Warning "Built-in Administrator; skipped."
                Write-Result $entry.SamAccountName "Skipped" "RID 500"
                continue
            }

            if (@($user.ServicePrincipalName).Count -gt 0) {
                Write-Warning "SPN detected; service-account review required."
                Write-Result $entry.SamAccountName "Skipped" "SPN detected"
                continue
            }

            $policy = Get-AccountPolicy -Identity $user.ObjectGuid.Guid
            $minimumLength = [Math]::Max(
                20, [int]$policy.MinPasswordLength
            )

            Write-Host "`nAccount: $($user.SamAccountName)"
            Write-Host "Policy: $($policy.Name)"
            Write-Host "Minimum length: $($policy.MinPasswordLength)"
            Write-Host "Generated length: $minimumLength"

            if (-not $Apply) {
                Write-Host "DRY RUN: no password generated or changed."
                Write-Result $user.SamAccountName "DryRun" "No changes"
                continue
            }

            $confirm = Read-Host "Type ROTATE to proceed with this account"
            if ($confirm -cne "ROTATE") {
                Write-Result $user.SamAccountName "Skipped" "Operator declined"
                continue
            }

            $password = New-SecurePassword -MinimumLength $minimumLength
            $securePassword = ConvertTo-SecureString $password `
                -AsPlainText -Force

            Write-Host "`nGenerated password for $($user.SamAccountName):"
            Write-Host $password -ForegroundColor Yellow
            Write-Warning "This password is visible in the terminal. Do not capture or share this screen."

            $saved = Read-Host "Save this password to your approved vault, then type SAVED"
            if ($saved -cne "SAVED") {
                Write-Result $user.SamAccountName "NotChanged" "Vault confirmation missing"
                continue
            }

            $lastConfirm = Read-Host "Type RESET to submit the password reset"
            if ($lastConfirm -cne "RESET") {
                Write-Result $user.SamAccountName "NotChanged" "Final confirmation missing"
                continue
            }

            if ($Server) {
                Set-ADAccountPassword -Identity $user.ObjectGuid `
                    -Server $Server -Reset `
                    -NewPassword $securePassword -ErrorAction Stop
            }
            else {
                Set-ADAccountPassword -Identity $user.ObjectGuid `
                    -Reset -NewPassword $securePassword `
                    -ErrorAction Stop
            }

            Write-Host "Reset accepted by AD. Verify sign-in separately."
            Write-Result $user.SamAccountName "ResetAcceptedByAD" `
                "Authentication not yet verified"
        }
        catch {
            Write-Warning "$($entry.SamAccountName): $($_.Exception.Message)"
            Write-Result $entry.SamAccountName "Failed" `
                "Review error in console; no password logged"
        }
        finally {
            $password = $null
            if ($null -ne $securePassword) {
                $securePassword.Dispose()
                $securePassword = $null
            }
        }
    }

    Write-Host "`nRotation pass complete."
    Write-Host "Review the results log and verify every intended account."
}


switch ($Mode) {
    "Inventory" {
        Show-Inventory
    }

    "Enroll" {
        Enroll-Users
    }

    "Review" {
        Show-Registry
    }

    "Policy" {
        Show-Policy
    }

    "Rotate" {
        Invoke-Rotation
    }
}
