# Ensure admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this PowerShell window as Administrator!"
    exit 1
}

$NewLocalPassword = "Local!C0mpetit10n2026"

# Add local usernames that scoring bots use to check service uptime
$ExemptLocalUsers = @("scoring", "white_admin", "administrator") # Remove administrator if you want to change admin pswd

# Stores local admins
$LocalAdmins = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.PrincipalSource -eq "Local" }

foreach ($Admin in $LocalAdmins) {
    $UserName = $Admin.Name.Split('\')[-1]
    
    if ($ExemptLocalUsers -contains $UserName.ToLower()) {
        Write-Host "Skipping local White Team account (please note): $UserName" -ForegroundColor Green
        continue
    }
    
    # Overwrites password without forcing a change prompt using net user
    net user $UserName $NewLocalPassword /expires:never /passwordchg:no > $null
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[SUCCESS] Local password reset completed for: $UserName" -ForegroundColor Cyan
    } else {
        Write-Warning "[ERROR] Failed to reset password for local user: $UserName"
    }
}
