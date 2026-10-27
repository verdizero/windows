Import-Module ActiveDirectory

function New-Password {
    $password = Read-Host -Prompt "Enter a new password" -AsSecureString -AsPlainText
    Write-Host "New password: $password -- PLEASE MAKE NOTE"
}
$NewSecurePassword = New-Password -Force
$AdminGroup = "Domain Admins"

# MUSTN'T CHANGE THE WHITE TEAM PEOPLE'S ACCOUNTS
$ExemptUsers = @("scoring", "scorekeeper", "whiteteam", "svc_scoring")

# Fetches and filters users
$AdminMembers = Get-ADGroupMember -Identity $AdminGroup | Where-Object { $_.objectClass -eq "user" }

foreach ($Member in $AdminMembers) {
    $SamAccount = $Member.SamAccountName
    
    # Check if this user is on the White Team safety list
    if ($ExemptUsers -contains $SamAccount.ToLower()) {
        Write-Host "Skipping likely White Team account (please note): $SamAccount" -ForegroundColor Green
        continue
    }
    
    try {
        # Clear flags that red team might use to maintain persistence
        Set-ADUser -Identity $SamAccount -PasswordNeverExpires $false -ChangePasswordAtLogon $false
        
        # Explicitly set the new known password right now
        Set-ADAccountPassword -Identity $SamAccount -NewPassword $NewSecurePassword -Reset
        
        # Force a kick on any active red team sessions using old credentials
        Set-ADUser -Identity $SamAccount -Clear "userCertificate" # Clears potential golden ticket vectors
        
        Write-Host "[SUCCESS] Reset password for admin: $SamAccount" -ForegroundColor Cyan
    } 
    catch {
        Write-Warning "[ERROR] Failed to modify user $SamAccount : $_"
    }
}
