# UB Lockdown: Windows & Active Directory Hardening Cheat Sheet

## 1. The First 5 Minutes (Immediate Defense)
Execute these immediately to stop automated Red Team scripts and secure administrative access.

### Change Local Administrator Password
```powershell
# Change the local built-in Administrator password
net user Administrator "ComplexPass123!"
```

### Stop Unauthorized Remote Access
Immediately terminate existing unauthorized sessions and restrict new ones.
```powershell
# List all active network connections with process IDs
netstat -ano

# View active sessions
query user

# Terminate an offensive session (replace SessionID)
logoff <SessionID>

# Disable WinRM (Often used by Red Team for lateral movement)
Disable-PSRemoting -Force
Stop-Service WinRM
Set-Service WinRM -StartupType Disabled
```

### Audit Local Administrators
Check who has full control over the box and strip unauthorized access.
```powershell
# View all members of the local Administrators group
net localgroup Administrators

# Remove a suspicious user from Administrators
net localgroup Administrators "SuspiciousUser" /delete
```

---

## 2. Active Directory & User Account Hardening
If the system is a Domain Controller, prioritize protecting the NTDS database and highly privileged accounts.

### Mass Reset Domain Passwords (The Loophole Method)
Copy, paste, and run this logic to instantly secure all user accounts. Exclude critical system accounts or your own team to avoid self-lockouts.
```powershell
# Reset all Domain User passwords except your specific admin account
$NewPassword = ConvertTo-SecureString "Lockdown2026!AD#Secure" -AsPlainText -Force
Get-ADUser -Filter * | Where-Object { $_.SamAccountName -ne "YourTeamAdmin" } | ForEach-Object {
    Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $NewPassword -ResetPasswordOnNextLogon $false
    Enable-ADAccount -Identity $_.SamAccountName
}
```

### Audit Domain Admins & Enterprise Admins
```powershell
# List high-privilege groups
Get-ADGroupMember -Identity "Domain Admins"
Get-ADGroupMember -Identity "Enterprise Admins"

# Remove an unauthorized account from Domain Admins
Remove-ADGroupMember -Identity "Domain Admins" -Members "SuspiciousUser" -Confirm:$false
```

### Disable Guest and Default Accounts
```powershell
Disable-ADAccount -Identity "Guest"
Disable-LocalUser -Name "Guest"
```

---

## 3. Firewall & Network Hardening
Ensure the host firewall is active and drop inbound traffic that isn't explicitly required for your services (e.g., DNS, HTTP, SMB).

### Enable Windows Defender Firewall
```powershell
# Enable firewall for all network profiles (Domain, Private, Public)
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# Block all inbound traffic by default unless explicitly allowed by a rule
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
```

---

## 4. Persistence & Backdoor Hunting
Red Team will look to establish long-term access. Audit the most common persistence locations regularly.

### Audit Scheduled Tasks
```powershell
# List all active scheduled tasks not created by Microsoft
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object TaskName, TaskPath, State
```

### Audit Startup Registries
```powershell
# Inspect common startup run keys for malicious executables
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```

### Audit Local Services
```powershell
# List all running services that are not part of standard Windows core
Get-Service | Where-Object { $_.Status -eq "Running" -and $_.Name -notlike "Win*" } | Select-Object Name, DisplayName
```
