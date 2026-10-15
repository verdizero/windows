# First 5 minutes

	# Change the local built-in Administrator password
	net user Administrator "CoMpPSWD%%$%1223!"


	# Immediately terminate existing unauthorized sessions and restrict new ones.
		# List all active network connections with process IDs
		netstat -ano

		# View active sessions
		query user

		# Terminate an offensive session (replace SessionID)
		logoff <SessionID>

	# Disable WinRM
	Disable-PSRemoting -Force
	Stop-Service WinRM
	Set-Service WinRM -StartupType Disabled

	# Audit local administrators to check who has full control over the box
	
		# View all members of the local Administrators group
		net localgroup Administrators
	
		# Remove a suspicious user from Administrators
		net localgroup Administrators "SuspiciousUser" /delete

# Active Directory && user account hardening

	# Reset all Domain User passwords except your specific admin account (copy paste into pwsh)
	$NewPassword = ConvertTo-SecureString "Lockdown2026!AD#Secure" -AsPlainText -Force
	Get-ADUser -Filter * | Where-Object { $_.SamAccountName -ne "YourTeamAdmin" } | ForEach-Object {
	    Set-ADAccountPassword -Identity $_.SamAccountName -NewPassword $NewPassword -ResetPasswordOnNextLogon $false
	    Enable-ADAccount -Identity $_.SamAccountName
	}

	# Audit domain admins & enterprise admins
	
		# List high-privilege groups
		Get-ADGroupMember -Identity "Domain Admins"
		Get-ADGroupMember -Identity "Enterprise Admins"

		# Remove an unauthorized account from Domain Admins
		Remove-ADGroupMember -Identity "Domain Admins" -Members "SuspiciousUser" -Confirm:$false


	# Disable Guest and Default Accounts
	Disable-ADAccount -Identity "Guest"
	Disable-LocalUser -Name "Guest"

# Firewall & network hardening

	# Enable Windows Defender Firewall
	Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

	# Block all inbound traffic by default unless explicitly allowed by a rule
	Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block

# Persistence & Backdoor Hunting

	# List all active scheduled tasks not created by Microsoft
	Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object TaskName, TaskPath, State


	# Inspect common startup run keys for malicious executables
	Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
	Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce
	Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run

	# List all running services that are not part of standard Windows core
	Get-Service | Where-Object { $_.Status -eq "Running" -and $_.Name -notlike "Win*" } | Select-Object Name, DisplayName
