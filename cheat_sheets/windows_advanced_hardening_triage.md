# Advanced Windows Hardening & Triage Cheat Sheet
## 1. Advanced Network Triage & Severance
### The Active Kill-Switch
If you know the Red Team's C2 infrastructure IP, run this loop to find any process communicating with it and immediately kill it:
```powershell
$AttackerIP = "10.x.x.x" # Replace with Red Team IP
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq $AttackerIP } | ForEach-Object {
    Write-Host "Killing Process ID: $($_.OwningProcess) communicating with Attacker" -ForegroundColor Red
    Stop-Process -Id $_.OwningProcess -Force
}
```

### DNS Sinkholing (Local Hosts File)
Block common C2 domains or redirect malicious traffic back to localhost:
```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`n127.0.0.1 maliciousdomain.local"
```

---

## 2. Active Directory & Kerberos Defense
### Mitigating Golden Tickets (KRBTGT Password Reset)
If your domain controller is compromised, the Red Team can forge tickets forever until you reset the KRBTGT password **TWICE** (with a pause for replication).
```powershell
# Reset 1st time
Set-ADUser -Identity krbtgt -PasswordNeverExpires $false -Enabled $true
# Use standard AD administrative center or Reset-ADUserPassword if tool modules are installed
```

### Lock Down Privileged Groups
Quickly list members of highly sensitive groups to find backdoors:
```powershell
$Groups = @("Schema Admins", "Enterprise Admins", "Backup Operators", "Account Operators")
foreach ($Group in $Groups) {
    Get-ADGroupMember -Identity $Group | Select-Object Name, SamAccountName, DistinguishedName
}
```

---

## 3. Advanced Persistence Triage
### WMI Event Consumer Hunting
Red Teams love WMI for fileless, stealthy persistence that triggers on a timer. Find them here:
```powershell
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
```
*If you see anything suspicious, delete the binding immediately using `Remove-CimInstance`.*

### AppCert / AppInit DLL Injection Audit
Check registry paths where malicious DLLs can be injected into every launching process:
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs", "LoadAppInit_DLLs"
Get-ChildItem -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDLLs" -ErrorAction SilentlyContinue
```

---

## 4. Defensive Registry Lockdowns
### Protect LSASS Memory (Anti-Mimikatz)
Prevent tools from dumping plaintext credentials out of memory by enforcing RunAsPPL:
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -PropertyType DWORD -Force
```

### Disable NTLM (Kill Pass-the-Hash)
Force the environment to use Kerberos and deny legacy, easily crackable NTLM hashes:
```powershell
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NtlmMinServerSec" -Value 536870912 -PropertyType DWORD -Force
```
