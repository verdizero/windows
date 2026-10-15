# UB Lockdown: Windows Incident Response Playbook

## 1. Identification & Triage
Determine what is happening and identify the scope of compromise when a service drops or unauthorized activity is detected.

### Process Identification
```powershell
# List all running processes sorted by high CPU utilization
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Id, ProcessName, CPU

# Find the path of an executable behind a suspicious running process
Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ExecutablePath | Where-Object { $_.Name -eq "suspicious.exe" }
```

### Kill a Malicious Process
```powershell
# Forcefully terminate a malicious process by ID or Name
Stop-Process -Id <PID> -Force
Stop-Process -Name "malicious_process_name" -Force
```

---

## 2. Network Connections & Scoping
Trace where the attack is coming from and what external IPs are connected to your system.

### Map Network Connections to Processes
```powershell
# View all active TCP connections along with the owning Process ID (PID)
Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State
```

---

## 3. Containment & Remediation
Isolate infected systems or block attacking IP addresses instantly without dropping authorized connection strings.

### Block an Attacking IP Address via Firewall
```powershell
# Instantly drop all traffic originating from a rogue Red Team IP
New-NetFirewallRule -DisplayName "Block Attacking Red Team IP" -Direction Inbound -RemoteAddress "192.168.X.X" -Action Block
```

### Isolate Host Netsh Emergency Command
If a host is heavily compromised, isolate it entirely while keeping your management console open if possible.
```powershell
# Block all inbound/outbound network traffic to contain threat (Emergency Only)
New-NetFirewallRule -DisplayName "Emergency Containment" -Direction Inbound -Action Block
New-NetFirewallRule -DisplayName "Emergency Containment Outbound" -Direction Outbound -Action Block
```

---

## 4. Log Analysis & Forensic Artifacts
Look through Windows Event Logs to find out exactly how access was gained.

### Monitor Failed Logins (Event ID 4625)
```powershell
# Query Security log for the 10 most recent failed authentication attempts
Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 | Select-Object TimeGenerated, Message
```

### Monitor Successful Logins (Event ID 4624)
```powershell
# Query Security log for successful logins to trace Red Team's active accounts
Get-EventLog -LogName Security -InstanceId 4624 -Newest 10 | Select-Object TimeGenerated, Message
```
