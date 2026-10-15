# Windows Incident Response Playbook

# Identification & Triage

  # List all running processes sorted by high CPU utilization
  Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Id, ProcessName, CPU

  # Find the path of an executable behind a suspicious running process
  Get-WmiObject Win32_Process | Select-Object ProcessId, Name, ExecutablePath | Where-Object { $_.Name -eq "suspicious.exe" }

  # Kill a malicious process
  Stop-Process -Id <PID> -Force
  Stop-Process -Name "malicious_process_name" -Force

# Network Connections & Scoping

  # View all active TCP connections along with the owning PID
  Get-NetTCPConnection | Where-Object { $_.State -eq "Established" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State

# Containment

  # Block an Attacking IP Address via Firewall, instantly drops traffic originating from rogue IP (REPLACE WITH BAD IP)
  New-NetFirewallRule -DisplayName "Block Attacking Red Team IP" -Direction Inbound -RemoteAddress "192.168.X.X" -Action Block

  # Isolate host Netsh emergency command (if a host is heavily compromised, isolate it entirely while keeping your management console open if possible)
  New-NetFirewallRule -DisplayName "Emergency Containment" -Direction Inbound -Action Block
  New-NetFirewallRule -DisplayName "Emergency Containment Outbound" -Direction Outbound -Action Block

# Log Analysis & Forensic Artifacts

  # Monitor Failed Logins (Event ID 4625) && query security log for 10 most recent failed authentication attempts
  Get-EventLog -LogName Security -InstanceId 4625 -Newest 10 | Select-Object TimeGenerated, Message

  # Monitor Successful Logins (Event ID 4624)
  Get-EventLog -LogName Security -InstanceId 4624 -Newest 10 | Select-Object TimeGenerated, Message
