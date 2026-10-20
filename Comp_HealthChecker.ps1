[CmdletBinding()]
param(
    [string]$OutputRoot = ".\Competition-Health",
    [string[]]$DomainControllers = @(),
    [int]$EventLookbackHours = 24,
    [switch]$IncludeDism
)

$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutputRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$results = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param($Name, $Status, $Details, $Recommendation = "")
    $results.Add([pscustomobject]@{
        Time = Get-Date
        Check = $Name
        Status = $Status
        Details = [string]$Details
        Recommendation = [string]$Recommendation
    })
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host "Competition health check" -ForegroundColor Cyan

# Identify domain and domain controllers
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    Add-Check "AD module/domain discovery" "PASS" $domain.DNSRoot

    if ($DomainControllers.Count -eq 0) {
        $DomainControllers = @(
            Get-ADDomainController -Filter * |
                Select-Object -ExpandProperty HostName
        )
    }
} catch {
    Add-Check "AD module/domain discovery" "FAIL" $_.Exception.Message `
        "Install RSAT AD tools and verify domain connectivity."
    $DomainControllers = @()
}

# Pending Reboot Detection
$rebootPending = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $rebootPending = $true }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $rebootPending = $true }

if ($rebootPending) {
    Add-Check "Pending System Reboot" "WARN" "Host has a pending system reboot." "Schedule host reboot during maintainance window."
} else {
    Add-Check "Pending System Reboot" "PASS" "No pending reboot flags detected."
}

# DNS resolver configuration
try {
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        Select-Object InterfaceAlias, ServerAddresses

    $dns | Export-Csv (Join-Path $outDir "dns-client.csv") `
        -NoTypeInformation

    Add-Check "DNS client configuration" "INFO" `
        (($dns | ForEach-Object {
            "$($_.InterfaceAlias): $($_.ServerAddresses -join ',')"
        }) -join "; ") `
        "Confirm domain members use appropriate internal DNS resolvers."
} catch {
    Add-Check "DNS client configuration" "WARN" $_.Exception.Message
}

# Time synchronization
try {
    $timeOutput = & w32tm.exe /query /status 2>&1
    $timeExit = $LASTEXITCODE
    $timeOutput | Set-Content (Join-Path $outDir "time-status.txt")

    if ($timeExit -eq 0) {
        Add-Check "Time synchronization" "INFO" ($timeOutput -join " ") `
            "Verify time source and skew if Kerberos authentication fails."
    } else {
        Add-Check "Time synchronization" "WARN" ($timeOutput -join " ") `
            "Investigate Windows Time configuration."
    }
} catch {
    Add-Check "Time synchronization" "WARN" $_.Exception.Message
}

# Local and remote service checks using WinRM / CIM fallback
foreach ($dc in $DomainControllers) {
    try {
        # Fast CIM query over WinRM (WS-Man)
        $cimSessionOptions = New-CimSessionOption -Protocol Wsman -ConnectTimeoutMs 2000
        $session = New-CimSession -ComputerName $dc -SessionOption $cimSessionOptions -ErrorAction Stop
        
        $adServices = Get-CimInstance -CimSession $session -ClassName Win32_Service -Filter "Name='NTDS' OR Name='DNS' OR Name='KDC' OR Name='Netlogon' OR Name='W32Time' OR Name='DFSR' OR Name='Dnscache' OR Name='ADWS'" -ErrorAction Stop
        
        foreach ($svc in $adServices) {
            $svcStatus = if ($svc.State -eq 'Running') { "PASS" } else { "WARN" }
            Add-Check "DC Service ($dc): $($svc.Name)" $svcStatus "State=$($svc.State)"
        }
        Remove-CimSession $session -ErrorAction SilentlyContinue
    } catch {
        # Invoke-Command over PowerShell Remoting
        try {
            $adServices = Invoke-Command -ComputerName $dc -ScriptBlock {
                Get-Service -Name "NTDS", "DNS", "KDC", "Netlogon", "W32Time", "DFSR", "Dnscache", "ADWS" -ErrorAction SilentlyContinue
            } -ConnectionUri "http://$dc`:5985/WSMAN" -ErrorAction Stop

            foreach ($svc in $adServices) {
                $svcStatus = if ($svc.Status -eq 'Running') { "PASS" } else { "WARN" }
                Add-Check "DC Service ($dc): $($svc.Name)" $svcStatus "Status=$($svc.Status)"
            }
        } catch {
            Add-Check "DC Service Check ($dc)" "WARN" "Failed to query services via WinRM/CIM: $($_.Exception.Message)" "Verify WinRM (TCP 5985) or RPC permissions on $dc."
        }
    }
}

# SYSVOL and NETLOGON access
if ($domain) {
    foreach ($share in @("SYSVOL", "NETLOGON")) {
        $path = "\\$($domain.PDCEmulator)\$share"
        if (Test-Path $path) {
            Add-Check "$share share" "PASS" "$path is accessible."
        } else {
            Add-Check "$share share" "WARN" "$path is inaccessible." `
                "Check DNS, permissions, SMB connectivity, and DC health."
        }
    }
}

# OS servicing store health (DISM) 
if ($IncludeDism) {
    try {
        $dismResult = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1
        if ($LASTEXITCODE -eq 0 -and ($dismResult -match "No component store corruption detected")) {
            Add-Check "OS Servicing Store (DISM)" "PASS" "Component store healthy."
        } else {
            Add-Check "OS Servicing Store (DISM)" "WARN" "Component store corruption detected or DISM error." "Run Dism /Online /Cleanup-Image /RestoreHealth."
        }
    } catch {
        Add-Check "OS Servicing Store (DISM)" "WARN" $_.Exception.Message
    }
} else {
    Add-Check "OS Servicing Store (DISM)" "SKIP" "DISM check skipped for performance. Run with -IncludeDism to enable."
}

# Domain controller reachability
foreach ($dc in $DomainControllers) {
    if (Test-Connection -ComputerName $dc -Count 1 -Quiet) {
        Add-Check "DC reachability: $dc" "PASS" "ICMP response received."
    } else {
        Add-Check "DC reachability: $dc" "WARN" `
            "No ICMP response; ICMP may be blocked." `
            "Validate with DNS, LDAP, RPC, and event-log checks too."
    }
}

# FSMO role owner reachability
if ($domain) {
    try {
        $forest = Get-ADForest -ErrorAction Stop
        $fsmoRoles = @{
            "PDCEmulator"         = $domain.PDCEmulator
            "RIDMaster"           = $domain.RIDMaster
            "InfrastructureMaster"= $domain.InfrastructureMaster
            "SchemaMaster"        = $forest.SchemaMaster
            "DomainNamingMaster"  = $forest.DomainNamingMaster
        }

        foreach ($role in $fsmoRoles.Keys) {
            $holder = $fsmoRoles[$role]
            if (Test-Connection -ComputerName $holder -Count 1 -Quiet) {
                Add-Check "FSMO Role: $role" "PASS" "Owner ($holder) is online."
            } else {
                Add-Check "FSMO Role: $role" "WARN" "Owner ($holder) is unreachable via ICMP." "Verify owner host state."
            }
        }
    } catch {
        Add-Check "FSMO Role Check" "WARN" $_.Exception.Message
    }
}

# AD replication health
if (Test-CommandAvailable "repadmin.exe") {
    $repOutput = & repadmin.exe /replsummary 2>&1
    $repExit = $LASTEXITCODE
    $repOutput | Set-Content (Join-Path $outDir "replication-summary.txt")

    if ($repExit -eq 0) {
        Add-Check "AD replication summary" "INFO" ($repOutput -join " ") `
            "Review failure counts and largest replication delta."
    } else {
        Add-Check "AD replication summary" "WARN" ($repOutput -join " ") `
            "Investigate failed replication partners."
    }
} else {
    Add-Check "AD replication summary" "SKIP" `
        "repadmin.exe not found." "Run on a machine with AD DS tools installed."
}

# ADWS and LDAP port checks
$requiredPorts = @(53, 88, 389, 636, 3268, 9389)

foreach ($dc in $DomainControllers) {
    foreach ($port in $requiredPorts) {
        $tcp = Test-NetConnection -ComputerName $dc -Port $port -WarningAction SilentlyContinue
        if ($tcp.TcpTestSucceeded) {
            Add-Check "Port Check (${dc}:${port})" "PASS" "TCP Port $port open."
        } else {
            Add-Check "Port Check (${dc}:${port})" "WARN" "TCP Port $port filtered or closed." "Check host firewalls and service states."
        }
    }
}

# DCDIAG
if (Test-CommandAvailable "dcdiag.exe") {
    foreach ($dc in $DomainControllers) {
        $safeName = $dc -replace '[^a-zA-Z0-9_.-]', '_'
        $log = Join-Path $outDir "dcdiag-$safeName.txt"
        $output = & dcdiag.exe "/s:$dc" /test:Advertising /test:Services `
            /test:SysVolCheck /test:NetLogons 2>&1
        $exit = $LASTEXITCODE
        $output | Set-Content $log

        $status = if ($exit -eq 0) { "INFO" } else { "WARN" }
        Add-Check "DCDIAG: $dc" $status `
            "Exit code=$exit; see $log" `
            "Inspect failed tests and corroborate with replication and DNS checks."
    }
} else {
    Add-Check "DCDIAG" "SKIP" "dcdiag.exe not found."
}

# Current machine's Security log: recent high-value event IDs.
# This is not a substitute for collecting from every DC.
try {
    $since = (Get-Date).AddHours(-$EventLookbackHours)
    $ids = @(1102, 4719, 4720, 4722, 4724, 4726, 4728, 4732, 4740, 4756, 5136)

    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = $ids
            StartTime = $since
        } -MaxEvents 200 -ErrorAction SilentlyContinue
    )

    $events |
        Select-Object TimeCreated, Id, MachineName, RecordId, Message |
        Export-Csv (Join-Path $outDir "security-events.csv") `
            -NoTypeInformation

    Add-Check "Recent security events" "INFO" `
        "$($events.Count) matching events on local host in last $EventLookbackHours hours." `
        "Review security-events.csv. Ensure audit policies and DC collection are configured."
} catch {
    Add-Check "Recent security events" "WARN" $_.Exception.Message `
        "Verify Security log read permissions."
}

# Domain password policy
if ($domain) {
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy
        $policy | Select-Object ComplexityEnabled, ReversibleEncryptionEnabled,
            MinPasswordLength, PasswordHistoryCount, MaxPasswordAge,
            LockoutThreshold, LockoutDuration |
            Export-Csv (Join-Path $outDir "password-policy.csv") `
                -NoTypeInformation

        if ($policy.ReversibleEncryptionEnabled) {
            Add-Check "Reversible password encryption" "WARN" "Enabled" `
                "Validate dependencies and plan a safe remediation if unnecessary."
        } else {
            Add-Check "Reversible password encryption" "PASS" "Disabled."
        }

        if ($policy.MinPasswordLength -lt 14) {
            Add-Check "Password length baseline" "INFO" `
                "Minimum length=$($policy.MinPasswordLength)" `
                "Compare against your organization's approved baseline."
        }
    } catch {
        Add-Check "Domain password policy" "WARN" $_.Exception.Message
    }
}

# Save results
$results | Export-Csv (Join-Path $outDir "health-checks.csv") `
    -NoTypeInformation

$results |
    Sort-Object Status, Check |
    Format-Table Status, Check, Details -Wrap |
    Out-String -Width 240 |
    Set-Content (Join-Path $outDir "summary.txt")

Write-Host "`nResults:" -ForegroundColor Green
$results | Group-Object Status | ForEach-Object {
    Write-Host ("{0}: {1}" -f $_.Name, $_.Count)
}

Write-Host "Report folder: $outDir"
Write-Host "Open summary.txt and health-checks.csv first."
