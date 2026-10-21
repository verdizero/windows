
#requires -Version 5.1
<#
NOT a full system image or Active Directory system state backup
#>

[CmdletBinding()]
param(
    [string]$Root = 'C:\TrollwareIR\Backups',
    [int]$RetentionHours = 2
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostName = $env:COMPUTERNAME
$run = Join-Path (Join-Path $Root $hostName) $stamp
$null = New-Item -ItemType Directory -Path $run -Force
$log = Join-Path $run 'backup.log'

function Log {
    param([string]$Message)
    Add-Content -LiteralPath $log -Value "$(Get-Date -Format o) $Message"
}

function Export-CsvSafe {
    param([string]$Name, [scriptblock]$Command)
    try {
        @(& $Command) |
            Export-Csv -LiteralPath (Join-Path $run $Name) -NoTypeInformation
        Log "Exported $Name"
    } catch {
        Log "FAILED $Name : $_"
    }
}

Log "Starting configuration snapshot on $hostName"

# Basic machine and OS details
Export-CsvSafe 'operating-system.csv' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object CSName, Caption, Version, BuildNumber,
                      LastBootUpTime, OSArchitecture
}

Export-CsvSafe 'computer-system.csv' {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Name, Domain, PartOfDomain, DomainRole,
                      Manufacturer, Model, TotalPhysicalMemory
}

# Installed applications: registry inventory, avoiding Win32_Product
# because querying Win32_Product can trigger MSI consistency checks
$uninstallPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = foreach ($path in $uninstallPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher,
                      InstallDate, InstallLocation
}
$apps | Sort-Object DisplayName -Unique |
    Export-Csv (Join-Path $run 'installed-apps.csv') -NoTypeInformation

Export-CsvSafe 'services.csv' {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode,
                      StartName, PathName
}

Export-CsvSafe 'drivers.csv' {
    Get-CimInstance Win32_SystemDriver |
        Select-Object Name, DisplayName, State, StartMode, PathName
}

Export-CsvSafe 'processes.csv' {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name,
                      ExecutablePath, CommandLine
}

Export-CsvSafe 'scheduled-tasks.csv' {
    Get-ScheduledTask | ForEach-Object {
        $t = $_
        [pscustomobject]@{
            TaskPath = $t.TaskPath
            TaskName = $t.TaskName
            State = $t.State
            Actions = ($t.Actions | ForEach-Object {
                "$($_.Execute) $($_.Arguments)"
            }) -join ' ; '
            Principal = $t.Principal.UserId
        }
    }
}

Export-CsvSafe 'local-admins.csv' {
    Get-LocalGroupMember -Group Administrators |
        Select-Object Name, ObjectClass, PrincipalSource, SID
}

Export-CsvSafe 'local-users.csv' {
    Get-LocalUser |
        Select-Object Name, Enabled, LastLogon, SID
}

Export-CsvSafe 'firewall-profiles.csv' {
    Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction,
                      DefaultOutboundAction, LogBlocked
}

Export-CsvSafe 'network-listeners.csv' {
    Get-NetTCPConnection -State Listen |
        Select-Object LocalAddress, LocalPort, OwningProcess
}

Export-CsvSafe 'shares.csv' {
    Get-SmbShare |
        Select-Object Name, Path, Description, Special, EncryptData
}

# Scheduled task XML for configuration recovery/reference
$taskDir = Join-Path $run 'TaskXML'
$null = New-Item -ItemType Directory -Path $taskDir -Force
try {
    foreach ($task in Get-ScheduledTask) {
        try {
            $xml = Export-ScheduledTask -TaskName $task.TaskName `
                -TaskPath $task.TaskPath -ErrorAction Stop
            $safeName = (($task.TaskPath + $task.TaskName) -replace '[\\/:*?"<>|]', '_')
            Set-Content -LiteralPath (Join-Path $taskDir "$safeName.xml") `
                -Value $xml -Encoding Unicode
        } catch {
            Log "Task XML export failed for $($task.TaskPath)$($task.TaskName)"
        }
    }
} catch {
    Log "Task export failed: $_"
}

# Export selected configuration keys as reference copies.
# These exports are evidence; do not import them blindly to restore a system.
$registryKeys = @(
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM\SYSTEM\CurrentControlSet\Services'
)
foreach ($key in $registryKeys) {
    $safeName = $key -replace '[\\/:*?"<>|]', '_'
    $destination = Join-Path $run "$safeName.reg"
    & reg.exe export $key $destination /y 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Log "Exported registry key $key"
    } else {
        Log "Registry key not exported (may not exist or access denied): $key"
    }
}

# Create hashes for collected evidence files.
$manifest = Get-ChildItem -LiteralPath $run -File -Recurse |
    Where-Object Name -ne 'manifest.csv' |
    ForEach-Object {
        try {
            $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            [pscustomobject]@{
                RelativePath = $_.FullName.Substring($run.Length).TrimStart('\')
                Length = $_.Length
                SHA256 = $h.Hash
            }
        } catch {
            Log "Could not hash $($_.FullName)"
        }
    }
$manifest | Export-Csv (Join-Path $run 'manifest.csv') -NoTypeInformation

# Compare the latest previous snapshot of this host against this one.
$hostRoot = Split-Path $run -Parent
$previous = Get-ChildItem -LiteralPath $hostRoot -Directory |
    Where-Object FullName -ne $run |
    Sort-Object Name -Descending |
    Select-Object -First 1

if ($previous -and (Test-Path (Join-Path $previous.FullName 'services.csv'))) {
    try {
        $old = Import-Csv (Join-Path $previous.FullName 'services.csv')
        $new = Import-Csv (Join-Path $run 'services.csv')
        $diff = Compare-Object $old $new -Property Name, State, StartMode, PathName
        $diff | Export-Csv (Join-Path $run 'service-changes.csv') -NoTypeInformation
        Log "Compared services with snapshot $($previous.Name)"
    } catch {
        Log "Service comparison failed: $_"
    }
}

# Remove only old timestamped snapshot directories for this host
try {
    Get-ChildItem -LiteralPath $hostRoot -Directory |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-$RetentionHours) } |
        ForEach-Object {
            Log "Removing expired snapshot directory $($_.FullName)"
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
} catch {
    Log "Retention cleanup failed: $_"
}

Log "Snapshot finished: $run"
Write-Host "Snapshot saved to $run"