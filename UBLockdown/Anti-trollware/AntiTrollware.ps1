
#requires -Version 5.1
<#
Yay offline IR audit for trollware!
I hated everything about making this script
#>

[CmdletBinding()]
param(
    [string]$Database = "$PSScriptRoot\trollware-db.json",
    [string]$OutputRoot = "$env:ProgramData\TrollwareIR",
    [string]$Autorunsc = "$PSScriptRoot\Sysinternals\autorunsc64.exe",
    [switch]$SkipAutoruns
)

$ErrorActionPreference = 'Continue'
$RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunDir = Join-Path $OutputRoot $RunId
$null = New-Item -ItemType Directory -Path $RunDir -Force

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Candidates = @{}

function Log {
    param([string]$Message)
    Add-Content -LiteralPath (Join-Path $RunDir 'activity.log') `
        -Value "$(Get-Date -Format o) $Message"
    Write-Host $Message
}

function Add-Finding {
    param(
        [string]$Category, [string]$Name, [string]$Details,
        [string]$Risk = 'REVIEW', [string]$Reason = '',
        [string]$Path = '', [string]$SHA256 = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Time = Get-Date -Format o
        Category = $Category
        Name = $Name
        Risk = $Risk
        Reason = $Reason
        Details = $Details
        Path = $Path
        SHA256 = $SHA256
    })
}

function Add-Candidate {
    param([string]$Path, [string]$Source)

    if ([string]::IsNullOrWhiteSpace($Path)) { return }

    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim())

    if ($p -match '^\s*"([^"]+\.(exe|com|scr|dll|bat|cmd|ps1|vbs|js))"') {
        $p = $Matches[1]
    } elseif ($p -match '^\s*(.+?\.(exe|com|scr|bat|cmd|ps1|vbs|js))(?=\s|$)') {
        $p = $Matches[1].Trim('"')
    } else {
        $p = $p.Trim('"')
    }

    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return }

    $key = $p.ToLowerInvariant()
    if (-not $script:Candidates.ContainsKey($key)) {
        $script:Candidates[$key] = @{
            Path = $p
            Sources = New-Object System.Collections.Generic.List[string]
        }
    }
    $script:Candidates[$key].Sources.Add($Source)
}

# Validate administrator privileges
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw 'Run Windows PowerShell as Administrator.'
}

if (-not (Test-Path -LiteralPath $Database)) {
    throw "Database missing: $Database"
}

try {
    $db = Get-Content -LiteralPath $Database -Raw | ConvertFrom-Json
} catch {
    throw "Could not parse database JSON: $_"
}

if ($db.schemaVersion -ne 1) {
    throw 'Unsupported database schema version.'
}

foreach ($section in @('hashRules','taskRules','startupRules')) {
    if ($null -eq $db.$section) { throw "Missing database section: $section" }
}
foreach ($r in $db.hashRules) {
    if ([string]$r.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$r.reason)) {
        throw 'Invalid hash rule: require a 64-character SHA-256 and reason.'
    }
}

Log "Host: $env:COMPUTERNAME"
Log "Start: $(Get-Date -Format o)"
Log 'Mode: AUDIT ONLY. This script does not remove or disable anything.'

# System identity and OS details
Get-CimInstance Win32_OperatingSystem |
    Select-Object CSName, Caption, Version, BuildNumber, LastBootUpTime |
    Export-Csv (Join-Path $RunDir 'operating-system.csv') -NoTypeInformation

Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, Domain, PartOfDomain, DomainRole, Manufacturer, Model |
    Export-Csv (Join-Path $RunDir 'computer-system.csv') -NoTypeInformation

# Startup registry locations, including policy-based startup
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)

foreach ($key in $runKeys) {
    if (-not (Test-Path $key)) { continue }
    $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue

    foreach ($prop in $props.PSObject.Properties) {
        if ($prop.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') {
            continue
        }

        $value = [string]$prop.Value
        Add-Candidate -Path $value -Source "Registry:$key\$($prop.Name)"

        $rule = @($db.startupRules | Where-Object {
            [string]$_.key -ieq $key -and
            [string]$_.valueName -ieq $prop.Name
        }) | Select-Object -First 1

        Add-Finding -Category 'StartupRegistry' -Name $prop.Name `
            -Details "$key :: $value" `
            -Risk $(if ($rule) {'KNOWN_MATCH'} else {'REVIEW'}) `
            -Reason $(if ($rule) {[string]$rule.reason} else {''})
    }
}

# Other sensitive persistence settings. I made this so its inventory-early, no changes made
$specialKeys = @(
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager',
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
)

foreach ($key in $specialKeys) {
    if (Test-Path $key) {
        try {
            Get-ItemProperty -LiteralPath $key -ErrorAction Stop |
                Select-Object * -ExcludeProperty PS* |
                ConvertTo-Json -Depth 4 |
                Set-Content -LiteralPath (Join-Path $RunDir (
                    'registry-' + ($key -replace '[\\: ]','_') + '.json'
                ))
        } catch {
            Log "Could not inventory $key : $_"
        }
    }
}

# Startup folders
$startupFolders = @(
    [Environment]::GetFolderPath('CommonStartup'),
    [Environment]::GetFolderPath('Startup')
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

foreach ($folder in $startupFolders) {
    Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            Add-Candidate -Path $_.FullName -Source "StartupFolder:$folder"
            Add-Finding -Category 'StartupFile' -Name $_.Name `
                -Details $_.FullName -Path $_.FullName
        }
}

# Scheduled tasks
$taskRows = @()
try {
    foreach ($task in Get-ScheduledTask -ErrorAction Stop) {
        $actions = ($task.Actions | ForEach-Object {
            "$($_.Execute) $($_.Arguments)"
        }) -join ' ; '

        foreach ($action in $task.Actions) {
            Add-Candidate -Path $action.Execute `
                -Source "Task:$($task.TaskPath)$($task.TaskName)"
        }

        $rule = @($db.taskRules | Where-Object {
            [string]$_.taskPath -ceq [string]$task.TaskPath -and
            [string]$_.taskName -ceq [string]$task.TaskName
        }) | Select-Object -First 1

        if ($rule) {
            Add-Finding -Category 'ScheduledTask' `
                -Name "$($task.TaskPath)$($task.TaskName)" `
                -Details $actions -Risk 'KNOWN_MATCH' `
                -Reason ([string]$rule.reason)
        } elseif ($actions -match '(?i)(\\AppData\\|\\Temp\\|\\Downloads\\|wscript|cscript|mshta|powershell|rundll32|regsvr32)') {
            Add-Finding -Category 'ScheduledTask' `
                -Name "$($task.TaskPath)$($task.TaskName)" `
                -Details $actions
        }

        $taskRows += [pscustomobject]@{
            TaskPath = $task.TaskPath
            TaskName = $task.TaskName
            State = $task.State
            Actions = $actions
            Principal = $task.Principal.UserId
        }
    }
} catch { Log "Scheduled task enumeration failed: $_" }

$taskRows | Export-Csv (Join-Path $RunDir 'scheduled-tasks.csv') -NoTypeInformation

# Services and drivers
$services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
foreach ($svc in $services) {
    Add-Candidate -Path $svc.PathName -Source "Service:$($svc.Name)"

    if ($svc.PathName -match '(?i)\\Users\\[^\\]+\\AppData\\|\\Temp\\|\\Downloads\\') {
        Add-Finding -Category 'Service' -Name $svc.Name `
            -Details "$($svc.State) :: $($svc.PathName)"
    }
}
$services |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    Export-Csv (Join-Path $RunDir 'services.csv') -NoTypeInformation

Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
    Select-Object Name, DisplayName, State, StartMode, PathName |
    Export-Csv (Join-Path $RunDir 'drivers.csv') -NoTypeInformation

# WMI event persistence
$wmiClasses = @(
    @{Class='__EventFilter'; Label='WMIEventFilter'},
    @{Class='CommandLineEventConsumer'; Label='WMICommandConsumer'},
    @{Class='ActiveScriptEventConsumer'; Label='WMIActiveScriptConsumer'},
    @{Class='__FilterToConsumerBinding'; Label='WMIEventBinding'}
)

foreach ($spec in $wmiClasses) {
    try {
        Get-CimInstance -Namespace 'root/subscription' `
            -ClassName $spec.Class -ErrorAction Stop |
            Select-Object * |
            ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath (Join-Path $RunDir (
                "$($spec.Label).json"
            ))
    } catch {
        Log "WMI $($spec.Class) not available or denied: $_"
    }
}

# Running processes and candidate file paths
$processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
foreach ($proc in $processes) {
    Add-Candidate -Path $proc.ExecutablePath -Source "Process:$($proc.ProcessId)"
}
$processes |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
    Export-Csv (Join-Path $RunDir 'processes.csv') -NoTypeInformation

# Local administrators and local accounts
try {
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
        Select-Object Name, ObjectClass, PrincipalSource, SID |
        Export-Csv (Join-Path $RunDir 'local-admins.csv') -NoTypeInformation
} catch { Log "Local group inventory unavailable: $_" }

try {
    Get-LocalUser -ErrorAction Stop |
        Select-Object Name, Enabled, LastLogon, SID |
        Export-Csv (Join-Path $RunDir 'local-users.csv') -NoTypeInformation
} catch { Log "Local user inventory unavailable: $_" }

# Listening ports
try {
    Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Export-Csv (Join-Path $RunDir 'network-listeners.csv') -NoTypeInformation
} catch { Log "Listener inventory unavailable: $_" }

# Recent security-relevant events
$eventSpecs = @(
    @{Log='Security'; Id=4697},
    @{Log='Security'; Id=4698},
    @{Log='Security'; Id=4702},
    @{Log='System'; Id=7045}
)
foreach ($spec in $eventSpecs) {
    try {
        Get-WinEvent -FilterHashtable @{
            LogName = $spec.Log
            Id = $spec.Id
            StartTime = (Get-Date).AddDays(-3)
        } -MaxEvents 500 -ErrorAction Stop |
            Select-Object TimeCreated, Id, ProviderName, Message |
            Export-Csv (Join-Path $RunDir (
                "$($spec.Log)-$($spec.Id)-events.csv"
            )) -NoTypeInformation
    } catch {
        Log "Event collection skipped: $($spec.Log) ID $($spec.Id)"
    }
}

# Sysinternals Autorunsc
if (-not $SkipAutoruns -and (Test-Path -LiteralPath $Autorunsc)) {
    try {
        $autorunsOut = Join-Path $RunDir 'autoruns.csv'
        & $Autorunsc -accepteula -a '*' -c -h -s 2> (
            Join-Path $RunDir 'autorunsc-errors.txt'
        ) | Set-Content -LiteralPath $autorunsOut
        Log "Autorunsc inventory saved: $autorunsOut"
    } catch {
        Log "Autorunsc failed: $_"
    }
} else {
    Log 'Autorunsc skipped or not found.'
}

# Hash all collected executable candidates and compare database
$fileRows = foreach ($entry in $script:Candidates.Values) {
    $p = $entry.Path
    try {
        $hash = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue
        $rule = @($db.hashRules | Where-Object {
            [string]$_.sha256 -ieq $hash
        }) | Select-Object -First 1

        $risk = if ($rule) {'KNOWN_MATCH'} else {'REVIEW'}
        $reason = if ($rule) {[string]$rule.reason} else {''}

        Add-Finding -Category 'File' -Name (Split-Path $p -Leaf) `
            -Details ("Sources={0}; Signature={1}; Signer={2}" -f
                ($entry.Sources -join ';'), $sig.Status,
                $sig.SignerCertificate.Subject) `
            -Risk $risk -Reason $reason -Path $p -SHA256 $hash

        [pscustomobject]@{
            Path = $p
            SHA256 = $hash
            SignatureStatus = $sig.Status
            Signer = $sig.SignerCertificate.Subject
            Sources = $entry.Sources -join ';'
            DatabaseMatch = [bool]$rule
            Reason = $reason
        }
    } catch { Log "File inspection failed: $p :: $_" }
}
$fileRows | Export-Csv (Join-Path $RunDir 'file-inventory.csv') -NoTypeInformation

# Write report and summary
$FindingPath = Join-Path $RunDir 'findings.csv'
$script:Findings | Export-Csv $FindingPath -NoTypeInformation
$script:Findings |
    Group-Object Risk, Category |
    Select-Object @{n='Group';e={$_.Name}}, Count |
    Export-Csv (Join-Path $RunDir 'summary.csv') -NoTypeInformation

Log "Audit finished: $RunDir"
Log "Findings: $FindingPath"
Write-Host "`nAudit complete. No remediation was performed."
Write-Host "Review findings.csv, file-inventory.csv, and autoruns.csv."