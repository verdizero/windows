#requires -Version 5.1
<#
.SYNOPSIS
    Read-only background monitor for Windows security events with triage guidance.
.DESCRIPTION
    Polls local or remote Windows Security logs, tracks per-host record IDs,
    displays context, and appends alerts to a CSV.
.EXAMPLE
    .\AD-SecurityMonitor.ps1 -ComputerName DC01,DC02
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$PollSeconds = 10,
    [string]$OutputRoot = ".\AD-SecurityMonitor",
    [int]$FirstRunLookbackMinutes = 5,
    [switch]$IncludeInformational,
    [switch]$ConfigureLocalAuditPolicy
)

$ErrorActionPreference = "Stop"

if ($PollSeconds -lt 2) { throw "PollSeconds must be at least 2." }
if ($FirstRunLookbackMinutes -lt 0) { throw "FirstRunLookbackMinutes cannot be negative." }

$root = [System.IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $root -Force | Out-Null

$checkpointPath = Join-Path $root "checkpoints.json"
$alertPath      = Join-Path $root "alerts.csv"
$monitorLogPath  = Join-Path $root "monitor.log"

# Enable local auditing only if explicitly requested
if ($ConfigureLocalAuditPolicy) {
    Write-Host "[+] Configuring local audit policies via auditpol..." -ForegroundColor Green
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
}

$eventCatalog = @{
    1102 = @{ Severity = "High";   Title = "Security Audit Log Cleared"; Meaning = "Log cleared."; Investigate = "URGENT: Defense evasion in progress." }
    4624 = @{ Severity = "Info";   Title = "Successful Logon"; Meaning = "Session created."; Investigate = "Check LogonType (3=Net, 10=RDP), user, and IP." }
    4625 = @{ Severity = "Medium"; Title = "Failed Logon"; Meaning = "Logon failed."; Investigate = "Check for brute-force or password spraying." }
    4648 = @{ Severity = "Medium"; Title = "Explicit Credentials Used"; Meaning = "Process used runas/explicit creds."; Investigate = "Check subject process and target account." }
    4688 = @{ Severity = "Info";   Title = "Process Created"; Meaning = "New process executed."; Investigate = "Review command line, parent process, and path." }
    4697 = @{ Severity = "High";   Title = "Service Installed"; Meaning = "New service created."; Investigate = "Check binary path and service name for persistence." }
    4698 = @{ Severity = "High";   Title = "Scheduled Task Created"; Meaning = "Task created."; Investigate = "Check action path and triggers for persistence." }
    4720 = @{ Severity = "High";   Title = "User Account Created"; Meaning = "New user created."; Investigate = "Identify actor and verify authorization." }
    4724 = @{ Severity = "High";   Title = "Password Reset Attempted"; Meaning = "Password reset."; Investigate = "Verify actor resetting administrative passwords." }
    4728 = @{ Severity = "High";   Title = "Added to Global Security Group"; Meaning = "User added to group."; Investigate = "Check if added to Domain Admins." }
    4732 = @{ Severity = "High";   Title = "Added to Local Security Group"; Meaning = "User added to group."; Investigate = "Check if added to Local Administrators." }
    4719 = @{ Severity = "High";   Title = "Audit Policy Changed"; Meaning = "System audit settings modified."; Investigate = "Check if logging was disabled." }
}

function Write-MonitorLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $monitorLogPath -Value $line -Encoding UTF8
}

function Get-EventDataHashtable {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$SecurityEvent)

    $result = @{}
    try {
        [xml]$xml = $SecurityEvent.ToXml()
        foreach ($item in $xml.Event.EventData.Data) {
            if ($item.Name) {
                $result[[string]$item.Name] = [string]$item.'#text'
            }
        }
    } catch {}
    return $result
}

function Get-FirstValue {
    param([hashtable]$Data, [string[]]$Names)
    foreach ($name in $Names) {
        if ($Data.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($Data[$name])) {
            return [string]$Data[$name]
        }
    }
    return ""
}

function Get-EventDescription {
    param([int]$Id)
    if ($eventCatalog.ContainsKey($Id)) { return $eventCatalog[$Id] }
    return @{
        Severity = "Info"
        Title = "Uncatalogued Event"
        Meaning = "No custom explanation configured."
        Investigate = "Review raw message XML in Event Viewer."
    }
}

function Process-SecurityEvent {
    param(
        [string]$HostName,
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$SecurityEvent
    )

    $data = Get-EventDataHashtable -SecurityEvent $SecurityEvent
    $id   = [int]$SecurityEvent.Id
    $info = Get-EventDescription -Id $id

    if ($info.Severity -eq "Info" -and -not $IncludeInformational) {
        return
    }

    $target = Get-FirstValue $data @("TargetUserName", "AccountName", "MemberName", "ServiceName", "ObjectName", "TaskName")
    $actor  = Get-FirstValue $data @("SubjectUserName", "CallerUserName")
    $source = Get-FirstValue $data @("IpAddress", "ClientAddress", "Workstation", "WorkstationName", "CallerComputerName")

    $message = [string]$SecurityEvent.Message
    if ($message.Length -gt 3500) {
        $message = $message.Substring(0, 3500) + " [truncated]"
    }

    $record = [pscustomobject]@{
        TimeCreated          = $SecurityEvent.TimeCreated
        Computer             = $HostName
        EventId              = $id
        Severity             = $info.Severity
        Title                = $info.Title
        AccountOrTarget      = $target
        Actor                = $actor
        SourceAddressOrHost  = $source
        RecordId             = $SecurityEvent.RecordId
        Meaning              = $info.Meaning
        RecommendedTriage    = $info.Investigate
        EventMessage         = $message
    }

    $color = switch ($info.Severity) {
        "High"   { "Red" }
        "Medium" { "Yellow" }
        default  { "Cyan" }
    }

    Write-Host "`n[$($info.Severity)] [$HostName] $($info.Title) - Event $id" -ForegroundColor $color
    Write-Host "Time: $($SecurityEvent.TimeCreated) | Record: $($SecurityEvent.RecordId)"
    if ($target) { Write-Host "Target: $target" }
    if ($actor)  { Write-Host "Actor:  $actor" }
    if ($source) { Write-Host "Source: $source" }
    Write-Host "Triage: $($info.Investigate)"

    $exportParams = @{
        LiteralPath   = $alertPath
        NoTypeInformation = $true
        Encoding      = "UTF8"
        Append        = (Test-Path -LiteralPath $alertPath)
    }
    $record | Export-Csv @exportParams

    Write-MonitorLog ("ALERT host={0} id={1} record={2} severity={3}" -f $HostName, $id, $SecurityEvent.RecordId, $info.Severity)
}

# --- State Initialization ---
$checkpoints = @{}
if (Test-Path -LiteralPath $checkpointPath) {
    try {
        $saved = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
        foreach ($property in $saved.PSObject.Properties) {
            $checkpoints[$property.Name] = [long]$property.Value
        }
    } catch {
        throw "Cannot read checkpoints at $checkpointPath. Backup and inspect file. $_"
    }
}

Write-Host "AD Security Monitor Started" -ForegroundColor Cyan
Write-Host "Hosts: $($ComputerName -join ', ')"

foreach ($hostName in $ComputerName) {
    if (-not $checkpoints.ContainsKey($hostName)) {
        try {
            $latest = Get-WinEvent -ComputerName $hostName -LogName Security -MaxEvents 1 -ErrorAction Stop
            $lastId = [long]$latest.RecordId

            if ($FirstRunLookbackMinutes -gt 0) {
                $since = (Get-Date).AddMinutes(-$FirstRunLookbackMinutes)
                $initialEvents = @(
                    Get-WinEvent -ComputerName $hostName -FilterHashtable @{ LogName = "Security"; StartTime = $since } -ErrorAction SilentlyContinue |
                    Where-Object { $_.RecordId -le $lastId } |
                    Sort-Object RecordId
                )

                foreach ($securityEvent in $initialEvents) {
                    Process-SecurityEvent -HostName $hostName -SecurityEvent $securityEvent
                }
            }

            $checkpoints[$hostName] = $lastId
            Write-Host "Initialized $hostName at record $lastId"
        } catch {
            Write-Warning "Cannot initialize $hostName : $_"
        }
    }
}

$checkpoints | ConvertTo-Json | Set-Content -LiteralPath $checkpointPath -Encoding UTF8

# --- Polling Loop ---
while ($true) {
    foreach ($hostName in $ComputerName) {
        try {
            if (-not $checkpoints.ContainsKey($hostName)) { continue }

            $lastId = [long]$checkpoints[$hostName]
            $since  = (Get-Date).AddMinutes(-10)

            $events = @(
                Get-WinEvent -ComputerName $hostName -FilterHashtable @{ LogName = "Security"; StartTime = $since } -ErrorAction SilentlyContinue |
                Where-Object { [long]$_.RecordId -gt $lastId } |
                Sort-Object RecordId
            )

            foreach ($securityEvent in $events) {
                Process-SecurityEvent -HostName $hostName -SecurityEvent $securityEvent
                if ([long]$securityEvent.RecordId -gt $lastId) {
                    $lastId = [long]$securityEvent.RecordId
                }
            }

            $checkpoints[$hostName] = $lastId
        } catch {
            Write-Warning "Polling $hostName failed: $_"
        }
    }

    $checkpoints | ConvertTo-Json | Set-Content -LiteralPath $checkpointPath -Encoding UTF8
    Start-Sleep -Seconds $PollSeconds
}
