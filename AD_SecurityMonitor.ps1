#requires -Version 5.1
<#
.SYNOPSIS
    Read-only background monitor for Windows security events 
    with guidance for triage
.DESCRIPTION
    Polls local or remote Windows Security logs, tracks per-host
    event record IDs, displays useful event context, and pipes into a
    CSV file for later review
.EXAMPLE
    .\AD-SecurityMonitor.ps1 -ComputerName DC01,DC02
.EXAMPLE
    .\AD-SecurityMonitor.ps1 -ComputerName DC01 -PollSeconds 10
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$PollSeconds = 15,
    [string]$OutputRoot = ".\AD-SecurityMonitor",
    [int]$FirstRunLookbackMinutes = 5,
    [switch]$IncludeInformational
)

$ErrorActionPreference = "Stop"

if ($PollSeconds -lt 2) {
    throw "PollSeconds must be at least 2."
}
if ($FirstRunLookbackMinutes -lt 0) {
    throw "FirstRunLookbackMinutes cannot be negative."
}

$root = [System.IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $root -Force | Out-Null

$checkpointPath = Join-Path $root "checkpoints.json"
$alertPath = Join-Path $root "alerts.csv"
$monitorLogPath = Join-Path $root "monitor.log"

# Enables successful and failed auditing categories
    # Viewable with with auditpol /get /category:*
auditpol /get /category:*
auditpol /set /subcategory:”Logon” /success:enable /failure:enable
auditpol /set /subcategory:”User Account Management” /success:enable /failure:enable
auditpol /set /subcategory:”Security Group Management” /success:enable /failure:enable
auditpol /set /subcategory:”Process Creation” /success:enable /failure:enable
auditpol /set /subcategory:”Audit Policy Change” /success:enable /failure:enable

# Creates an event catalog with descriptions and triage guidance
# for common security events. Not exhaustive, and also not verdicts
# on whether an event is malicious or benign!!
$eventCatalog = @{
    4624 = @{
        Severity = "Info"
        Title = "Successful logon"
        Meaning = "A logon session was created."
        Investigate = "Review logon type, account, source address, and expected activity."
    }
    4625 = @{
        Severity = "Medium"
        Title = "Failed logon"
        Meaning = "A logon attempt failed."
        Investigate = "Check target account, source address, status/substatus, and repeated attempts."
    }
    4648 = @{
        Severity = "Medium"
        Title = "Explicit credentials used"
        Meaning = "A process attempted a logon using explicitly supplied credentials."
        Investigate = "Confirm the process, account, target server, and whether this was expected."
    }
    4672 = @{
        Severity = "Medium"
        Title = "Special privileges assigned"
        Meaning = "A new logon was granted sensitive privileges."
        Investigate = "Correlate the logon ID with 4624 and verify the account's role."
    }
    4688 = @{
        Severity = "Info"
        Title = "Process created"
        Meaning = "A new process was created, if process-creation auditing is enabled."
        Investigate = "Review executable, parent process, command line if collected, and user."
    }
    4697 = @{
        Severity = "High"
        Title = "Service installed"
        Meaning = "A service was installed on the system."
        Investigate = "Verify service name, binary path, installer, account, and change record."
    }
    4720 = @{
        Severity = "High"
        Title = "User account created"
        Meaning = "A user account was created."
        Investigate = "Identify the actor, new account, creation time, and approval."
    }
    4722 = @{
        Severity = "Medium"
        Title = "User account enabled"
        Meaning = "A user account was enabled."
        Investigate = "Check who enabled it and whether the account should be active."
    }
    4724 = @{
        Severity = "High"
        Title = "Password reset attempted"
        Meaning = "An attempt was made to reset an account password."
        Investigate = "Identify the target and actor; verify the reset was authorized."
    }
    4725 = @{
        Severity = "Info"
        Title = "User account disabled"
        Meaning = "A user account was disabled."
        Investigate = "Verify this was an approved administrative action."
    }
    4726 = @{
        Severity = "Medium"
        Title = "User account deleted"
        Meaning = "A user account was deleted."
        Investigate = "Verify the actor, target, and change authorization."
    }
    4728 = @{
        Severity = "High"
        Title = "Member added to global security group"
        Meaning = "A member was added to a security-enabled global group."
        Investigate = "Inspect the group and member; prioritize privileged groups."
    }
    4729 = @{
        Severity = "Info"
        Title = "Member removed from global security group"
        Meaning = "A member was removed from a security-enabled global group."
        Investigate = "Check whether this was authorized and whether access was restored later."
    }
    4732 = @{
        Severity = "High"
        Title = "Member added to local security group"
        Meaning = "A member was added to a security-enabled local group."
        Investigate = "Identify the group and member; check administrative groups."
    }
    4733 = @{
        Severity = "Info"
        Title = "Member removed from local security group"
        Meaning = "A member was removed from a security-enabled local group."
        Investigate = "Validate the membership change."
    }
    4739 = @{
        Severity = "High"
        Title = "Domain policy changed"
        Meaning = "A domain policy setting was changed."
        Investigate = "Review the changed settings, actor, and approved change window."
    }
    4740 = @{
        Severity = "Medium"
        Title = "Account locked out"
        Meaning = "An account was locked out."
        Investigate = "Review caller computer and nearby failed logons; check stale credentials."
    }
    4756 = @{
        Severity = "High"
        Title = "Member added to universal security group"
        Meaning = "A member was added to a security-enabled universal group."
        Investigate = "Inspect the group and member and validate the change."
    }
    4757 = @{
        Severity = "Info"
        Title = "Member removed from universal security group"
        Meaning = "A member was removed from a security-enabled universal group."
        Investigate = "Validate the membership change."
    }
    4768 = @{
        Severity = "Info"
        Title = "Kerberos TGT requested"
        Meaning = "A Kerberos ticket-granting ticket was requested."
        Investigate = "Review account, client address, status, and authentication type."
    }
    4769 = @{
        Severity = "Info"
        Title = "Kerberos service ticket requested"
        Meaning = "A Kerberos service ticket was requested."
        Investigate = "Look for unusual accounts, services, client addresses, or request patterns."
    }
    4771 = @{
        Severity = "Medium"
        Title = "Kerberos pre-authentication failed"
        Meaning = "Kerberos pre-authentication failed."
        Investigate = "Check account, client address, failure code, and repeated requests."
    }
    4776 = @{
        Severity = "Info"
        Title = "NTLM credential validation"
        Meaning = "NTLM credentials were validated or validation failed."
        Investigate = "Review workstation, account, status, and unexpected NTLM usage."
    }
    1102 = @{
        Severity = "High"
        Title = "Security audit log cleared"
        Meaning = "The Security audit log was cleared."
        Investigate = "Urgently verify the actor and change history; preserve other available logs."
    }
    4719 = @{
        Severity = "High"
        Title = "System audit policy changed"
        Meaning = "The system audit policy was changed."
        Investigate = "Check which audit settings changed and whether visibility was reduced."
    }
    5136 = @{
        Severity = "High"
        Title = "Directory object modified"
        Meaning = "An Active Directory object was modified, when directory-change auditing is enabled."
        Investigate = "Inspect object DN, attribute, actor, and old/new values where available."
    }
    4662 = @{
        Severity = "Medium"
        Title = "Directory object operation"
        Meaning = "An operation was performed on an AD object, when appropriate auditing is enabled."
        Investigate = "Review subject, object, access mask, properties, and directory auditing configuration."
    }
}

function Write-MonitorLog {
    param([string]$Message)

    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $monitorLogPath -Value $line -Encoding UTF8
}

function Get-EventData {
    param($SecurityEvent)

    $result = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($item in $xml.Event.EventData.Data) {
            if ($item.Name) {
                $result[[string]$item.Name] = [string]$item.'#text'
            }
        }
    } catch {}

    return $result
}

function Get-FirstValue {
    param(
        [hashtable]$Data,
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($Data.ContainsKey($name) -and
            -not [string]::IsNullOrWhiteSpace($Data[$name])) {
            return [string]$Data[$name]
        }
    }
    return ""
}

function Get-EventDescription {
    param([int]$Id)

    if ($eventCatalog.ContainsKey($Id)) {
        return $eventCatalog[$Id]
    }

    return @{
        Severity = "Info"
        Title = "Uncatalogued event"
        Meaning = "No custom explanation is configured for this event ID."
        Investigate = "Review the event message and provider details in Event Viewer."
    }
}

function Send-Alert {
    param(
        [string]$HostName,
        $SecurityEvent,
        [hashtable]$Data
    )

    $id = [int]$Event.Id
    $info = Get-EventDescription -Id $id

    if ($info.Severity -eq "Info" -and -not $IncludeInformational) {
        return
    }

    $target = Get-FirstValue $Data @(
        "TargetUserName", "AccountName", "MemberName",
        "ServiceName", "ObjectName"
    )
    $actor = Get-FirstValue $Data @(
        "SubjectUserName", "CallerUserName", "AccountName"
    )
    $source = Get-FirstValue $Data @(
        "IpAddress", "ClientAddress", "Workstation",
        "WorkstationName", "CallerComputerName"
    )

    $message = [string]$Event.Message
    if ($message.Length -gt 3500) {
        $message = $message.Substring(0, 3500) + " [truncated]"
    }

    $record = [pscustomobject]@{
        TimeCreated = $Event.TimeCreated
        Computer = $HostName
        EventId = $id
        Severity = $info.Severity
        Title = $info.Title
        AccountOrTarget = $target
        Actor = $actor
        SourceAddressOrHost = $source
        RecordId = $Event.RecordId
        Meaning = $info.Meaning
        RecommendedTriage = $info.Investigate
        EventMessage = $message
    }

    $color = switch ($info.Severity) {
        "High"   { "Red" }
        "Medium" { "Yellow" }
        default  { "Cyan" }
    }

    Write-Host ""
    Write-Host ("[{0}] [{1}] {2} - Event {3}" -f
        $info.Severity, $HostName, $info.Title, $id) -ForegroundColor $color
    Write-Host ("Time: {0} | Record: {1}" -f
        $Event.TimeCreated, $Event.RecordId)
    if ($target) { Write-Host "Target: $target" }
    if ($actor)  { Write-Host "Actor:  $actor" }
    if ($source) { Write-Host "Source: $source" }
    Write-Host "Meaning: $($info.Meaning)"
    Write-Host "Triage:  $($info.Investigate)"
    Write-Host "Details: $message"

    if (Test-Path -LiteralPath $alertPath) {
        $record | Export-Csv -LiteralPath $alertPath -NoTypeInformation `
            -Append -Encoding UTF8
    } else {
        $record | Export-Csv -LiteralPath $alertPath -NoTypeInformation `
            -Encoding UTF8
    }

    Write-MonitorLog ("ALERT host={0} id={1} record={2} severity={3}" -f
        $HostName, $id, $Event.RecordId, $info.Severity)
}

# Loads existing checkpoints
$checkpoints = @{}
if (Test-Path -LiteralPath $checkpointPath) {
    try {
        $saved = Get-Content -LiteralPath $checkpointPath -Raw |
            ConvertFrom-Json
        foreach ($property in $saved.PSObject.Properties) {
            $checkpoints[$property.Name] = [long]$property.Value
        }
    } catch {
        throw "Cannot read checkpoints at $checkpointPath. Back it up and inspect it before restarting. $_"
    }
}

Write-Host "AD Security Monitor" -ForegroundColor Cyan
Write-Host "Hosts: $($ComputerName -join ', ')"
Write-Host "Poll interval: $PollSeconds seconds"
Write-Host "Alert CSV: $alertPath"
Write-Host "Press Ctrl+C to stop."
Write-MonitorLog "Monitor starting for $($ComputerName -join ', ')"

# Establish initial checkpoints - By default, only events after startup
# are monitored; can inspect a short lookback on first run
foreach ($hostName in $ComputerName) {
    if (-not $checkpoints.ContainsKey($hostName)) {
        try {
            $latest = Get-WinEvent -ComputerName $hostName `
                -LogName Security -MaxEvents 1 -ErrorAction Stop

            $lastId = [long]$latest.RecordId

            if ($FirstRunLookbackMinutes -gt 0) {
                $since = (Get-Date).AddMinutes(-$FirstRunLookbackMinutes)
                $initialEvents = @(
                    Get-WinEvent -ComputerName $hostName `
                        -FilterHashtable @{
                            LogName = "Security"
                            StartTime = $since
                        } -ErrorAction SilentlyContinue |
                    Where-Object { $_.RecordId -le $lastId } |
                    Sort-Object RecordId
                )

                foreach ($securityEvent in $initialEvents) {
                    $data = Get-EventData $event
                    Send-Alert -HostName $hostName -Event $event -Data $data
                }
            }

            $checkpoints[$hostName] = $lastId
            Write-Host "Initialized $hostName at record $lastId"
            Write-MonitorLog "Initialized host=$hostName record=$lastId"
        } catch {
            Write-Warning "Cannot initialize $hostName : $_"
            Write-MonitorLog "INIT-ERROR host=$hostName error=$($_.Exception.Message)"
        }
    }
}

$checkpoints | ConvertTo-Json |
    Set-Content -LiteralPath $checkpointPath -Encoding UTF8

while ($true) {
    foreach ($hostName in $ComputerName) {
        try {
            if (-not $checkpoints.ContainsKey($hostName)) {
                continue
            }

            $lastId = [long]$checkpoints[$hostName]

            # Query recent events and filter by the persisted record ID
            $since = (Get-Date).AddMinutes(-10)
            $events = @(
                Get-WinEvent -ComputerName $hostName `
                    -FilterHashtable @{
                        LogName = "Security"
                        StartTime = $since
                    } -ErrorAction SilentlyContinue |
                Where-Object { [long]$_.RecordId -gt $lastId } |
                Sort-Object RecordId
            )

            foreach ($securityEvent in $events) {
                $data = Get-EventData $event
                Send-Alert -HostName $hostName -Event $event -Data $data

                if ([long]$event.RecordId -gt $lastId) {
                    $lastId = [long]$event.RecordId
                }
            }

            $checkpoints[$hostName] = $lastId
        } catch {
            Write-Warning "Polling $hostName failed: $_"
            Write-MonitorLog "POLL-ERROR host=$hostName error=$($_.Exception.Message)"
        }
    }

    # Save checkpoints after each polling cycle, so that the monitor can resume from the last processed event
    $checkpoints | ConvertTo-Json |
        Set-Content -LiteralPath $checkpointPath -Encoding UTF8

    Start-Sleep -Seconds $PollSeconds
}
