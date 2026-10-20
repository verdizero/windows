#requires -Version 5.1
<#
.SYNOPSIS
    Collects an Active Directory and DNS inventory and writes CSV and HTML reports.

.DESCRIPTION
    Read-only inventory/triage script. It does not disable accounts, change DNS,
    or remediate findings. Run from an elevated PowerShell session with network
    access to the domain and appropriate read permissions

.PARAMETER OutputRoot
    Parent directory under which a timestamped report directory is created

.PARAMETER StaleDays
    Number of days without a recorded logon before an enabled user/computer is
    flagged as potentially stale

.PARAMETER Server
    Optional domain controller FQDN to use for Active Directory queries
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = (Join-Path $env:USERPROFILE 'ADInventory'),

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 90,

    [Parameter()]
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Object,
        [Parameter(Mandatory)][string]$Issue,
        [Parameter(Mandatory)][string]$Evidence
    )

    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Object   = $Object
        Issue    = $Issue
        Evidence = $Evidence
    })
}

function ConvertTo-RecordDataString {
    param([Parameter(Mandatory)]$RecordData)

    # DNS record data differs by record type, so builds a readable value from the
    # populated properties rather than assuming every record has IPv4Address
    $parts = foreach ($property in $RecordData.PSObject.Properties) {
        $value = $property.Value

        if ($null -eq $value) {
            continue
        }
        elseif ($value -is [System.Net.IPAddress]) {
            $value.IPAddressToString
        }
        elseif ($value -is [System.Array]) {
            ($value -join ',')
        }
        elseif ($value -is [System.TimeSpan]) {
            $value.ToString()
        }
        elseif (
            $value -is [string] -or
            $value.GetType().IsPrimitive -or
            $value -is [decimal]
        ) {
            [string]$value
        }
        elseif ($value.PSObject.Properties['IPAddressToString']) {
            $value.IPAddressToString
        }
        elseif ($value.PSObject.Properties['HostNameAlias']) {
            $value.HostNameAlias
        }
        elseif ($value.PSObject.Properties['DescriptiveText']) {
            $value.DescriptiveText
        }
        else {
            $value.ToString()
        }
    }

    return (@(
        $parts | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }
    ) -join '; ')
}

function Export-CsvSafe {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$InputObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    if (@($InputObject).Count -gt 0) {
        $InputObject |
            Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        # Write an empty file for predictable report contents
        Set-Content -LiteralPath $Path -Value '' -Encoding UTF8
    }
}

# 1. Active Directory module and domain discovery

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'Active Directory PowerShell module not found. Attempting RSAT installation...' -ForegroundColor Yellow

    if (-not (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue)) {
        throw 'The ActiveDirectory module is missing and Add-WindowsCapability is unavailable. Install RSAT Active Directory tools, then rerun this script.'
    }

    Add-WindowsCapability `
        -Online `
        -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0' `
        -ErrorAction Stop | Out-Null
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $Server) {
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $Server = $domain.PDCEmulator
    }
    catch {
        Write-Warning "Automatic domain discovery failed: $($_.Exception.Message)"

        $Server = Read-Host 'Enter the FQDN of a reachable domain controller'

        if ([string]::IsNullOrWhiteSpace($Server)) {
            throw 'A domain controller must be specified.'
        }

        $domain = Get-ADDomain -Server $Server -ErrorAction Stop
    }
}
else {
    $domain = Get-ADDomain -Server $Server -ErrorAction Stop
}

# Use a consistent server for all AD queries
$adServer = $Server

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$outDir = Join-Path `
    -Path $OutputRoot `
    -ChildPath $stamp

New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$script:Findings = [System.Collections.Generic.List[object]]::new()

$cutoff = (Get-Date).AddDays(-$StaleDays)

Write-Host "Collecting inventory for $($domain.DNSRoot) via $adServer..." -ForegroundColor Cyan
Write-Host "Output directory: $outDir" -ForegroundColor DarkGray

# 2. Domain controllers

$dcs = @(
    Get-ADDomainController -Filter * -Server $adServer |
        Select-Object HostName,
            IPv4Address,
            Site,
            IsGlobalCatalog,
            IsReadOnly,
            OperatingSystem,
            OperationMasterRoles
)

Export-CsvSafe `
    -InputObject $dcs `
    -Path (Join-Path $outDir 'DomainControllers.csv')

# 3. Users and user-account triage

$users = @(
    Get-ADUser `
        -Filter * `
        -Server $adServer `
        -Properties Enabled,
            LastLogonDate,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordNotRequired,
            AdminCount,
            ServicePrincipalNames,
            whenCreated |
        Select-Object Name,
            SamAccountName,
            Enabled,
            LastLogonDate,
            PasswordLastSet,
            PasswordNeverExpires,
            PasswordNotRequired,
            AdminCount,
            ServicePrincipalNames,
            whenCreated,
            DistinguishedName
)

Export-CsvSafe `
    -InputObject $users `
    -Path (Join-Path $outDir 'Users.csv')

foreach ($u in $users) {

    if ($u.Enabled -and $u.PasswordNotRequired) {
        Add-Finding `
            -Severity High `
            -Object $u.SamAccountName `
            -Issue 'Enabled account has PasswordNotRequired set' `
            -Evidence 'PasswordNotRequired=True'
    }

    if ($u.Enabled -and $u.PasswordNeverExpires) {
        Add-Finding `
            -Severity Medium `
            -Object $u.SamAccountName `
            -Issue 'Password never expires' `
            -Evidence 'PasswordNeverExpires=True'
    }

    if (
        $u.Enabled -and
        $u.LastLogonDate -and
        $u.LastLogonDate -lt $cutoff
    ) {
        Add-Finding `
            -Severity Medium `
            -Object $u.SamAccountName `
            -Issue 'Potentially stale enabled user' `
            -Evidence "LastLogonDate=$($u.LastLogonDate)"
    }
}

# 4. Computers and computer-account triage

$computers = @(
    Get-ADComputer `
        -Filter * `
        -Server $adServer `
        -Properties Enabled,
            LastLogonDate,
            OperatingSystem,
            OperatingSystemVersion,
            PasswordLastSet |
        Select-Object Name,
            Enabled,
            LastLogonDate,
            OperatingSystem,
            OperatingSystemVersion,
            PasswordLastSet,
            DistinguishedName
)

Export-CsvSafe `
    -InputObject $computers `
    -Path (Join-Path $outDir 'Computers.csv')

foreach ($computer in $computers) {

    if (
        $computer.Enabled -and
        $computer.LastLogonDate -and
        $computer.LastLogonDate -lt $cutoff
    ) {
        Add-Finding `
            -Severity Medium `
            -Object $computer.Name `
            -Issue 'Potentially stale enabled computer' `
            -Evidence "LastLogonDate=$($computer.LastLogonDate)"
    }
}

# 5. Groups

$groups = @(
    Get-ADGroup `
        -Filter * `
        -Server $adServer `
        -Properties GroupCategory,
            GroupScope,
            AdminCount,
            whenCreated |
        Select-Object Name,
            SamAccountName,
            SID,
            GroupCategory,
            GroupScope,
            AdminCount,
            whenCreated,
            DistinguishedName
)

Export-CsvSafe `
    -InputObject $groups `
    -Path (Join-Path $outDir 'Groups.csv')

# 6. Members of selected privileged groups

$privilegedGroupNames = @(
    'Domain Admins'
    'Enterprise Admins'
    'Schema Admins'
    'Administrators'
)

$privileged = @(
    foreach ($groupName in $privilegedGroupNames) {

        try {
            $group = Get-ADGroup `
                -Identity $groupName `
                -Server $adServer `
                -ErrorAction Stop

            Get-ADGroupMember `
                -Identity $group `
                -Server $adServer `
                -Recursive `
                -ErrorAction Stop |
                Select-Object @{
                    Name = 'PrivilegedGroup'
                    Expression = { $groupName }
                },
                Name,
                SamAccountName,
                ObjectClass,
                SID
        }
        catch {
            Write-Warning "Could not query privileged group '$groupName': $($_.Exception.Message)"
        }
    }
)

Export-CsvSafe `
    -InputObject $privileged `
    -Path (Join-Path $outDir 'PrivilegedMembers.csv')

# 7. Default domain password policy

try {
    $passwordPolicy = @(
        Get-ADDefaultDomainPasswordPolicy `
            -Server $adServer `
            -ErrorAction Stop |
            Select-Object ComplexityEnabled,
                MinPasswordLength,
                PasswordHistoryCount,
                MaxPasswordAge,
                LockoutThreshold,
                LockoutDuration,
                LockoutObservationWindow
    )

    Export-CsvSafe `
        -InputObject $passwordPolicy `
        -Path (Join-Path $outDir 'PasswordPolicy.csv')
}
catch {
    Write-Warning "Password policy query failed: $($_.Exception.Message)"
}

# 8. DNS zones, records, and triage

Write-Host 'Querying DNS configuration...' -ForegroundColor Cyan

$dnsZones = @()
$dnsRecords = @()

$dnsServerModuleAvailable = [bool](
    Get-Module -ListAvailable -Name DnsServer
)

if ($dnsServerModuleAvailable) {

    try {
        Import-Module DnsServer -ErrorAction Stop

        $dnsZones = @(
            Get-DnsServerZone `
                -ComputerName $adServer `
                -ErrorAction Stop |
                Select-Object ZoneName,
                    ZoneType,
                    DynamicUpdate,
                    IsDsIntegrated,
                    IsReverseLookupZone
        )
    }
    catch {
        Write-Warning "DNS PowerShell zone query failed: $($_.Exception.Message). Trying CIM/WMI fallback."
    }
}

# Fallback if the DNS PowerShell module is unavailable or its query fails
if ($dnsZones.Count -eq 0) {

    try {
        $dnsZones = @(
            Get-CimInstance `
                -ComputerName $adServer `
                -Namespace 'root\MicrosoftDNS' `
                -ClassName 'MicrosoftDNS_Zone' `
                -ErrorAction Stop |
                Select-Object @{
                    Name = 'ZoneName'
                    Expression = { $_.Name }
                },
                @{
                    Name = 'ZoneType'
                    Expression = { $_.ZoneType }
                },
                @{
                    Name = 'DynamicUpdate'
                    Expression = { $_.AllowUpdate }
                },
                @{
                    Name = 'IsDsIntegrated'
                    Expression = { $_.DsIntegrated }
                },
                @{
                    Name = 'IsReverseLookupZone'
                    Expression = { $_.Reverse }
                }
        )
    }
    catch {
        Write-Warning "DNS zone inventory unavailable: $($_.Exception.Message)"
    }
}

Export-CsvSafe `
    -InputObject $dnsZones `
    -Path (Join-Path $outDir 'DNS_Zones.csv')

# Check DNS zone dynamic-update configuration
foreach ($zone in $dnsZones) {

    $dynamicUpdate = [string]$zone.DynamicUpdate

    if ($dynamicUpdate -match '^(NonsecureAndSecure|1)$') {

        Add-Finding `
            -Severity High `
            -Object $zone.ZoneName `
            -Issue 'DNS zone allows non-secure dynamic updates' `
            -Evidence "DynamicUpdate=$dynamicUpdate; review whether unauthenticated updates are required."
    }
}

# Enumerate DNS resource records
foreach ($zone in $dnsZones) {

    $zoneName = [string]$zone.ZoneName

    if ([string]::IsNullOrWhiteSpace($zoneName)) {
        continue
    }

    $dnsRecordCommand = Get-Command `
        Get-DnsServerResourceRecord `
        -ErrorAction SilentlyContinue

    if ($dnsServerModuleAvailable -and $dnsRecordCommand) {

        try {
            $zoneRecords = Get-DnsServerResourceRecord `
                -ComputerName $adServer `
                -ZoneName $zoneName `
                -ErrorAction Stop

            foreach ($record in $zoneRecords) {

                $dnsRecords += [pscustomobject]@{
                    ZoneName   = $zoneName
                    HostName   = $record.HostName
                    RecordType = [string]$record.RecordType
                    RecordData = ConvertTo-RecordDataString `
                        -RecordData $record.RecordData
                    TimeToLive = $record.TimeToLive.TotalSeconds
                    Timestamp  = $record.Timestamp
                }
            }

            continue
        }
        catch {
            Write-Warning "DNS record query failed for '$zoneName'; trying CIM/WMI fallback."
        }
    }

    # CIM/WMI fallback
    try {
        $escapedZoneName = $zoneName.Replace("'", "''")

        $wmiRecords = Get-CimInstance `
            -ComputerName $adServer `
            -Namespace 'root\MicrosoftDNS' `
            -ClassName 'MicrosoftDNS_ResourceRecord' `
            -Filter "ContainerName='$escapedZoneName'" `
            -ErrorAction Stop

        foreach ($record in $wmiRecords) {

            $dnsRecords += [pscustomobject]@{
                ZoneName   = $record.ContainerName
                HostName   = $record.OwnerName
                RecordType = [string]$record.RecordClass
                RecordData = [string]$record.TextRepresentation
                TimeToLive = $record.TimeToLive
                Timestamp  = $record.Timestamp
            }
        }
    }
    catch {
        Write-Warning "Could not query DNS records for '$zoneName': $($_.Exception.Message)"
    }
}

Export-CsvSafe `
    -InputObject $dnsRecords `
    -Path (Join-Path $outDir 'DNS_ResourceRecords.csv')

# Analyze DNS records
foreach ($record in $dnsRecords) {

    $hostName = [string]$record.HostName
    $recordType = [string]$record.RecordType
    $recordObject = "$hostName.$($record.ZoneName)"

    # WPAD / ISATAP records with no timestamp warrant review
    if (
        $hostName -in @('wpad', 'isatap') -and
        -not $record.Timestamp
    ) {
        Add-Finding `
            -Severity High `
            -Object $recordObject `
            -Issue 'Static WPAD/ISATAP record detected' `
            -Evidence "Record data: $($record.RecordData). Review whether this record is expected."
    }

    # Static A / AAAA records are triage leads, not inherently malicious
    if (
        $recordType -in @('A', 'AAAA') -and
        -not $record.Timestamp -and
        $hostName -ne '@'
    ) {
        Add-Finding `
            -Severity Low `
            -Object $recordObject `
            -Issue 'Static A/AAAA record (no timestamp)' `
            -Evidence "Record data: $($record.RecordData)"
    }

    # TXT records may contain legitimate configuration data
    if ($recordType -eq 'TXT') {

        Add-Finding `
            -Severity Medium `
            -Object $recordObject `
            -Issue 'DNS TXT record found (review contents)' `
            -Evidence "Data: $($record.RecordData)"
    }
}

# Check DNS global query block-list status on the selected server
$blockListCommand = Get-Command `
    Get-DnsServerGlobalQueryBlockList `
    -ErrorAction SilentlyContinue

if ($dnsServerModuleAvailable -and $blockListCommand) {

    try {
        $blockList = Get-DnsServerGlobalQueryBlockList `
            -ComputerName $adServer `
            -ErrorAction Stop

        if (
            $blockList.PSObject.Properties['Enable'] -and
            -not $blockList.Enable
        ) {
            Add-Finding `
                -Severity High `
                -Object 'DNS Server Configuration' `
                -Issue 'DNS Global Query BlockList is disabled' `
                -Evidence 'Enable=False; review WPAD/ISATAP name-resolution exposure.'
        }
    }
    catch {
        Write-Warning "Could not query the DNS global query block list: $($_.Exception.Message)"
    }
}

# Export findings and HTML report

$findingsPath = Join-Path $outDir 'Findings.csv'

Export-CsvSafe `
    -InputObject @($script:Findings) `
    -Path $findingsPath

$high = @(
    $script:Findings | Where-Object Severity -eq 'High'
).Count

$medium = @(
    $script:Findings | Where-Object Severity -eq 'Medium'
).Count

$low = @(
    $script:Findings | Where-Object Severity -eq 'Low'
).Count

$rows = foreach ($finding in $script:Findings) {

    $severity = [System.Net.WebUtility]::HtmlEncode(
        [string]$finding.Severity
    )

    $object = [System.Net.WebUtility]::HtmlEncode(
        [string]$finding.Object
    )

    $issue = [System.Net.WebUtility]::HtmlEncode(
        [string]$finding.Issue
    )

    $evidence = [System.Net.WebUtility]::HtmlEncode(
        [string]$finding.Evidence
    )

    "<tr><td>$severity</td><td>$object</td><td>$issue</td><td>$evidence</td></tr>"
}

$domainNameHtml = [System.Net.WebUtility]::HtmlEncode(
    [string]$domain.DNSRoot
)

$generatedAtHtml = [System.Net.WebUtility]::HtmlEncode(
    (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
)

$adServerHtml = [System.Net.WebUtility]::HtmlEncode(
    [string]$adServer
)

$rowsHtml = $rows -join [Environment]::NewLine

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Active Directory Inventory Report</title>
<style>
body {
    font-family: Segoe UI, Arial, sans-serif;
    margin: 2rem;
    color: #202124;
}
table {
    border-collapse: collapse;
    width: 100%;
}
th, td {
    border: 1px solid #ccc;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}
th {
    background: #e8eef5;
}
tr:nth-child(even) {
    background: #f8f9fa;
}
code {
    overflow-wrap: anywhere;
}
</style>
</head>
<body>
<h1>Active Directory Inventory</h1>
<p>Domain: $domainNameHtml</p>
<p>Domain controller queried: $adServerHtml</p>
<p>Generated: $generatedAtHtml</p>
<p>
Users: $($users.Count) |
Computers: $($computers.Count) |
Groups: $($groups.Count) |
DNS Zones: $($dnsZones.Count)
</p>

<h2>Triage findings</h2>
<p>High: $high | Medium: $medium | Low: $low</p>

<p>
Findings are leads for investigation, not proof of compromise.
Review accounts and dependencies before taking action.
Static DNS records and TXT records are not inherently malicious.
</p>

<table>
<thead>
<tr>
<th>Severity</th>
<th>Object</th>
<th>Issue</th>
<th>Evidence</th>
</tr>
</thead>
<tbody>
$rowsHtml
</tbody>
</table>
</body>
</html>
"@

Set-Content `
    -LiteralPath (Join-Path $outDir 'Report.html') `
    -Value $html `
    -Encoding UTF8


Write-Host ''
Write-Host 'Inventory complete.' -ForegroundColor Green
Write-Host "HTML report: $(Join-Path $outDir 'Report.html')"
Write-Host "CSV exports: $outDir"