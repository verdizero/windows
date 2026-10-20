# Verifies Active Directory RSAT tools are installed and attempts to install them if not found
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module not found. Installing RSAT..." -ForegroundColor Yellow
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop
}

# DNS RSAT Check
if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host "DnsServer module not found. Script will fallback to WMI if needed..." -ForegroundColor Yellow
}

Import-Module ActiveDirectory -ErrorAction Stop

# Attempt automatic domain query and falls back to explicit DC if needed
try {
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-Warning "Default ADWS discovery failed: $_"
    $dcTarget = Read-Host "Enter the FQDN or IP of a target Domain Controller (e.g. dc01.domain.com)"
    $domain = Get-ADDomain -Server$dcTarget -ErrorAction Stop
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutputRoot$stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()
$cutoff = (Get-Date).AddDays(-$StaleDays)

Write-Host "Collecting inventory for $($domain.DNSRoot)..." -ForegroundColor Cyan

# 1. Domain controllers
$dcs = Get-ADDomainController -Filter * |
    Select-Object HostName, IPv4Address, Site, IsGlobalCatalog,
        IsReadOnly, OperatingSystem, OperationMasterRoles

$dcs \vert{} Export-Csv "$outDir\DomainControllers.csv" -NoTypeInformation

# 2. Users
$users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate,
    PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,
    AdminCount, ServicePrincipalNames, whenCreated |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate,
        PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,
        AdminCount, ServicePrincipalNames, whenCreated, DistinguishedName

$users \vert{} Export-Csv "$outDir\Users.csv" -NoTypeInformation

foreach ($u in$users) {
    if ($u.Enabled -and $u.PasswordNotRequired) {$findings.Add([pscustomobject]@{
            Severity = "High"
            Object = $u.SamAccountName
            Issue = "Enabled account has PasswordNotRequired set"
            Evidence = "PasswordNotRequired=True"
        })
    }

    if ($u.Enabled -and $u.PasswordNeverExpires) {$findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object = $u.SamAccountName
            Issue = "Password never expires"
            Evidence = "PasswordNeverExpires=True"
        })
    }

    if ($u.Enabled -and $u.LastLogonDate -and$u.LastLogonDate -lt $cutoff) {$findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object = $u.SamAccountName
            Issue = "Potentially stale enabled user"
            Evidence = "LastLogonDate=$($u.LastLogonDate)"
        })
    }
}

# 3. Computers
$computers = Get-ADComputer -Filter * -Properties Enabled,
    LastLogonDate, OperatingSystem, OperatingSystemVersion,
    PasswordLastSet |
    Select-Object Name, Enabled, LastLogonDate, OperatingSystem,
        OperatingSystemVersion, PasswordLastSet, DistinguishedName

$computers \vert{} Export-Csv "$outDir\Computers.csv" -NoTypeInformation

foreach ($c in$computers) {
    if ($c.Enabled -and $c.LastLogonDate -and$c.LastLogonDate -lt $cutoff) {$findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object = $c.Name
            Issue = "Potentially stale enabled computer"
            Evidence = "LastLogonDate=$($c.LastLogonDate)"
        })
    }
}

# 4. Groups
$groups = Get-ADGroup -Filter * -Properties GroupCategory,
    GroupScope, AdminCount, whenCreated |
    Select-Object Name, SamAccountName, SID, GroupCategory,
        GroupScope, AdminCount, whenCreated, DistinguishedName

$groups \vert{} Export-Csv "$outDir\Groups.csv" -NoTypeInformation

# 5. Selected privileged groups
$privilegedGroupNames = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators"
)

$privileged = foreach ($name in$privilegedGroupNames) {
    try {
        $group = Get-ADGroup -Identity$name -ErrorAction Stop
        Get-ADGroupMember -Identity $group -Recursive |
            Select-Object @{N="PrivilegedGroup";E={$name}},
                Name, SamAccountName, ObjectClass, SID
    } catch {
        Write-Warning "Could not query group '$name':$_"
    }
}

$privileged \vert{} Export-Csv "$outDir\PrivilegedMembers.csv" -NoTypeInformation

# 6. Default domain password policy
try {
    Get-ADDefaultDomainPasswordPolicy |
        Select-Object ComplexityEnabled, MinPasswordLength,
            PasswordHistoryCount, MaxPasswordAge, LockoutThreshold,
            LockoutDuration, LockoutObservationWindow |
        Export-Csv "$outDir\PasswordPolicy.csv" -NoTypeInformation
} catch {
    Write-Warning "Password policy query failed: $_"
}

# 7. DNS zones, records and triage
Write-Host "Querying DNS configuration..." -ForegroundColor Cyan

# Enumerate DNS zones
try {
    $dnsZones = Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName, ZoneType, DynamicUpdate, IsDsIntegrated, IsReverseLookupZone
} catch {
    $dnsZones = Get-CimInstance -Namespace "root\MicrosoftDNS" -ClassName "MicrosoftDNS_Zone" -ErrorAction SilentlyContinue |
        Select-Object @{N="ZoneName";E={$_.Name}}, ZoneType, @{N="DynamicUpdate";E={$_.AllowUpdate}}, @{N="IsDsIntegrated";E={$_.DsIntegrated}}, @{N="IsReverseLookupZone";E={$_.Reverse}}
}

if ($dnsZones) {
    $dnsZones \vert{} Export-Csv "$outDir\DNS_Zones.csv" -NoTypeInformation

    foreach ($zone in$dnsZones) {
        if ($zone.DynamicUpdate -eq "NonsecureAndSecure" -or $zone.DynamicUpdate -eq 1) {$findings.Add([pscustomobject]@{
                Severity = "High"
                Object   = $zone.ZoneName
                Issue    = "DNS Zone allows non-secure dynamic updates"
                Evidence = "DynamicUpdate=$($zone.DynamicUpdate) (Allows unauthenticated DNS poisoning)"
            })
        }
    }

    # Dump DNS resource records
    $dnsRecords = foreach ($zone in$dnsZones) {
        $zName =$zone.ZoneName
        try {
            Get-DnsServerResourceRecord -ZoneName $zName -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    ZoneName   = $zName
                    HostName   = $_.HostName
                    RecordType = $_.RecordType
                    RecordData = ($_.RecordData.IPv4Address.IPAddressToString + $_.RecordData.HostNameAlias +$_.RecordData.DescriptiveText) -join ""
                    TimeToLive = $_.TimeToLive.TotalSeconds
                    Timestamp  = $_.TimeStamp
                }
            }
        } catch {
            Get-CimInstance -Namespace "root\MicrosoftDNS" -ClassName "MicrosoftDNS_ResourceRecord" -Filter "ContainerName='$zName'" -ErrorAction SilentlyContinue |
                Select-Object @{N="ZoneName";E={$_.ContainerName}}, @{N="HostName";E={$_.OwnerName}}, @{N="RecordType";E={$_.RecordClass}}, @{N="RecordData";E={$_.TextRepresentation}}, TimeToLive, Timestamp
        }
    }

    if ($dnsRecords) {
        $dnsRecords \vert{} Export-Csv "$outDir\DNS_ResourceRecords.csv" -NoTypeInformation

        foreach ($rec in$dnsRecords) {
            # Check for WPAD / ISATAP hijacking risks
            if ($rec.HostName -in @("wpad", "isatap") -and -not $rec.Timestamp) {$findings.Add([pscustomobject]@{
                    Severity = "High"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "Static WPAD/ISATAP record detected"
                    Evidence = "Points to $($rec.RecordData). High risk of MiTM hijacking."
                })
            }

            # Check for static host records
            if ($rec.RecordType -in @("A", "AAAA") -and -not $rec.Timestamp -and$rec.HostName -ne "@") {
                $findings.Add([pscustomobject]@{
                    Severity = "Low"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "Static A/AAAA record (No timestamp)"
                    Evidence = "Target IP: $($rec.RecordData)"
                })
            }

            # Check for TXT records
            if ($rec.RecordType -eq "TXT") {
                $findings.Add([pscustomobject]@{
                    Severity = "Medium"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "DNS TXT record found"
                    Evidence = "Data: $($rec.RecordData)"
                })
            }
        }
    }
}

# Check global query blockList status
try {
    $globalBlocklist = Get-DnsServerGlobalQueryBlockList -ErrorAction Stop
    if (-not $globalBlocklist.Enable) {$findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = "DNS Server Configuration"
            Issue    = "DNS Global Query BlockList is disabled"
            Evidence = "Enable = False (Allows WPAD/ISATAP resolution)"
        })
    }
} catch {
    # Ignore error if run from a workstation target without local DNS Server module context
}


# Export findings to CSV for triage
$findings \vert{} Export-Csv "$outDir\Findings.csv" -NoTypeInformation

# Makes a neat little HTML report with findings and links to CSV exports :)
$high = @($findings | Where-Object Severity -eq "High").Count
$medium = @($findings | Where-Object Severity -eq "Medium").Count

$rows = foreach ($f in$findings) {
    $severity = [System.Net.WebUtility]::HtmlEncode($f.Severity)
    $obj = [System.Net.WebUtility]::HtmlEncode($f.Object)
    $issue = [System.Net.WebUtility]::HtmlEncode($f.Issue)
    $evidence = [System.Net.WebUtility]::HtmlEncode($f.Evidence)

    "<tr><td>$severity</td><td>$obj</td><td>$issue</td><td>$evidence</td></tr>"
}

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>AD Inventory Report</title>
<style>
body { font-family: Segoe UI, Arial; margin: 30px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background: #e8eef5; }
</style>
</head>
<body>
<h1>Active Directory Inventory</h1>
<p>Domain: $($domain.DNSRoot)</p>
<p>Generated: $(Get-Date)</p>
<p>Users: $(@($users).Count) |
Computers: $(@($computers).Count) |
Groups: $(@($groups).Count) |
DNS Zones: $(@($dnsZones).Count)</p>
<h2>Triage findings</h2>
<p>High: $high \vert{} Medium:$medium</p>
<p>Findings are leads for investigation, not proof of compromise.
Review accounts and dependencies before taking action.</p>
<table>
<tr><th>Severity</th><th>Object</th><th>Issue</th><th>Evidence</th></tr>
$($rows -join "`n")
</table>
</body>
</html>
"@

$html | Set-Content "$outDir\Report.html" -Encoding UTF8

Write-Host "`nInventory complete!" -ForegroundColor Green
Write-Host "Report: $outDir\Report.html"
Write-Host "CSV exports: $outDir"
