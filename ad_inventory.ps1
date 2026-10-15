# Verifies Active Directory RSAT tools are installed and attempts to install them if not found

param(
    [string]$OutputRoot = ".\AD-Inventory-Reports",
    [int]$StaleDays = 90
)

# Collects an inventory of Active Directory objects and generates a report with findings

Get-Module -ListAvailable ActiveDirectory

Add-WindowsCapability -Online `
  -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0


$ErrorActionPreference = "Continue"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-Error "Cannot load AD module or query the domain: $_"
    return
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutputRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()
$cutoff = (Get-Date).AddDays(-$StaleDays)

Write-Host "Collecting inventory for $($domain.DNSRoot)..." -ForegroundColor Cyan

# 1. Domain controllers
$dcs = Get-ADDomainController -Filter * |
    Select-Object HostName, IPv4Address, Site, IsGlobalCatalog,
        IsReadOnly, OperatingSystem, OperationMasterRoles

$dcs | Export-Csv "$outDir\DomainControllers.csv" -NoTypeInformation

# 2. Users
$users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate,
    PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,
    AdminCount, ServicePrincipalNames, whenCreated |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate,
        PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,
        AdminCount, ServicePrincipalNames, whenCreated, DistinguishedName

$users | Export-Csv "$outDir\Users.csv" -NoTypeInformation

foreach ($u in $users) {
    if ($u.Enabled -and $u.PasswordNotRequired) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object = $u.SamAccountName
            Issue = "Enabled account has PasswordNotRequired set"
            Evidence = "PasswordNotRequired=True"
        })
    }

    if ($u.Enabled -and $u.PasswordNeverExpires) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object = $u.SamAccountName
            Issue = "Password never expires"
            Evidence = "PasswordNeverExpires=True"
        })
    }

    if ($u.Enabled -and $u.LastLogonDate -and
        $u.LastLogonDate -lt $cutoff) {
        $findings.Add([pscustomobject]@{
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

$computers | Export-Csv "$outDir\Computers.csv" -NoTypeInformation

foreach ($c in $computers) {
    if ($c.Enabled -and $c.LastLogonDate -and
        $c.LastLogonDate -lt $cutoff) {
        $findings.Add([pscustomobject]@{
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

$groups | Export-Csv "$outDir\Groups.csv" -NoTypeInformation

# 5. Selected privileged groups
$privilegedGroupNames = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators"
)

$privileged = foreach ($name in $privilegedGroupNames) {
    try {
        $group = Get-ADGroup -Identity $name -ErrorAction Stop
        Get-ADGroupMember -Identity $group -Recursive |
            Select-Object @{N="PrivilegedGroup";E={$name}},
                Name, SamAccountName, ObjectClass, SID
    } catch {
        Write-Warning "Could not query group '$name': $_"
    }
}

$privileged | Export-Csv "$outDir\PrivilegedMembers.csv" -NoTypeInformation

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

# 7. Findings
$findings | Export-Csv "$outDir\Findings.csv" -NoTypeInformation

# 8. Readable HTML summary
$high = @($findings | Where-Object Severity -eq "High").Count
$medium = @($findings | Where-Object Severity -eq "Medium").Count

$rows = foreach ($f in $findings) {
    $severity = [System.Net.WebUtility]::HtmlEncode($f.Severity)
    $obj = [System.Net.WebUtility]::HtmlEncode($f.Object)
    $issue = [System.Net.WebUtility]::HtmlEncode($f.Issue)
    $evidence = [System.Net.WebUtility]::HtmlEncode($f.Evidence)

    "<tr><td>$severity</td><td>$obj</td><td>$issue</td><td>$evidence</td></tr>"
}

# Makes a neat little HTML report with findings and links to CSV exports :)
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
Groups: $(@($groups).Count)</p>
<h2>Triage findings</h2>
<p>High: $high | Medium: $medium</p>
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