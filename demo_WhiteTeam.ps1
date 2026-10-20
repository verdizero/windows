# Read only scoring simulator for isolated Windows lab environments
# Run this script from the scoring machine to simulate a scoring engine, which should be
# a separate virtual machine joined to the same lab domain

    # NOTE: this script expects the lab domain to be configured with a single DC and a single
    # service host, as well as a scoring machine and a client machine. The lab also expects
    # a configured listener on port 80 of the service host, and that the scoring machine can
    # reach the service host on ports 445 and 80

[CmdletBinding()]
param(
    [string]$DomainController = "DC01",
    [string]$ServiceHost = "SRV01",
    [string]$DomainName = "lab.example.test",
    [string]$OutputDirectory = ".\ScoringResults"
)

$ErrorActionPreference = "Stop"
$results = [System.Collections.Generic.List[object]]::new()

function Add-CheckResult {
    param(
        [string]$Name,
        [bool]$Passed,
        [int]$Points,
        [string]$Details
    )

    $script:results.Add([pscustomobject]@{
        Time    = (Get-Date).ToString("o")
        Check   = $Name
        Passed  = $Passed
        Earned  = if ($Passed) { $Points } else { 0 }
        Possible = $Points
        Details = $Details
    })
}

# DNS resolution
try {
    $resolved = Resolve-DnsName -Name $DomainController `
        -Type A -ErrorAction Stop

    Add-CheckResult "DC DNS resolution" $true 10 `
        (($resolved.IPAddress | Where-Object { $_ }) -join ", ")
}
catch {
    Add-CheckResult "DC DNS resolution" $false 10 $_.Exception.Message
}

# Domain discovery
try {
    $discovery = Resolve-DnsName `
        -Name "_ldap._tcp.dc._msdcs.$DomainName" `
        -Type SRV -ErrorAction Stop

    Add-CheckResult "AD LDAP SRV record" `
        ($null -ne $discovery) 10 "AD discovery record resolved"
}
catch {
    Add-CheckResult "AD LDAP SRV record" $false 10 `
        $_.Exception.Message
}

# TCP reachability from the scoring machine
    # Only test ports that are intentionally configured in lab
$ports = @(
    @{ Name = "LDAP TCP"; Host = $DomainController; Port = 389; Points = 10 },
    @{ Name = "SMB TCP";  Host = $ServiceHost; Port = 445; Points = 10 },
    @{ Name = "HTTP TCP"; Host = $ServiceHost; Port = 80; Points = 10 }
)

foreach ($item in $ports) {
    try {
        $ok = Test-NetConnection -ComputerName $item.Host `
            -Port $item.Port -InformationLevel Quiet `
            -WarningAction SilentlyContinue

        Add-CheckResult $item.Name ([bool]$ok) $item.Points `
            "$($item.Host):$($item.Port)"
    }
    catch {
        Add-CheckResult $item.Name $false $item.Points `
            $_.Exception.Message
    }
}

# Example local service check
    # Run this portion on server machine, or replace it 
    # with an explicitly authorized remote service query
    # ex. sc \\192.168.10.129 query W32Time
if ($env:COMPUTERNAME -eq $ServiceHost) {
    $svc = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
    $running = ($null -ne $svc -and $svc.Status -eq "Running")

    Add-CheckResult "Server service state" $running 10 `
        $(if ($svc) { "$($svc.Status)" } else { "Service not found" })
}
else {
    Add-CheckResult "Server service state" $false 10 `
        "Run this check on $ServiceHost to verify local service state"
}

# Score and export
$earned = ($results | Measure-Object -Property Earned -Sum).Sum
$possible = ($results | Measure-Object -Property Possible -Sum).Sum

New-Item -ItemType Directory -Path $OutputDirectory `
    -Force | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$results | Export-Csv `
    -Path (Join-Path $OutputDirectory "$stamp-checks.csv") `
    -NoTypeInformation

$results | Format-Table Check, Passed, Earned, Possible, Details -AutoSize

Write-Host "`nSimulated score: $earned / $possible"
Write-Host "Results saved to $OutputDirectory"