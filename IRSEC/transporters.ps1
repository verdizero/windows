$ComputerName = "transporters"
$IPv4         = "192.168.15.1"

# fill in after confirming comp network
$InternalSubnets      = @(192.168.15.0/24)
$ApprovedSMBClients   = @()
$ApprovedAdminIPs     = @()
$DomainControllerIPs  = @()
$ScoringAdminIP       = ""

# placeholder variable for exact white team account identity
$WhiteTeamAccount     = "whiteteam"

$BackupRoot = Join-Path $env:SystemDrive "backups"
$Timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$BackupDir  = Join-Path $BackupRoot "transporters-SMB-$Timestamp"

# checks to see if the script is being run on the correct computer

if ($env:COMPUTERNAME -ne $ComputerName) {
    throw "Run on $ComputerName, not $env:COMPUTERNAME."
}

$ComputerSystem = Get-CimInstance Win32_ComputerSystem
$DomainName = if ($ComputerSystem.PartOfDomain) {
    $ComputerSystem.Domain
} else {
    $null
}

$Addresses = @(
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*"
        } |
        Select-Object -ExpandProperty IPAddress
)

if ($IPv4 -notin $Addresses) {
    throw "Script expected IP: $IPv4 but was not found in the system's IPv4 addresses."
}

Write-Host "Host: $env:COMPUTERNAME"
Write-Host "Domain: $(if ($DomainName) { $DomainName } else { 'standalone' })"
Write-Host "IPv4: $($Addresses -join ', ')"