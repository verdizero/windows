<#
.SYNOPSIS
  Windows Blue Team Hardening and Incident Response Installation Toolkit

.USAGE
  1. Fill in the config block below, OR leave it generic and make one small
     per-host file (see EXAMPLE CONFIG FILE at the bottom) and pass -ConfigFile
  2. Pass -InstallTools to install Sysinternals, SCT, BloodHound, and SharpHound:
     .\Harden-Windows.ps1 -InstallTools
  3. Pass -DryRun to only audit, not make changes:   .\Harden-Windows.ps1 -DryRun -ConfigFile .\web01.ps1
  4. Review suggestions and then apply:    .\Harden-Windows.ps1 -ConfigFile .\web01.ps1
  Run only some:            .\Harden-Windows.ps1 -Only Users,Firewall
  Skip some:                .\Harden-Windows.ps1 -Skip Services,Registry

  Modules (run in this order):
    Tools, Backup, Recon, Users, PasswordPolicy, Firewall, Services, Registry, SMB,
    Audit, Shares, RoleSpecific, Custom

  Everything --> $Config.BackupDir. Backup + Recon establish what's
  already on this box before any changes, runs even with -DryRun

  !! Everything that commonly breaks scoring has a flag in config and is off by default
  !! Check your scoring requirements first if you have them (ik IRSEC doesn't probably)

  After processes run, review the output and any changes made to ensure everything is as expected.
  Double check all installed packages work via testing on virtual machines.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$InstallTools,
    [string[]]$Only = @(),
    [string[]]$Skip = @(),
    [string]$ConfigFile
)

$ErrorActionPreference = 'Continue'

$Config = [ordered]@{
    HostLabel            = ''             # ex. 'web01', computername
    Role                 = 'Workstation'  # DC | Web (IIS) | DNS | FTP | File | Mail | Workstation

    # Accounts --> case-insensitive, SamAccountName or local username only
    AuthorizedAdmins     = @('principal', 'sportingdir', 'chiefeng', 'strategist', 'scrutineer', 'techdirector', 'crewchief', 'firecrew')
    AuthorizedUsers      = @('pitcrew', 'mechanic', 'analyst', 'driver', 'tireman', 'jackcrew', 'garagecrew', 'celebrity', 'pitlaner', 'reserve', 'gunners')
    ProtectedAccounts    = @('whiteteam')
    RDPUsers             = @()            # allowed in "Remote Desktop Users" (empty = don't touch group)
    PasswordMode         = 'Prompt'       # Random = unique pw per account -> CSV | Prompt = one pw for all | None

    # Services / network 
    ScoredServices       = @()            # service short names like 'W3SVC','DNS','MSSQLSERVER.' look up short name and tailor to computer
    AllowedInboundTCP    = @()            # ex. 80,443  (ranges ok: '49152-65535')
    AllowedInboundUDP    = @()            # ex. 53
    UseRoleDefaultPorts  = $false         # also open typical ports for $Role
    AllowPing            = $false         # scoring often uses ICMP, but only on one workstation
    ScoringEngineIPs     = @()            # if set, scored ports are limited to these + TrustedIPs
    TrustedIPs           = @('192.168.15.1', '192.168.15.2', '10.15.1.1', '10.15.1.2', '10.15.1.3', '10.15.1.254', '172.20.1.15')            # your team, limits RDP/WinRM when set
    EnableRDP            = $false         # $true if RDP
    EnableWinRM          = $false         # $true if WinRM/PSRemoting
    ResetFirewallFirst   = $false         # wipe firewall to defaults before applying rules

    # Things that can break scoring
    DisableSpooler       = $true          # print spooler (PrintNightmare). Set $false on print servers
    RequireSMBSigning    = $true          # true breaks some old/Samba clients
    LmCompatibilityLevel = 4              # 5 = NTLMv2 only (strongest, may break legacy clients)
    DisableNetBIOS       = $false
    RequireLdapSigning   = $false         # DC only, true breaks simple/unsigned LDAP binds
    RemoveUnlistedShares = $false         # $true deletes non-default shares not in AllowedShares
    AllowedShares        = @()            # share names to keep

    ServicesToDisable    = @('TlntSvr','RemoteRegistry','SNMP','SSDPSRV','upnphost','WebClient',
                             'simptcp','lltdsvc','WMPNetworkSvc','icssvc','RasAuto','Browser')

    # Password policy
    PasswordMinLength    = 12
    LockoutThreshold     = 10             # 0 = off. Watch out for scoring-engine failed logins
    # Role specifics
    FtpSiteName          = ''             # IIS FTP site name, for Role = FTP

    BackupDir            = 'C:\backups'
}

<# EXAMPLE CONFIG FILE
# Save as web01.ps1 and run:  .\Harden-Windows.ps1 -ConfigFile .\web01.ps1 -DryRun

$Config.HostLabel         = 'web01'$Config.Role              = 'Web'
$Config.AuthorizedAdmins  = @('blueadmin')$Config.AuthorizedUsers   = @('alice','bob')
$Config.ProtectedAccounts = @('svc_scoring')$Config.ScoredServices    = @('W3SVC')
$Config.AllowedInboundTCP = @(80,443)$Config.TrustedIPs        = @('10.0.0.50')
$Config.EnableRDP         =$true
#>

if ($ConfigFile) { .$ConfigFile }   # per-host overrides, edits $Config directly

$null = New-Item -ItemType Directory -Force -Path$Config.BackupDir
$Stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'$LogFile = Join-Path $Config.BackupDir "harden_$Stamp.log"
$IsDC    = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)$PwRows  = @()
$SharedSecure =$null

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $colors = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; ERROR='Red'; DRY='Cyan' }$line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level,$Msg
    Write-Host $line -ForegroundColor $colors[$Level]
    Add-Content -Path $LogFile -Value$line
}

function Invoke-Step {
    param([string]$Desc, [scriptblock]$Action)
    if ($DryRun) { Write-Log$Desc 'DRY'; return }
    try   { & $Action; Write-Log$Desc 'OK' }
    catch { Write-Log "$Desc :: $($_.Exception.Message)" 'ERROR' }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    Invoke-Step "REG $Path -> $Name =$Value" {
        if (-not (Test-Path $Path)) { New-Item -Path$Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name$Name -Value $Value -Type$Type -Force
    }
}

function New-RandomPassword {
    param([int]$Length = 20)$sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#%^*-_=+')
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    function Get-Rand($max) {$b = New-Object byte[] 4; $rng.GetBytes($b); [int]([BitConverter]::ToUInt32($b, 0) % $max) }$all = $sets -join ''$chars = @()
    foreach ($s in $sets) {$chars += $s[(Get-Rand$s.Length)] }
    while ($chars.Count -lt $Length) {$chars += $all[(Get-Rand$all.Length)] }
    for ($i =$chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-Rand ($i + 1); $t =$chars[$i];$chars[$i] =$chars[$j];$chars[$j] =$t
    }
    -join $chars
}

if ($PSSenderInfo -and -not$Config.EnableWinRM) {
    Write-Log "Forcing EnableWinRM = $true so you don't lock yourself out silly" 'WARN'
    $Config.EnableWinRM =$true
}
if ($env:SESSIONNAME -like 'RDP-*' -and -not$Config.EnableRDP) {
    Write-Log "Forcing EnableRDP = $true so you don't lock yourself out silly" 'WARN'
    $Config.EnableRDP =$true
}

# Tools installation module
function Invoke-Tools {
    if (-not $InstallTools -and -not ($Only -contains 'Tools')) {
        return
    }

    Invoke-Step 'Install Winget dependencies' {
        Add-AppxPackage -Path "$env:TEMP\winget.msixbundle"
    }

    Invoke-Step 'Install Sysinternals Suite via winget' {
        winget install --id Microsoft.Sysinternals.SysinternalsSuite --silent --accept-package-agreements --accept-source-agreements
    }

    Invoke-Step 'Install Sysmon via winget and configure' {
        winget install --id Microsoft.Sysinternals.Sysinternals.Sysmon --silent --accept-package-agreements --accept-source-agreements
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
        if (-not $DryRun) {
            sysmon64.exe -accepteula -i "$env:TEMP\sysmonconfig.xml"
        }
    }

    Invoke-Step 'Download and setup Security Compliance Toolkit' {
        $SCTPath = "$env:SystemDrive\Tools\SecurityComplianceToolkit"
        New-Item -ItemType Directory -Force -Path $SCTPath | Out-Null
        Invoke-WebRequest -Uri "https://github.com/microsoft/SecurityComplianceToolkit/releases/latest/download/SecurityComplianceToolkit.zip" -OutFile "$SCTPath\SecurityComplianceToolkit.zip"
        Expand-Archive -Path "$SCTPath\SecurityComplianceToolkit.zip" -DestinationPath "$SCTPath\SecurityComplianceToolkit" -Force
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/microsoftarchive/New-KrbtgtKeys.ps1/master/New-KrbtgtKeys.ps1" -OutFile "$SCTPath\New-KrbtgtKeys.ps1"
        Unblock-File -Path "$SCTPath\New-KrbtgtKeys.ps1"
    }

    Invoke-Step 'Install BloodHound and SharpHound collectors' {
        winget install --id SpecterOps.BloodHound --silent --accept-package-agreements --accept-source-agreements
        $BloodHoundPath = "$env:SystemDrive\Tools\BloodHound"
        New-Item -ItemType Directory -Force -Path $BloodHoundPath | Out-Null
        Invoke-WebRequest -Uri "https://github.com/SpecterOps/Bloodhound/raw/main/Collectors/SharpHound.ps1" -OutFile "$BloodHoundPath\SharpHound.ps1"
        Unblock-File -Path "$BloodHoundPath\SharpHound.ps1"
        Invoke-WebRequest -Uri "https://github.com/SpecterOps/Bloodhound/raw/main/Collectors/SharpHound.exe" -OutFile "$BloodHoundPath\SharpHound.exe"
        Unblock-File -Path "$BloodHoundPath\SharpHound.exe"
    }
}

# Backup
function Invoke-Backup {
    $b = Join-Path $Config.BackupDir "backup_$Stamp"
    $null = New-Item -ItemType Directory -Force -Path$b
    netsh advfirewall export "$b\firewall.wfw" | Out-Null
    secedit /export /cfg "$b\secpol.cfg" /quiet
    auditpol /backup /file:"$b\audit.csv" | Out-Null
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv "$b\services.csv" -NoTypeInformation
    Get-SmbShare | Export-Csv "$b\shares.csv" -NoTypeInformation
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Export-Csv "$b\tasks.csv" -NoTypeInformation
    if (-not $IsDC) {
        Get-LocalUser | Export-Csv "$b\localusers.csv" -NoTypeInformation
        Get-LocalGroupMember -Group 'Administrators' | Export-Csv "$b\localadmins.csv" -NoTypeInformation
    }
    $keys = @{
        lsa      = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
        lanman   = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer'
        lanwks   = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation'
        ts       = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
        policies = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
    }
    foreach ($k in $keys.Keys) { reg export$keys[$k] "$b\$k.reg" /y | Out-Null }
    Write-Log "Backup saved to $b" 'OK'
    Write-Log "Firewall rollback: netsh advfirewall import `"$b\firewall.wfw`"" 'INFO' }  # report of suspicious stuff function Invoke-Recon { $out = Join-Path $Config.BackupDir "recon_$Stamp.txt" function Add-Section([string]$Title, [scriptblock]$Block) { Add-Content $out "`n===== $Title ====="
        try { & $Block \vert{} Out-String -Width 250 \vert{} Add-Content$out }
        catch { Add-Content $out "ERROR: $_" }
    }
    Add-Section 'Logged-on sessions' { quser 2>&1 }
    if (-not $IsDC) {
        Add-Section 'Local users' { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet }
        Add-Section 'Local Administrators' { Get-LocalGroupMember -Group 'Administrators' }
        Add-Section 'Remote Desktop Users' { Get-LocalGroupMember -Group 'Remote Desktop Users' }
    }
    Add-Section 'Listening TCP ports + process' {
        Get-NetTCPConnection -State Listen | Sort-Object LocalPort | Select-Object LocalAddress, LocalPort, OwningProcess,
            @{n='Process'; e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }}
    }
    Add-Section 'UDP endpoints' {
        Get-NetUDPEndpoint | Sort-Object LocalPort | Select-Object LocalAddress, LocalPort, OwningProcess,
            @{n='Process'; e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }}
    }
    Add-Section 'Established connections' {
        Get-NetTCPConnection -State Established | Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess,
            @{n='Process'; e={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name }}
    }
    Add-Section 'Processes with paths' { Get-Process | Select-Object Name, Id, Path | Sort-Object Name }
    Add-Section 'Non-Microsoft scheduled tasks' {
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            Select-Object TaskName, TaskPath, State,
            @{n='Actions'; e={ ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ' }}
    }
    Add-Section 'Services outside System32 / Program Files' {
        Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'system32|Program Files' } |
            Select-Object Name, State, StartMode, StartName, PathName
    }
    Add-Section 'Run / RunOnce keys' {
        Get-ItemProperty -ErrorAction SilentlyContinue -Path @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')
    }
    Add-Section 'Startup folders' {
        Get-ChildItem -Force -ErrorAction SilentlyContinue "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    Add-Section 'Winlogon Shell/Userinit' {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Shell, Userinit
    }
    Add-Section 'Image File Execution Options debuggers' {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
            ForEach-Object { $d = (Get-ItemProperty$_.PSPath -ErrorAction SilentlyContinue).Debugger
                             if ($d) { [pscustomobject]@{ Key = $_.PSChildName; Debugger =$d } } }
    }
    Add-Section 'Accessibility binaries replaced? (sticky keys backdoor)' {
        $h = @{ cmd = (Get-FileHash "$env:windir\System32\cmd.exe").Hash
                ps  = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe").Hash }
        'sethc','utilman','osk','narrator','magnify','displayswitch' | ForEach-Object {
            $f = "$env:windir\System32\$_.exe"
            if (Test-Path $f) { $x = (Get-FileHash$f).Hash
                [pscustomobject]@{ File = $f; SameAsCmd = ($x -eq$h.cmd); SameAsPowerShell = ($x -eq$h.ps) } }
        }
    }
    Add-Section 'WMI event subscriptions (persistence)' {
        Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    }
    Add-Section 'Hosts file (non-comment lines)' {
        Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and$_ -notmatch '^\s*#' }
    }
    Add-Section 'SMB shares' { Get-SmbShare | Select-Object Name, Path, Special, Description }
    Write-Log "Report written to $out - READ IT, then hunt anything odd por flavor" 'OK'
}

# Users
function Set-AccountPassword {
    param([string]$Name)
    $sec =$null
    switch ($Config.PasswordMode) {
        'None'   { return }
        'Prompt' { $sec =$SharedSecure }
        'Random' {
            $plain = New-RandomPassword
            $sec = ConvertTo-SecureString$plain -AsPlainText -Force
            if (-not $DryRun) { $script:PwRows += [pscustomobject]@{ Host =$env:COMPUTER