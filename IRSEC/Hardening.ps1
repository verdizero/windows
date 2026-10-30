<#
.SYNOPSIS
  oh em gosh bro :/ i wrote most of this myself but i had to learn powershell in two weeks so
  ofc i needed some help i'm crine i'm so stressed

.USAGE
  1. Fill in the config block below, OR leave it generic and make one small
     per-host file (see EXAMPLE CONFIG FILE at the bottom) and pass -ConfigFile
  2. Install Sysinternals, Sysmon, Everything:
     .\Hardening.ps1 -InstallTools
  3. Audit only (no hardening changes). Backup + Recon still run:
     .\Hardening.ps1 -DryRun -ConfigFile .\web01.ps1
  4. Review suggestions and then apply:
     .\Hardening.ps1 -ConfigFile .\web01.ps1
  Run only some:            .\Hardening.ps1 -Only Users,Firewall
  Skip some:                .\Hardening.ps1 -Skip Services,Registry

  Modules (run in this order):
    Tools, Backup, Recon, Users, PasswordPolicy, Firewall, Services, Registry, SMB,
    Audit, Shares, RoleSpecific, Custom

  Backup + Recon always run (even with -DryRun / -Only) unless you -Skip them.
  -InstallTools with no -Only runs ONLY the Tools module.
  Applying changes (no -DryRun) requires an elevated PowerShell session.

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

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-ConfigFilePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if (Test-Path -LiteralPath $Path) { return (Resolve-Path -LiteralPath $Path).Path }
    if ($PSScriptRoot) {
        $besideScript = Join-Path $PSScriptRoot $Path
        if (Test-Path -LiteralPath $besideScript) { return (Resolve-Path -LiteralPath $besideScript).Path }
    }
    throw "Config file not found: $Path"
}

$Config = [ordered]@{
    HostLabel            = ''             # ex. 'web01', computername
    Role                 = ''  # DC | Web (IIS) | DNS | FTP | File | Mail | Workstation

    # Accounts --> case-insensitive, SamAccountName or local username only
    AuthorizedAdmins     = @('principal', 'sportingdir', 'chiefeng', 'strategist', 'scrutineer', 'techdirector', 'crewchief', 'firecrew','whiteteam')
    AuthorizedUsers      = @('pitcrew', 'mechanic', 'analyst', 'driver', 'tireman', 'jackcrew', 'garagecrew', 'celebrity', 'pitlaner', 'reserve', 'gunners', 'whiteteam')
    ProtectedAccounts    = @('whiteteam', 'Administrator')
    RDPUsers             = @()            
    PasswordMode         = 'Prompt'       # Random = unique pw per account into csv, Prompt = one pw for all, None

    # Services / network
    ScoredServices       = @()            # service short names like 'W3SVC','DNS','MSSQLSERVER'. look up short name and tailor to computer
    AllowedInboundTCP    = @()            # ex. 80,443  (ranges ok: '49152-65535')
    AllowedInboundUDP    = @()            # ex. 53
    UseRoleDefaultPorts  = $true        
    AllowPing            = $false         # scoring often uses ICMP, but only on one workstation
    ScoringEngineIPs     = @()            # if set, scored ports are limited to these + TrustedIPs
    TrustedIPs           = @('10.15.1.254', '172.20.1.15', '10.15.1.1', '10.15.1.2', '10.15.1.3', '192.168.15.1', '192.168.15.2')
    EnableRDP            = $false         
    EnableWinRM          = $false         
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
# Save as web01.ps1 and run:  .\Hardening.ps1 -ConfigFile .\web01.ps1 -DryRun

$Config.HostLabel         = 'web01'
$Config.Role              = 'Web'
$Config.AuthorizedAdmins  = @('blueadmin')
$Config.AuthorizedUsers   = @('alice','bob')
$Config.ProtectedAccounts = @('svc_scoring')
$Config.ScoredServices    = @('W3SVC')
$Config.AllowedInboundTCP = @(80,443)
$Config.TrustedIPs        = @('10.0.0.50')
$Config.EnableRDP         = $true
#>

if ($ConfigFile) {
    $resolvedConfig = Resolve-ConfigFilePath -Path $ConfigFile
    . $resolvedConfig
}

$IsAdmin = Test-IsAdministrator
if (-not $DryRun -and -not $IsAdmin) {
    throw 'Reopen Powershell as Administrator!'
}

try {
    $null = New-Item -ItemType Directory -Force -Path $Config.BackupDir -ErrorAction Stop
} catch {
    $fallback = Join-Path $env:TEMP 'harden-backups'
    Write-Warning "Could not create $($Config.BackupDir) ($($_.Exception.Message)). Using $fallback"
    $Config.BackupDir = $fallback
    $null = New-Item -ItemType Directory -Force -Path $Config.BackupDir
}

$Stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = Join-Path $Config.BackupDir "harden_$Stamp.log"
$IsDC    = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)
$PwRows  = New-Object System.Collections.Generic.List[object]
$SharedSecure = $null
$script:ChocolateyExe = $null

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $colors = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; ERROR='Red'; DRY='Cyan' }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    $color = $colors[$Level]
    if ($color) { Write-Host $line -ForegroundColor $color } else { Write-Host $line }
    Add-Content -Path $LogFile -Value $line
}

function Invoke-Step {
    param(
        [string]$Desc,
        [scriptblock]$Action,
        [int[]]$SuccessExitCodes
    )
    if ($DryRun) { Write-Log $Desc 'DRY'; return }
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        & $Action
        if ($PSBoundParameters.ContainsKey('SuccessExitCodes')) {
            $code = Get-NativeExitCode
            if ($code -notin @($SuccessExitCodes)) {
                throw "Native command failed with exit code $code"
            }
        }
        Write-Log $Desc 'OK'
    } catch {
        Write-Log "$Desc :: $($_.Exception.Message)" 'ERROR'
    } finally {
        $ErrorActionPreference = $oldEap
    }
}

function Test-NameInList {
    param([string]$Name, [string[]]$List)
    if ([string]::IsNullOrWhiteSpace($Name) -or -not $List) { return $false }
    foreach ($item in $List) {
        if ($item -and ($Name -ieq $item)) { return $true }
    }
    return $false
}

function ConvertTo-UniquePortList {
    param($Ports)
    @($Ports) |
        Where-Object { $null -ne $_ -and "$_".Trim() -ne '' } |
        ForEach-Object { "$_".Trim() } |
        Select-Object -Unique
}

function Get-AccountSidString {
    param($Account)
    if ($null -eq $Account) { return $null }
    $sid = $null
    try { $sid = $Account.SID } catch { return $null }
    if ($null -eq $sid) { return $null }
    if ($sid -is [System.Security.Principal.SecurityIdentifier]) { return $sid.Value }
    try { return ([System.Security.Principal.SecurityIdentifier]$sid).Value } catch { return "$sid" }
}

function Test-IsProtectedAccount {
    param([string]$Name, $Account, [string[]]$ProtectedNames)
    if (Test-NameInList -Name $Name -List $ProtectedNames) { return $true }
    $sid = Get-AccountSidString -Account $Account
    # Built-in Administrator is RID 500 even if the account was renamed.
    if ($sid -and $sid -match '-500$') { return $true }
    return $false
}

function Get-LocalAccountEnabled {
    param([string]$Name)
    $u = Get-LocalUser -Name $Name -ErrorAction Stop
    return [bool]$u.Enabled
}

function Get-AdAccountEnabled {
    param([string]$Name)
    $u = Get-ADUser -Identity $Name -Properties Enabled -ErrorAction Stop
    return [bool]$u.Enabled
}

function Set-AccountEnabledState {
    param([string]$Name, [bool]$Enabled)
    if ($IsDC) {
        if ($Enabled) { Enable-ADAccount -Identity $Name -ErrorAction Stop }
        else { Disable-ADAccount -Identity $Name -ErrorAction Stop }
        $actual = Get-AdAccountEnabled -Name $Name
    } else {
        if ($Enabled) { Enable-LocalUser -Name $Name -ErrorAction Stop }
        else { Disable-LocalUser -Name $Name -ErrorAction Stop }
        $actual = Get-LocalAccountEnabled -Name $Name
    }
    if ($actual -ne $Enabled) {
        throw "$Name is still Enabled=$actual (wanted Enabled=$Enabled)"
    }
}

function Disable-OsFeature {
    param(
        [string[]]$OptionalFeatureNames = @(),
        [string[]]$ServerFeatureNames = @()
    )
    $changed = $false
    foreach ($name in $OptionalFeatureNames) {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue
        if ($feat -and $feat.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop | Out-Null
            $changed = $true
        }
    }
    $uninstall = Get-Command Uninstall-WindowsFeature -ErrorAction SilentlyContinue
    if (-not $uninstall) {
        try {
            Import-Module ServerManager -ErrorAction Stop
            $uninstall = Get-Command Uninstall-WindowsFeature -ErrorAction SilentlyContinue
        } catch {}
    }
    if ($uninstall) {
        foreach ($name in $ServerFeatureNames) {
            $feat = Get-WindowsFeature -Name $name -ErrorAction SilentlyContinue
            if ($feat -and $feat.Installed) {
                Uninstall-WindowsFeature -Name $name -ErrorAction Stop | Out-Null
                $changed = $true
            }
        }
    }
    if (-not $changed) {
        Write-Log "OS feature already off or not present on this SKU: $((@($OptionalFeatureNames) + @($ServerFeatureNames)) -join ', ')"
    }
}

function Set-SecpolIniValue {
    param([string[]]$Lines, [string]$Name, [string]$Value)
    $pattern = '^\s*{0}\s*=' -f [regex]::Escape($Name)
    $set = $false
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $Lines) {
        if ($line -match $pattern) {
            $out.Add("$Name = $Value") | Out-Null
            $set = $true
        } else {
            $out.Add($line) | Out-Null
        }
    }
    if ($set) { return @($out) }

    $inserted = $false
    $final = New-Object System.Collections.Generic.List[string]
    foreach ($line in $out) {
        $final.Add($line) | Out-Null
        if (-not $inserted -and $line -match '^\[System Access\]') {
            $final.Add("$Name = $Value") | Out-Null
            $inserted = $true
        }
    }
    if (-not $inserted) {
        $final.Add('[System Access]') | Out-Null
        $final.Add("$Name = $Value") | Out-Null
    }
    return @($final)
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    Invoke-Step "REG $Path -> $Name = $Value" {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    }
}

function New-RandomPassword {
    param([int]$Length = 20)
    if ($Length -lt 8) { $Length = 8 }
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#%^*-_=+')
    $all  = $sets -join ''
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf  = New-Object byte[] 4
    $pick = {
        param([int]$Max)
        $rng.GetBytes($buf)
        [int]([BitConverter]::ToUInt32($buf, 0) % [uint32]$Max)
    }
    try {
        $chars = New-Object System.Collections.Generic.List[char]
        foreach ($s in $sets) { $chars.Add($s[(& $pick $s.Length)]) }
        while ($chars.Count -lt $Length) { $chars.Add($all[(& $pick $all.Length)]) }
        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = & $pick ($i + 1)
            $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t
        }
        -join $chars
    } finally {
        $rng.Dispose()
    }
}

function Get-NativeExitCode {
    if ($null -ne $LASTEXITCODE) { return [int]$LASTEXITCODE }
    if ($?) { return 0 }
    return 1
}

if ($PSSenderInfo -and -not $Config.EnableWinRM) {
    Write-Log "Forcing EnableWinRM = true so you don't lock yourself out silly" 'WARN'
    $Config.EnableWinRM = $true
}
if ($env:SESSIONNAME -like 'RDP-*' -and -not $Config.EnableRDP) {
    Write-Log "Forcing EnableRDP = true so you don't lock yourself out silly" 'WARN'
    $Config.EnableRDP = $true
}

# Tools installation module
function Invoke-Tools {
    if (-not $InstallTools -and -not (Test-NameInList -Name 'Tools' -List $Only)) { return }

    if (-not $DryRun -and -not $IsAdmin) {
        throw 'Reopen Powershell as an Administrator to install tools!'
    }

    if (-not (Get-Command choco.exe -ErrorAction SilentlyContinue)) {
        Invoke-Step 'Install Chocolatey package manager' {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            } catch {}
            Set-ExecutionPolicy Bypass -Scope Process -Force
            $installScript = Join-Path $env:TEMP 'install-chocolatey.ps1'
            Invoke-WebRequest -Uri 'https://community.chocolatey.org/install.ps1' -OutFile $installScript -UseBasicParsing -ErrorAction Stop
            $proc = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $installScript
            ) -Wait -PassThru -WindowStyle Hidden
            Remove-Item -LiteralPath $installScript -Force -ErrorAction SilentlyContinue
            if ($proc.ExitCode -ne 0) { throw "Chocolatey bootstrap failed with exit code $($proc.ExitCode)" }
            $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                        [Environment]::GetEnvironmentVariable('Path', 'User')
            $chocoExe = Join-Path $env:ProgramData 'chocolatey\bin\choco.exe'
            if (Get-Command choco.exe -ErrorAction SilentlyContinue) {
                $script:ChocolateyExe = (Get-Command choco.exe).Source
            } elseif (Test-Path -LiteralPath $chocoExe) {
                $script:ChocolateyExe = $chocoExe
            } else {
                throw 'Chocolatey installation completed but choco.exe was not found!'
            }
        }
    }

    $chocoExe = if ($script:ChocolateyExe) { $script:ChocolateyExe } else {
        $cmd = Get-Command choco.exe -ErrorAction SilentlyContinue
        if ($cmd) { $cmd.Source } else { Join-Path $env:ProgramData 'chocolatey\bin\choco.exe' }
    }

    $packages = @(
        @{ Id = 'sysinternals';  Label = 'Microsoft Sysinternals Suite' },
        @{ Id = 'sysmon';        Label = 'Sysmon' },
        @{ Id = 'everything';    Label = 'Voidtools Everything' }
    )

    foreach ($pkg in $packages) {
        Invoke-Step "Install/update $($pkg.Label) via Chocolatey ($($pkg.Id))" {
            & $chocoExe upgrade $pkg.Id -y --no-progress
            $exitCode = Get-NativeExitCode
            if ($exitCode -notin @(0, 3010)) {
                throw "Chocolatey package '$($pkg.Id)' failed with exit code $exitCode."
            }
            if ($exitCode -eq 3010) { Write-Log "$($pkg.Label) installed; a reboot may be required." 'WARN' }
        }
    }

    Invoke-Step 'Prepare Security Compliance Toolkit download instructions' {
        $toolRoot = Join-Path $env:ProgramData 'BlueTeamTools'
        $sctPath = Join-Path $toolRoot 'SecurityComplianceToolkit'
        New-Item -ItemType Directory -Force -Path $sctPath -ErrorAction Stop | Out-Null
        $sctUrl = 'https://www.microsoft.com/en-us/download/details.aspx?id=55319'
        Set-Content -LiteralPath (Join-Path $sctPath 'DOWNLOAD-INSTRUCTIONS.txt') -Encoding UTF8 -Value @(
            'Security compliance toolkit download instructions',
            'Official Microsoft download center page:',
            $sctUrl,
            '',
            'Select and download the baseline matching this operating system, then extract it into this folder.',
            'No verified chocolatey package is configured for this toolkit.',
            'Sysmon is installed as a service only after you install a configuration XML (sysmon.exe -accepteula -i config.xml).'
        ) -ErrorAction Stop
        Write-Log "SCT instructions written to $sctPath"
    }

    Write-Log 'All done!' 'WARN'
}

# Backup
function Invoke-Backup {
    $b = Join-Path $Config.BackupDir "backup_$Stamp"
    $null = New-Item -ItemType Directory -Force -Path $b
    netsh advfirewall export "$b\firewall.wfw" | Out-Null
    if ((Get-NativeExitCode) -ne 0) { Write-Log 'Firewall export failed' 'WARN' }
    secedit /export /cfg "$b\secpol.cfg"
    if ((Get-NativeExitCode) -ne 0) { Write-Log 'secedit export failed' 'WARN' }
    auditpol /backup /file:"$b\audit.csv" | Out-Null
    if ((Get-NativeExitCode) -ne 0) { Write-Log 'auditpol backup failed' 'WARN' }
    Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv "$b\services.csv" -NoTypeInformation
    try { Get-SmbShare | Export-Csv "$b\shares.csv" -NoTypeInformation } catch { Write-Log "Share backup skipped: $($_.Exception.Message)" 'WARN' }
    Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Export-Csv "$b\tasks.csv" -NoTypeInformation
    if (-not $IsDC) {
        Get-LocalUser | Export-Csv "$b\localusers.csv" -NoTypeInformation
        try {
            Get-LocalGroupMember -Group 'Administrators' | Export-Csv "$b\localadmins.csv" -NoTypeInformation
        } catch {
            Write-Log "Local Administrators backup skipped: $($_.Exception.Message)" 'WARN'
        }
    }
    $keys = @{
        lsa      = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
        lanman   = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer'
        lanwks   = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation'
        ts       = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
        policies = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
    }
    foreach ($k in $keys.Keys) { reg.exe export $keys[$k] "$b\$k.reg" /y | Out-Null }
    Write-Log "Backup saved to $b" 'OK'
    Write-Log "Firewall rollback: netsh advfirewall import `"$b\firewall.wfw`"" 'INFO'
}

# report of suspicious stuff
function Invoke-Recon {
    $out = Join-Path $Config.BackupDir "recon_$Stamp.txt"
    function Add-Section([string]$Title, [scriptblock]$Block) {
        Add-Content $out "`n===== $Title ====="
        try { & $Block | Out-String -Width 250 | Add-Content $out }
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
        Get-CimInstance Win32_Service | Where-Object { $_.PathName -notmatch 'system32|Program Files|Windows Defender' } |
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
            ForEach-Object { $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
                             if ($d) { [pscustomobject]@{ Key = $_.PSChildName; Debugger = $d } } }
    }
    Add-Section 'Accessibility binaries replaced? (sticky keys backdoor)' {
        $h = @{
            cmd = (Get-FileHash "$env:windir\System32\cmd.exe" -ErrorAction Stop).Hash
            ps  = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -ErrorAction Stop).Hash
        }
        'sethc','utilman','osk','narrator','magnify','displayswitch' | ForEach-Object {
            $f = Join-Path $env:windir "System32\$_.exe"
            if (Test-Path -LiteralPath $f) {
                $x = (Get-FileHash -LiteralPath $f).Hash
                [pscustomobject]@{ File = $f; SameAsCmd = ($x -eq $h.cmd); SameAsPowerShell = ($x -eq $h.ps) }
            }
        }
    }
    Add-Section 'WMI event subscriptions (persistence)' {
        Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue
        Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    }
    Add-Section 'Hosts file (non-comment lines)' {
        Get-Content "$env:windir\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -and $_ -notmatch '^\s*#' }
    }
    Add-Section 'SMB shares' { Get-SmbShare | Select-Object Name, Path, Special, Description }
    Write-Log "Report written to $out - READ IT, then hunt anything odd por flavor" 'OK'
}

# Users
function Set-AccountPassword {
    param([string]$Name)
    $sec = $null
    switch ($Config.PasswordMode) {
        'None'   { return }
        'Prompt' { $sec = $SharedSecure }
        'Random' {
            $plain = New-RandomPassword
            $sec = ConvertTo-SecureString $plain -AsPlainText -Force
            if (-not $DryRun) { $PwRows.Add([pscustomobject]@{ Host = $env:COMPUTERNAME; User = $Name; Password = $plain }) }
        }
        default {
            Write-Log "Unknown PasswordMode '$($Config.PasswordMode)' + skipping password reset for $Name" 'WARN'
            return
        }
    }
    if (-not $sec) {
        Write-Log "No password material for $Name (Prompt value missing?) + skip reset" 'WARN'
        return
    }
    Invoke-Step "Reset password for $Name ($($Config.PasswordMode))" {
        if ($IsDC) { Set-ADAccountPassword -Identity $Name -Reset -NewPassword $sec -ErrorAction Stop }
        else       { Set-LocalUser -Name $Name -Password $sec -ErrorAction Stop }
    }
}

function Invoke-Users {
    $auth      = @($Config.AuthorizedAdmins + $Config.AuthorizedUsers) | Where-Object { $_ }
    $protected = @($Config.ProtectedAccounts + $env:USERNAME + 'krbtgt' + 'DefaultAccount' + 'WDAGUtilityAccount') | Where-Object { $_ }

    if ($auth.Count -eq 0) {
        Write-Log 'AuthorizedAdmins/AuthorizedUsers are empty, so skipping users module so we do not disable everyone' 'WARN'
        return
    }
    if ($Config.PasswordMode -eq 'Prompt' -and -not $DryRun) {
        $script:SharedSecure = Read-Host 'New password for authorized accounts' -AsSecureString
    }

    if ($IsDC) {
        Import-Module ActiveDirectory
        $accounts = Get-ADUser -Filter * -Properties Enabled, SamAccountName, SID
    } else {
        $accounts = Get-LocalUser
    }

    foreach ($u in $accounts) {
        $n = if ($IsDC) { $u.SamAccountName } else { $u.Name }
        if (Test-IsProtectedAccount -Name $n -Account $u -ProtectedNames $protected) {
            Write-Log "Skipping protected account $n"
            continue
        }

        if ($n -eq 'Guest' -or -not (Test-NameInList -Name $n -List $auth)) {
            if ($u.Enabled) {
                Invoke-Step "Disable unauthorized account $n" {
                    Set-AccountEnabledState -Name $n -Enabled $false
                }
            } else {
                Write-Log "Unauthorized account $n already disabled"
            }
            continue
        }
        if (-not $u.Enabled) {
            Invoke-Step "Enable authorized account $n" {
                Set-AccountEnabledState -Name $n -Enabled $true
            }
        }
        Set-AccountPassword -Name $n
    }
    foreach ($a in $auth) {
        $exists = if ($IsDC) {
            Get-ADUser -Identity $a -ErrorAction SilentlyContinue
        } else {
            Get-LocalUser -Name $a -ErrorAction SilentlyContinue
        }
        if (-not $exists) { Write-Log "Authorized account '$a' does not exist on this host" 'WARN' }
    }

    # privileged group cleanup
    $keep = @($Config.AuthorizedAdmins + $protected + 'Administrator')
    if ($IsDC) {
        $groups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators',
                  'Server Operators','Backup Operators','DnsAdmins','Group Policy Creator Owners'
        foreach ($g in $groups) {
            Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' } | ForEach-Object {
                if (-not (Test-IsProtectedAccount -Name $_.SamAccountName -Account $_ -ProtectedNames $keep)) {
                    $m = $_.SamAccountName
                    Invoke-Step "Remove $m from AD group $g" { Remove-ADGroupMember -Identity $g -Members $m -Confirm:$false }
                }
            }
        }
    } else {
        foreach ($m in (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)) {
            $short = ($m.Name -split '\\')[-1]
            if ($m.ObjectClass -eq 'Group') { Write-Log "Group in local Administrators left alone: $($m.Name) - review it" 'WARN'; continue }
            if (-not (Test-IsProtectedAccount -Name $short -Account $m -ProtectedNames $keep)) {
                Invoke-Step "Remove $($m.Name) from local Administrators" { Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name }
            }
        }
        if ($Config.RDPUsers.Count -gt 0) {
            foreach ($m in (Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue)) {
                $short = ($m.Name -split '\\')[-1]
                if (-not (Test-NameInList -Name $short -List $Config.RDPUsers) -and -not (Test-NameInList -Name $short -List $protected)) {
                    Invoke-Step "Remove $($m.Name) from Remote Desktop Users" { Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $m.Name }
                }
            }
        }
    }

    Write-Log 'Account Enabled status after Users module:'
    try {
        if ($IsDC) {
            Get-ADUser -Filter * -Properties Enabled, SamAccountName | Sort-Object SamAccountName | ForEach-Object {
                Write-Log ("  {0}  Enabled={1}" -f $_.SamAccountName, $_.Enabled)
            }
        } else {
            Get-LocalUser | Sort-Object Name | ForEach-Object {
                Write-Log ("  {0}  Enabled={1}" -f $_.Name, $_.Enabled)
            }
        }
    } catch {
        Write-Log "Could not enumerate accounts for verification: $($_.Exception.Message)" 'ERROR'
    }
}

# Password policy
function Invoke-PasswordPolicy {
    if ($IsDC) {
        Invoke-Step 'Domain password policy' {
            Import-Module ActiveDirectory
            Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
                -MinPasswordLength $Config.PasswordMinLength -ComplexityEnabled $true -PasswordHistoryCount 10 `
                -LockoutThreshold $Config.LockoutThreshold -LockoutDuration ([TimeSpan]::FromMinutes(30)) `
                -LockoutObservationWindow ([TimeSpan]::FromMinutes(30)) `
                -ReversibleEncryptionEnabled $false
        }
    } else {
        Invoke-Step 'Local password / lockout policy' {
            net accounts /minpwlen:$($Config.PasswordMinLength) /uniquepw:10 /lockoutthreshold:$($Config.LockoutThreshold) /lockoutduration:30 /lockoutwindow:30 | Out-Null
            $netCode = Get-NativeExitCode
            if ($netCode -ne 0) { throw "net accounts failed with exit code $netCode" }
            $cfg = Join-Path $Config.BackupDir 'secpol_apply.cfg'
            secedit /export /cfg $cfg
            $exportCode = Get-NativeExitCode
            if ($exportCode -ne 0) { throw "secedit /export failed with exit code $exportCode" }
            $secpol = Get-Content -LiteralPath $cfg
            $secpol = Set-SecpolIniValue -Lines $secpol -Name 'PasswordComplexity' -Value '1'
            $secpol = Set-SecpolIniValue -Lines $secpol -Name 'ClearTextPassword' -Value '0'
            Set-Content -LiteralPath $cfg -Value $secpol
            secedit /configure /db "$env:windir\security\local.sdb" /cfg $cfg /areas SECURITYPOLICY /quiet
            $cfgCode = Get-NativeExitCode
            if ($cfgCode -ne 0) { throw "secedit /configure failed with exit code $cfgCode" }
        }
    }
}

# Firewall
function Invoke-Firewall {
    if ($Config.ResetFirewallFirst) {
        Invoke-Step 'Reset firewall to defaults' -SuccessExitCodes 0 { netsh advfirewall reset | Out-Null }
    }

    Invoke-Step 'Enable firewall, default-deny inbound, logging' {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block `
            -DefaultOutboundAction Allow -LogBlocked True -LogAllowed False `
            -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384
    }
    Invoke-Step 'Remove previous BT-* rules (idempotent)' {
        Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'BT-*' } | Remove-NetFirewallRule
    }

    # typical ports per role. trim if scored services don't need them
    $roleTCP = @{ DC = @(53,88,135,389,445,464,636,3268,3269,'49152-65535'); Web = @(80,443); DNS = @(53)
                  FTP = @(21,'49152-65535'); File = @(445); Mail = @(25,110,143,587,993,995); Workstation = @() }
    $roleUDP = @{ DC = @(53,88,123,389,464); DNS = @(53) }
    $tcp = @($Config.AllowedInboundTCP)
    $udp = @($Config.AllowedInboundUDP)
    if ($Config.UseRoleDefaultPorts) {
        if ($roleTCP.ContainsKey($Config.Role)) { $tcp += $roleTCP[$Config.Role] }
        if ($roleUDP.ContainsKey($Config.Role)) { $udp += $roleUDP[$Config.Role] }
    }
    $tcp = ConvertTo-UniquePortList $tcp
    $udp = ConvertTo-UniquePortList $udp

    $scoredRemote = @($Config.ScoringEngineIPs + $Config.TrustedIPs) | Where-Object { $_ }
    if (-not $scoredRemote) { $scoredRemote = @('Any') }
    $mgmtRemote = @($Config.TrustedIPs) | Where-Object { $_ }
    if (-not $mgmtRemote) { $mgmtRemote = @('Any'); Write-Log 'TrustedIPs empty: RDP/WinRM (if enabled) open to ANY source' 'WARN' }

    foreach ($p in $tcp) {
        Invoke-Step "Allow inbound TCP $p" {
            New-NetFirewallRule -Name "BT-TCP-$p" -DisplayName "BT TCP $p" -Direction Inbound -Protocol TCP -LocalPort $p -RemoteAddress $scoredRemote -Action Allow -Profile Any | Out-Null }
    }
    foreach ($p in $udp) {
        Invoke-Step "Allow inbound UDP $p" {
            New-NetFirewallRule -Name "BT-UDP-$p" -DisplayName "BT UDP $p" -Direction Inbound -Protocol UDP -LocalPort $p -RemoteAddress $scoredRemote -Action Allow -Profile Any | Out-Null }
    }
    if ($Config.EnableRDP) {
        Invoke-Step 'Allow inbound RDP 3389' {
            New-NetFirewallRule -Name 'BT-RDP' -DisplayName 'BT RDP' -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $mgmtRemote -Action Allow -Profile Any | Out-Null }
    }
    if ($Config.EnableWinRM) {
        Invoke-Step 'Allow inbound WinRM 5985/5986' {
            New-NetFirewallRule -Name 'BT-WinRM' -DisplayName 'BT WinRM' -Direction Inbound -Protocol TCP -LocalPort 5985, 5986 -RemoteAddress $mgmtRemote -Action Allow -Profile Any | Out-Null }
    }
    if ($Config.AllowPing) {
        Invoke-Step 'Allow inbound ICMPv4 echo' {
            New-NetFirewallRule -Name 'BT-ICMP' -DisplayName 'BT ICMPv4 Echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any | Out-Null }
    }
    Write-Log 'Default inbound=Block does not disable built-in allow rules. Review with: Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object Name -notlike "BT-*"' 'INFO'
}

# Services
function Invoke-Services {
    $disable = @($Config.ServicesToDisable)
    if ($Config.DisableSpooler) { $disable += 'Spooler' }
    foreach ($s in ($disable | Select-Object -Unique)) {
        if (Test-NameInList -Name $s -List $Config.ScoredServices) { Write-Log "Not disabling $s (scored service)" 'WARN'; continue }
        if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
            Invoke-Step "Stop + disable service $s" {
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                Set-Service -Name $s -StartupType Disabled
            }
        }
    }
    # Keep scored services up: automatic start + restart on failure
    foreach ($s in $Config.ScoredServices) {
        if (-not (Get-Service -Name $s -ErrorAction SilentlyContinue)) { Write-Log "Scored service '$s' not found on this host" 'WARN'; continue }
        Invoke-Step "Scored service $s -> Automatic, running, auto-restart" {
            Set-Service -Name $s -StartupType Automatic
            sc.exe failure $s reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
            $scCode = Get-NativeExitCode
            if ($scCode -ne 0) { throw "sc.exe failure failed with exit code $scCode" }
            if ((Get-Service -Name $s).Status -ne 'Running') { Start-Service -Name $s }
        }
    }
}

# Registry / OS hardening
function Invoke-Registry {
    $lsa  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $sys  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $ts   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $lms  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $lmw  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $rdpDeny = $(if ($Config.EnableRDP) { 0 } else { 1 })

    $settings = @(
        @('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest', 'UseLogonCredential', 0),
        @($lsa, 'RunAsPPL', 1),                                   # LSA protection (needs reboot)
        @($lsa, 'NoLMHash', 1),
        @($lsa, 'LmCompatibilityLevel', [int]$Config.LmCompatibilityLevel),
        @($lsa, 'RestrictAnonymous', 1),
        @($lsa, 'RestrictAnonymousSAM', 1),
        @($lsa, 'EveryoneIncludesAnonymous', 0),
        @($lms, 'RestrictNullSessAccess', 1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast', 0),   # LLMNR off
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'NoDriveTypeAutoRun', 255),
        @($sys, 'EnableLUA', 1),
        @($sys, 'ConsentPromptBehaviorAdmin', 2),
        @($sys, 'LocalAccountTokenFilterPolicy', 0),
        @($sys, 'DontDisplayLastUserName', 1),
        @("$sys\Audit", 'ProcessCreationIncludeCmdLine_Enabled', 1),
        @($ts, 'fDenyTSConnections', $rdpDeny),
        @($ts, 'fAllowToGetHelp', 0),
        @("$ts\WinStations\RDP-Tcp", 'UserAuthentication', 1),                                # NLA
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging', 'EnableScriptBlockLogging', 1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging', 'EnableModuleLogging', 1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint', 'RestrictDriverInstallationToAdministrators', 1),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated', 0),
        @('HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer', 'AlwaysInstallElevated', 0),
        @('HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10', 'Start', 4)                      # SMB1 client driver off
    )
    if ($Config.RequireSMBSigning) {
        $settings += , @($lms, 'RequireSecuritySignature', 1)
        $settings += , @($lms, 'EnableSecuritySignature', 1)
        $settings += , @($lmw, 'RequireSecuritySignature', 1)
        $settings += , @($lmw, 'EnableSecuritySignature', 1)
    }
    if ($IsDC) {
        $settings += , @('HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters', 'FullSecureChannelProtection', 1)  # Zerologon
        if ($Config.RequireLdapSigning) {
            $settings += , @('HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'LDAPServerIntegrity', 2)
        }
    }
    foreach ($s in $settings) { Set-Reg -Path $s[0] -Name $s[1] -Value $s[2] }

    # Module logging does nothing unless ModuleNames is populated
    Set-Reg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -Name '*' -Value '*' -Type 'String'

    if ($Config.DisableNetBIOS) {
        Invoke-Step 'Disable NetBIOS over TCP/IP on all adapters' {
            Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' |
                ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null }
        }
    }
    Invoke-Step 'Disable PowerShell v2 (downgrade attacks)' {
        Disable-OsFeature -OptionalFeatureNames @('MicrosoftWindowsPowerShellV2Root', 'MicrosoftWindowsPowerShellV2') `
            -ServerFeatureNames @('PowerShell-V2')
    }
}

# SMB
function Invoke-SMB {
    Invoke-Step 'Disable SMBv1 server' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
    Invoke-Step 'Ensure SMBv2/3 enabled' { Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force }
    Invoke-Step 'Remove SMB1 Windows feature' {
        Disable-OsFeature -OptionalFeatureNames @('SMB1Protocol') -ServerFeatureNames @('FS-SMB1')
    }
    Invoke-Step 'Clear SMB null-session pipes/shares' {
        Set-SmbServerConfiguration -NullSessionPipes @() -NullSessionShares @() -Force
    }
    if ($Config.RequireSMBSigning) {
        Invoke-Step 'Require SMB signing (server)' { Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force }
    }
}

# Auditing / logging
function Invoke-Audit {
    # Quote /category:* so PowerShell does not expand * to filenames in the current directory
    Invoke-Step 'Enable success+failure auditing, all categories' -SuccessExitCodes 0 {
        auditpol.exe /set '/category:*' /success:enable /failure:enable | Out-Null
    }
    foreach ($log in 'Security', 'System', 'Application') {
        Invoke-Step "Grow $log event log to 512MB" -SuccessExitCodes 0 { wevtutil sl $log /ms:536870912 }
    }
    Invoke-Step 'Enable PowerShell operational log' -SuccessExitCodes 0 {
        wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /e:true
    }
}

# Shares
function Invoke-Shares {
    try { $allShares = Get-SmbShare } catch { Write-Log "Get-SmbShare failed: $($_.Exception.Message)" 'ERROR'; return }
    $shares = $allShares | Where-Object { -not $_.Special -and $_.Name -notin 'NETLOGON', 'SYSVOL' -and -not (Test-NameInList -Name $_.Name -List $Config.AllowedShares) }
    foreach ($s in $shares) {
        if ($Config.RemoveUnlistedShares) { Invoke-Step "Remove share $($s.Name) ($($s.Path))" { Remove-SmbShare -Name $s.Name -Force } }
        else { Write-Log "Unlisted share: $($s.Name) -> $($s.Path)  (add to AllowedShares or set RemoveUnlistedShares)" 'WARN' }
    }
}

# Role-specific
function Invoke-RoleSpecific {
    switch ($Config.Role) {
        'DC' {
            Write-Log 'DC: reset krbtgt password TWICE (10+ hrs apart) if you suspect golden tickets' 'WARN'
            Write-Log 'DC: review GPOs, Domain Admins history, and SYSVOL scripts manually' 'WARN'
        }
        'Web' {
            if (Get-Module -ListAvailable WebAdministration) {
                Import-Module WebAdministration
                Invoke-Step 'IIS: disable directory browsing' { Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -Name enabled -Value $false -PSPath 'IIS:\' }
                Write-Log 'IIS: review webroot ACLs, app pool identities, and any unknown .aspx/.php/web.config' 'WARN'
            }
        }
        'DNS' {
            if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
                Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object {
                    $z = $_.ZoneName
                    Invoke-Step "DNS: block zone transfers for $z" { Set-DnsServerPrimaryZone -Name $z -SecureSecondaries NoTransfer }
                }
                Write-Log 'DNS: compare zone records against your known-good list; consider disabling recursion if not scored' 'WARN'
            }
        }
        'FTP' {
            if ($Config.FtpSiteName -and (Get-Module -ListAvailable WebAdministration)) {
                Import-Module WebAdministration
                Invoke-Step "FTP: disable anonymous auth on $($Config.FtpSiteName)" {
                    Set-ItemProperty "IIS:\Sites\$($Config.FtpSiteName)" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false }
            }
        }
        'File' { Write-Log 'File server: review share + NTFS permissions on every scored share' 'WARN' }
        'Mail' { Write-Log 'Mail: verify relay restrictions and disable open relay in your MTA config' 'WARN' }
    }
}

# paste host-specific one-offs here
function Invoke-Custom {
    # Invoke-Step 'Restart scored service' { Restart-Service W3SVC }
}

function Test-ShouldRunModule {
    param([string]$Name, [switch]$Always)
    if (Test-NameInList -Name $Name -List $Skip) { return $false }
    if ($Always) { return $true }
    if ($Only.Count -gt 0) { return (Test-NameInList -Name $Name -List $Only) }
    return $true
}

# RUNNER
Write-Log "Host=$env:COMPUTERNAME Label=$($Config.HostLabel) Role=$($Config.Role) IsDC=$IsDC DryRun=$DryRun InstallTools=$InstallTools Admin=$IsAdmin"
$order = 'Tools','Backup','Recon','Users','PasswordPolicy','Firewall','Services','Registry','SMB','Audit','Shares','RoleSpecific','Custom'
$toolsOnly = $InstallTools -and $Only.Count -eq 0
foreach ($m in $order) {
    if ($toolsOnly -and $m -ne 'Tools') { continue }
    $always = ($m -eq 'Backup' -or $m -eq 'Recon') -and -not $toolsOnly
    if (-not (Test-ShouldRunModule -Name $m -Always:$always)) { continue }
    Write-Log "=== Module: $m ===" 'INFO'
    & "Invoke-$m"
}

if ($PwRows.Count -gt 0) {
    $pwFile = Join-Path $Config.BackupDir "passwords_$($env:COMPUTERNAME)_$Stamp.csv"
    $PwRows | Export-Csv $pwFile -NoTypeInformation
    icacls $pwFile /inheritance:r /grant:r '*S-1-5-32-544:F' | Out-Null
    Write-Log "New passwords saved to $pwFile - copy to your password manager / white team, then DELETE it." 'WARN'
}
Write-Log "Done. Log: $LogFile. Reboot when convenient (LSA protection, SMB1 removal need it)." 'OK'
