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

if (-not $DryRun -and -not $InstallTools) {
    Write-Warning 'No execution switch specified. Use -DryRun to audit or -InstallTools to run the toolkit.'
    return
}

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

if ($ConfigFile) { . $ConfigFile }   # per-host overrides, edits $Config directly

$null = New-Item -ItemType Directory -Force -Path $Config.BackupDir
$Stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile = Join-Path $Config.BackupDir "harden_$Stamp.log"
$IsDC    = ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4)
$PwRows  = @()
$SharedSecure = $null

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $colors = @{ INFO='Gray'; OK='Green'; WARN='Yellow'; ERROR='Red'; DRY='Cyan' }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    Write-Host $line -ForegroundColor $colors[$Level]
    Add-Content -Path $LogFile -Value $line
}

function Invoke-Step {
    param([string]$Desc, [scriptblock]$Action)
    if ($DryRun) { Write-Log $Desc 'DRY'; return }
    try   { & $Action; Write-Log $Desc 'OK' }
    catch { Write-Log "$Desc :: $($_.Exception.Message)" 'ERROR' }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    Invoke-Step "REG $Path -> $Name = $Value" {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
    }
}

function New-RandomPassword {
    param([int]$Length = 20)
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#%^*-_=+')
    $rng  = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    function Get-Rand($max) { $b = New-Object byte[] 4; $rng.GetBytes($b); [int]([BitConverter]::ToUInt32($b, 0) % $max) }
    $all = $sets -join ''
    $chars = @()
    foreach ($s in $sets) { $chars += $s[(Get-Rand $s.Length)] }
    while ($chars.Count -lt $Length) { $chars += $all[(Get-Rand $all.Length)] }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-Rand ($i + 1); $t = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $t
    }
    -join $chars
}

if ($PSSenderInfo -and -not $Config.EnableWinRM) {
    Write-Log "Forcing EnableWinRM = $true so you don't lock yourself out silly" 'WARN'
    $Config.EnableWinRM = $true
}
if ($env:SESSIONNAME -like 'RDP-*' -and -not $Config.EnableRDP) {
    Write-Log "Forcing EnableRDP = $true so you don't lock yourself out silly" 'WARN'
    $Config.EnableRDP = $true
}

# Tools installation module
function Invoke-Tools {
    if (-not $InstallTools -and -not ($Only -contains 'Tools')) {
        return
    }

    function Get-WinGetCommand {
        $cmd = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $cmd) { $cmd = Get-Command winget -ErrorAction SilentlyContinue }
        if (-not $cmd) {
            throw "WinGet is not installed / is not available to this user... Install/update Microsoft's App Installer, then reopen PowerShell. No nonexistent TEMP\winget.msixbundle is assumed"
        }
        return $cmd.Source
    }

    function Invoke-CheckedNative {
        param([string]$FilePath, [string[]]$Arguments)
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "'$FilePath' failed with exit code $LASTEXITCODE"
        }
    }

    function Invoke-DownloadWithRetry {
        param(
            [Parameter(Mandatory)][string]$Uri,
            [Parameter(Mandatory)][string]$OutFile,
            [int]$Attempts = 3
        )
        $parent = Split-Path -Parent $OutFile
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        $lastError = $null
        for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
            try {
                if (Test-Path -LiteralPath $OutFile) {
                    Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
                }
                Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop
                if (-not (Test-Path -LiteralPath $OutFile) -or (Get-Item -LiteralPath $OutFile).Length -lt 100) {
                    throw "Download was empty or suspiciously small: $Uri"
                }
                return
            }
            catch {
                $lastError = $_
                if ($attempt -lt $Attempts) {
                    Start-Sleep -Seconds ([Math]::Min(2 * $attempt, 8))
                }
            }
        }
        throw "Download failed after $Attempts attempts: $Uri. $($lastError.Exception.Message)"
    }

    $wingetPath = $null
    Invoke-Step 'Check WinGet availability' {
        $wingetPath = Get-WinGetCommand
        Write-Log "Using WinGet at $wingetPath"
    }

    if (-not $wingetPath) {
        Write-Log 'Skipping package installs because WinGet is unavailable' 'WARN'
        return
    }

    Invoke-Step 'Install Sysinternals Suite via WinGet' {
        Invoke-CheckedNative -FilePath $wingetPath -Arguments @(
            'install', '--id', 'Microsoft.Sysinternals.SysinternalsSuite', '--exact',
            '--silent', '--accept-package-agreements', '--accept-source-agreements',
            '--disable-interactivity'
        )
    }

    Invoke-Step 'Install Sysmon and configure' {
        Invoke-CheckedNative -FilePath $wingetPath -Arguments @(
            'install', '--id', 'Microsoft.Sysinternals.Sysmon', '--exact',
            '--silent', '--accept-package-agreements', '--accept-source-agreements',
            '--disable-interactivity'
        )

        $sysmonPath = (Get-Command sysmon64.exe, sysmon.exe -ErrorAction SilentlyContinue |
            Select-Object -First 1).Source
        if (-not $sysmonPath) {
            $candidatePaths = @(
                "$env:ProgramFiles\SysinternalsSuite\Sysmon64.exe",
                "$env:ProgramFiles\SysinternalsSuite\Sysmon.exe",
                "$env:LOCALAPPDATA\Microsoft\WinGet\Links\Sysmon64.exe",
                "$env:LOCALAPPDATA\Microsoft\WinGet\Links\Sysmon.exe"
            )
            foreach ($candidate in $candidatePaths) {
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    $sysmonPath = $candidate
                    break
                }
            }
        }
        if (-not $sysmonPath) {
            # Some WinGet installs are placed in package-specific directories.
            $sysmonPath = (Get-ChildItem -Path "$env:ProgramFiles\WindowsApps" -Filter 'Sysmon64.exe' -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1).FullName
        }
        if (-not $sysmonPath) {
            throw 'Sysmon installation reported success, but Sysmon64.exe could not be located. Check WinGet output and installed package files.'
        }

        $configPath = Join-Path $env:TEMP 'sysmonconfig.xml'
        Invoke-DownloadWithRetry -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile $configPath
        $null = [xml](Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop)
        Invoke-CheckedNative -FilePath $sysmonPath -Arguments @('-accepteula', '-i', $configPath)
    }

    Invoke-Step 'Prepare Security Compliance Toolkit download' {
        $SCTPath = Join-Path $env:SystemDrive 'Tools\SecurityComplianceToolkit'
        New-Item -ItemType Directory -Force -Path $SCTPath | Out-Null
        # Microsoft Download Center presents a selectable list of baseline/tool ZIPs;
        # it does not provide a stable "latest toolkit ZIP" URL.
        $sctUrl = 'https://www.microsoft.com/en-us/download/details.aspx?id=55319'
        Set-Content -LiteralPath (Join-Path $SCTPath 'DOWNLOAD-INSTRUCTIONS.txt') -Value @(
            'Download the required baseline/tool ZIP from the official Microsoft Security Compliance Toolkit page:',
            $sctUrl,
            '',
            'Select the baseline or tool appropriate for this operating system, download it, and extract it into this folder.'
        ) -Encoding UTF8
        Write-Log "SCT download page: $sctUrl"
    }

    Invoke-Step 'Download SharpHound collector from official release' {
        $BloodHoundPath = Join-Path $env:SystemDrive 'Tools\BloodHound'
        New-Item -ItemType Directory -Force -Path $BloodHoundPath | Out-Null

        # Resolve a real release asset rather than requesting .exe/.ps1 files from a
        # repository's source tree, where those filenames are not guaranteed to exist.
        $releaseUri = 'https://api.github.com/repos/SpecterOps/SharpHound/releases/latest'
        $release = Invoke-RestMethod -Uri $releaseUri -Headers @{
            'User-Agent' = 'Windows-Hardening-Toolkit'
            'Accept' = 'application/vnd.github+json'
        } -TimeoutSec 60 -ErrorAction Stop
        $asset = $release.assets |
            Where-Object { $_.name -match '(?i)\.zip$' -and $_.name -match '(?i)SharpHound' } |
            Select-Object -First 1
        if (-not $asset) {
            throw "Latest SharpHound release '$($release.tag_name)' did not expose a matching ZIP asset. Review https://github.com/SpecterOps/SharpHound/releases."
        }

        $zipPath = Join-Path $BloodHoundPath $asset.name
        Invoke-DownloadWithRetry -Uri $asset.browser_download_url -OutFile $zipPath
        $extractPath = Join-Path $BloodHoundPath 'SharpHound'
        New-Item -ItemType Directory -Force -Path $extractPath | Out-Null
        Expand-Archive -LiteralPath $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop
        if (-not (Get-ChildItem -LiteralPath $extractPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^SharpHound(\.exe|\.ps1|\.dll)?$' } |
            Select-Object -First 1)) {
            throw "Downloaded release ZIP did not contain an expected SharpHound collector file. Inspect: $extractPath"
        }
        Get-ChildItem -LiteralPath $extractPath -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
        Write-Log "SharpHound collector extracted to $extractPath"
    }
}

# Backup
function Invoke-Backup {
    $b = Join-Path $Config.BackupDir "backup_$Stamp"
    $null = New-Item -ItemType Directory -Force -Path $b
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
    foreach ($k in $keys.Keys) { reg export $keys[$k] "$b\$k.reg" /y | Out-Null }
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
        $h = @{ cmd = (Get-FileHash "$env:windir\System32\cmd.exe").Hash
                ps  = (Get-FileHash "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe").Hash }
        'sethc','utilman','osk','narrator','magnify','displayswitch' | ForEach-Object {
            $f = "$env:windir\System32\$_.exe"
            if (Test-Path $f) { $x = (Get-FileHash $f).Hash
                [pscustomobject]@{ File = $f; SameAsCmd = ($x -eq $h.cmd); SameAsPowerShell = ($x -eq $h.ps) } }
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
            if (-not $DryRun) { $script:PwRows += [pscustomobject]@{ Host = $env:COMPUTERNAME; User = $Name; Password = $plain } }
        }
    }
    Invoke-Step "Reset password for $Name ($($Config.PasswordMode))" {
        if ($IsDC) { Set-ADAccountPassword -Identity $Name -Reset -NewPassword $sec }
        else       { Set-LocalUser -Name $Name -Password $sec }
    }
}

function Invoke-Users {
    $auth      = @($Config.AuthorizedAdmins + $Config.AuthorizedUsers) | Where-Object { $_ }
    $protected = @($Config.ProtectedAccounts + $env:USERNAME + 'krbtgt' + 'DefaultAccount' + 'WDAGUtilityAccount') | Where-Object { $_ }

    if ($auth.Count -eq 0) {
        Write-Log 'AuthorizedAdmins/AuthorizedUsers are empty - skipping Users module so we do not disable everyone.' 'WARN'
        return
    }
    if ($Config.PasswordMode -eq 'Prompt' -and -not $DryRun) {
        $script:SharedSecure = Read-Host 'New password for authorized accounts' -AsSecureString
    }

    if ($IsDC) {
        Import-Module ActiveDirectory
        $accounts = Get-ADUser -Filter * -Properties Enabled
    } else {
        $accounts = Get-LocalUser
    }

    foreach ($u in $accounts) {
        $n = if ($IsDC) { $u.SamAccountName } else { $u.Name }
        if ($protected -contains $n) { Write-Log "Skipping protected account $n"; continue }

        if ($n -eq 'Guest' -or $auth -notcontains $n) {
            if ($u.Enabled) {
                Invoke-Step "Disable unauthorized account $n" {
                    if ($IsDC) { Disable-ADAccount -Identity $n } else { Disable-LocalUser -Name $n }
                }
            }
            continue
        }
        if (-not $u.Enabled) {
            Invoke-Step "Enable authorized account $n" {
                if ($IsDC) { Enable-ADAccount -Identity $n } else { Enable-LocalUser -Name $n }
            }
        }
        Set-AccountPassword -Name $n
    }
    foreach ($a in $auth) {
        $exists = if ($IsDC) { Get-ADUser -Filter "SamAccountName -eq '$a'" } else { Get-LocalUser -Name $a -ErrorAction SilentlyContinue }
        if (-not $exists) { Write-Log "Authorized account '$a' does not exist on this host" 'WARN' }
    }

    # privileged group cleanup
    $keep = @($Config.AuthorizedAdmins + $protected + 'Administrator')
    if ($IsDC) {
        $groups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators',
                  'Server Operators','Backup Operators','DnsAdmins','Group Policy Creator Owners'
        foreach ($g in $groups) {
            Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue | Where-Object { $_.objectClass -eq 'user' } | ForEach-Object {
                if ($keep -notcontains $_.SamAccountName) {
                    $m = $_.SamAccountName
                    Invoke-Step "Remove $m from AD group $g" { Remove-ADGroupMember -Identity $g -Members $m -Confirm:$false }
                }
            }
        }
    } else {
        foreach ($m in (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)) {
            $short = ($m.Name -split '\\')[-1]
            if ($m.ObjectClass -eq 'Group') { Write-Log "Group in local Administrators left alone: $($m.Name) - review it" 'WARN'; continue }
            if ($keep -notcontains $short) {
                Invoke-Step "Remove $($m.Name) from local Administrators" { Remove-LocalGroupMember -Group 'Administrators' -Member $m.Name }
            }
        }
        if ($Config.RDPUsers.Count -gt 0) {
            foreach ($m in (Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue)) {
                $short = ($m.Name -split '\\')[-1]
                if ($Config.RDPUsers -notcontains $short -and $protected -notcontains $short) {
                    Invoke-Step "Remove $($m.Name) from Remote Desktop Users" { Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $m.Name }
                }
            }
        }
    }
}

# Password policy
function Invoke-PasswordPolicy {
    if ($IsDC) {
        Invoke-Step 'Domain password policy' {
            Import-Module ActiveDirectory
            Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
                -MinPasswordLength $Config.PasswordMinLength -ComplexityEnabled $true -PasswordHistoryCount 10 `
                -LockoutThreshold $Config.LockoutThreshold -LockoutDuration '00:30:00' -LockoutObservationWindow '00:30:00' `
                -ReversibleEncryptionEnabled $false
        }
    } else {
        Invoke-Step 'Local password / lockout policy' {
            net accounts /minpwlen:$($Config.PasswordMinLength) /uniquepw:10 /lockoutthreshold:$($Config.LockoutThreshold) /lockoutduration:30 /lockoutwindow:30 | Out-Null
            $cfg = Join-Path $Config.BackupDir 'secpol_apply.cfg'
            secedit /export /cfg $cfg /quiet
            (Get-Content $cfg) -replace 'PasswordComplexity\s*=\s*\d', 'PasswordComplexity = 1' `
                               -replace 'ClearTextPassword\s*=\s*\d',  'ClearTextPassword = 0' | Set-Content $cfg
            secedit /configure /db "$env:windir\security\local.sdb" /cfg $cfg /areas SECURITYPOLICY /quiet
        }
    }
}

# Firewall
function Invoke-Firewall {
    if ($Config.ResetFirewallFirst) { Invoke-Step 'Reset firewall to defaults' { netsh advfirewall reset | Out-Null } }

    Invoke-Step 'Enable firewall, default-deny inbound, logging' {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True -DefaultInboundAction Block `
            -DefaultOutboundAction Allow -LogBlocked True -LogAllowed False `
            -LogFileName '%systemroot%\system32\LogFiles\Firewall\pfirewall.log' -LogMaxSizeKilobytes 16384
    }
    Invoke-Step 'Remove previous BT-* rules (idempotent)' {
        Get-NetFirewallRule -Name 'BT-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }

    # typical ports per role. trim  if scored services don't need them
    $roleTCP = @{ DC = @(53,88,135,389,445,464,636,3268,3269,'49152-65535'); Web = @(80,443); DNS = @(53)
                  FTP = @(21,'49152-65535'); File = @(445); Mail = @(25,110,143,587,993,995); Workstation = @() }
    $roleUDP = @{ DC = @(53,88,123,389,464); DNS = @(53) }
    $tcp = @($Config.AllowedInboundTCP)
    $udp = @($Config.AllowedInboundUDP)
    if ($Config.UseRoleDefaultPorts) {
        if ($roleTCP.ContainsKey($Config.Role)) { $tcp += $roleTCP[$Config.Role] }
        if ($roleUDP.ContainsKey($Config.Role)) { $udp += $roleUDP[$Config.Role] }
    }
    $tcp = $tcp | Where-Object { $_ } | Select-Object -Unique
    $udp = $udp | Where-Object { $_ } | Select-Object -Unique

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
    Write-Log 'Review existing allow rules with: Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | ? Name -notlike "BT-*"' 'INFO'
}

# Services
function Invoke-Services {
    $disable = @($Config.ServicesToDisable)
    if ($Config.DisableSpooler) { $disable += 'Spooler' }
    foreach ($s in ($disable | Select-Object -Unique)) {
        if ($Config.ScoredServices -contains $s) { Write-Log "Not disabling $s (scored service)" 'WARN'; continue }
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

    if ($Config.DisableNetBIOS) {
        Invoke-Step 'Disable NetBIOS over TCP/IP on all adapters' {
            Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' |
                ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null }
        }
    }
    Invoke-Step 'Disable PowerShell v2 (downgrade attacks)' {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null
    }
}

# SMB
function Invoke-SMB {
    Invoke-Step 'Disable SMBv1 server' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
    Invoke-Step 'Ensure SMBv2/3 enabled' { Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force }
    Invoke-Step 'Remove SMB1 Windows feature' { Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null }
    Invoke-Step 'Disable SMB null-session share exposure' { Set-SmbServerConfiguration -RestrictNamedPipeAccessViaQuic $true -Force -ErrorAction SilentlyContinue }
    if ($Config.RequireSMBSigning) {
        Invoke-Step 'Require SMB signing (server)' { Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true -Force }
    }
}

# Auditing / logging
function Invoke-Audit {
    Invoke-Step 'Enable success+failure auditing, all categories' { auditpol /set /category:* /success:enable /failure:enable | Out-Null }
    foreach ($log in 'Security', 'System', 'Application') {
        Invoke-Step "Grow $log event log to 512MB" { wevtutil sl $log /ms:536870912 }
    }
    Invoke-Step 'Enable PowerShell operational log' { wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /e:true }
}

# Shares
function Invoke-Shares {
    $shares = Get-SmbShare | Where-Object { -not $_.Special -and $_.Name -notin 'NETLOGON', 'SYSVOL' -and $Config.AllowedShares -notcontains $_.Name }
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
    # Example:
    # Invoke-Step 'Restart scored service' { Restart-Service W3SVC }
}

# RUNNER
Write-Log "Host=$env:COMPUTERNAME Label=$($Config.HostLabel) Role=$($Config.Role) IsDC=$IsDC DryRun=$DryRun InstallTools=$InstallTools"
$order = 'Tools','Backup','Recon','Users','PasswordPolicy','Firewall','Services','Registry','SMB','Audit','Shares','RoleSpecific','Custom'
foreach ($m in $order) {
    if ($Only.Count -gt 0 -and $Only -notcontains $m) { continue }
    if ($Skip -contains $m) { continue }
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