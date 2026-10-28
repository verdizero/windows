function LetsAllCheckRegExist {
    param (
        [string]$Path
    )
    $root = $Path -replace '\\.+', '' 
    $subPath = $Path -replace '^[^\\]+\\', '' 

    if (-not (Test-Path $Path)) {
        try {
            New-Item -Path "$root" -Name "$subPath" -Force -ErrorAction Stop | Out-Null
            Write-Host "Created registry path: $Path" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to create registry path: $Path" -ForegroundColor Red
        }
    }
}

$registryPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    "HKCU:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch",
    "HKCU:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter",
    "HKLM:\SOFTWARE\Policies\Google\Chrome",
    "HKCU:\Software\Microsoft\Office\14.0\Word\Options",
    "HKCU:\Software\Microsoft\Office\14.0\Word\Options\WordMail",
    "HKCU:\Software\Microsoft\Office\15.0\Word\Options",
    "HKCU:\Software\Microsoft\Office\15.0\Word\Options\WordMail",
    "HKCU:\Software\Microsoft\Office\16.0\Word\Options",
    "HKCU:\Software\Microsoft\Office\16.0\Word\Options\WordMail",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
    "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule",
    "HKLM:\SYSTEM\CurrentControlSet\Control",
    "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint",
    "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
)

foreach ($path in $registryPaths) {
    LetsAllCheckRegExist -Path $path
}

$extensions = @('hta', 'wsh', 'wsf', 'js', 'jse', 'vbe', 'vbs', 'scr', 'htm')
$optionalExtensions = @('bat', 'ps1')

Write-Host "Do you want to change the file associations for .bat and .ps1 files to Notepad? (Y/N)" -ForegroundColor Yellow
$response = Read-Host "Please enter Y for Yes or N for No"

if ($response -eq 'Y') {
    $extensions += $optionalExtensions
}

foreach ($ext in $extensions) {
    $path = "HKCU:\Software\Classes\.$ext"
    if (Test-Path $path) {
        Set-ItemProperty -Path $path -Name "(Default)" -Value "Notepad"
        Write-Host "File association for .$ext changed to Notepad." -ForegroundColor Green
    } else {
        Write-Host "The registry path for .$ext does not exist. Attempting to create."
        New-Item -Path $path -Force | Out-Null
        Set-ItemProperty -Path $path -Name "(Default)" -Value "Notepad"
        Write-Host "File association for .$ext has been created and set to Notepad." -ForegroundColor Green
    }
}