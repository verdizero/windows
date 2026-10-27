[CmdletBinding()]
param(
    [switch]$PurgeCurrentSession
)

$ErrorActionPreference = "Stop"

Write-Host "=== Kerberos Ticket Status ===" -ForegroundColor Cyan
Write-Host "User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "Computer: $env:COMPUTERNAME"
Write-Host ""

Write-Host "--- Current ticket cache ---"
& klist.exe
if ($LASTEXITCODE -ne 0) {
    throw "Unable to query the Kerberos ticket cache."
}

if (-not $PurgeCurrentSession) {
    Write-Host ""
    Write-Host "Inspection only; no tickets were purged." -ForegroundColor Green
    Write-Host "To explicitly purge this user's current-session cache, run:"
    Write-Host ".\Kerberos-Ticket-Refresh.ps1 -PurgeCurrentSession"
    return
}

Write-Host ""
Write-Warning "Purging tickets can interrupt access to network resources."
$confirmation = Read-Host "Type PURGE to clear tickets for this logon session"

if ($confirmation -cne "PURGE") {
    Write-Host "Cancelled; no tickets were changed."
    return
}

& klist.exe purge
if ($LASTEXITCODE -ne 0) {
    throw "Ticket purge failed."
}

Write-Host ""
Write-Host "--- Cache after purge ---"
& klist.exe

Write-Host ""
Write-Host "The Kerberos cache has been purged for the current logon session."
Write-Host "Fresh tickets are obtained as needed when accessing Kerberos-protected services."
Write-Host "This does not rotate passwords or invalidate all tickets across the domain."