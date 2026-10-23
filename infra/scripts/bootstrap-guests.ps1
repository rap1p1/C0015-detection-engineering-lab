<#
.SYNOPSIS
    Push the WinRM bootstrap into each guest with vmrun, then verify the listener.
.DESCRIPTION
    vmrun is used only for this one-time push. After the bootstrap runs, each guest re-asserts WinRM
    at boot through a startup task, so subsequent operations use PowerShell remoting and do not
    depend on vmrun remaining healthy.

    Requires: VMware Workstation on the host, VMware Tools in the guests, local administrator
    credentials for the guest.
.PARAMETER Credential
    Guest local administrator credential (C0015\administrator).
.PARAMETER Names
    Guests to bootstrap. Defaults to the three lab hosts.
.PARAMETER Vmx
    Optional hashtable mapping guest name to vmx path. Defaults to the standard lab layout.
.EXAMPLE
    $c = Get-Credential C0015\administrator
    .\bootstrap-guests.ps1 -Credential $c
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][pscredential]$Credential,
    [string[]]$Names = @('DC01','FS01','WS01'),
    [string]$GuestDir = 'C:\',
    [string]$VmRoot   = 'E:\VM\C0015',
    [hashtable]$Vmx
)

$ErrorActionPreference = 'Stop'
$vmrun = @(
    'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
    'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vmrun) { throw 'vmrun.exe not found' }

if (-not $Vmx) {
    $Vmx = @{
        DC01 = Join-Path $VmRoot 'DC01\DC01 - C0015.vmx'
        FS01 = Join-Path $VmRoot 'FS01\FS01.vmx'
        WS01 = Join-Path $VmRoot 'WS01\WS01 - C0015.vmx'
    }
}

$user = $Credential.UserName
$pass = $Credential.GetNetworkCredential().Password
$source = Join-Path $PSScriptRoot 'guest-winrm-bootstrap.ps1'
if (-not (Test-Path $source)) { throw "missing $source" }

function Invoke-Vmrun {
    param([string[]]$Arguments)
    & $vmrun -T ws @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "vmrun failed ($code): $($Arguments -join ' ')" }
}

foreach ($name in $Names) {
    $vmxPath = $Vmx[$name]
    if (-not $vmxPath -or -not (Test-Path $vmxPath)) {
        Write-Warning "[$name] vmx not found: $vmxPath"
        continue
    }
    Write-Host "[$name] bootstrapping"


    $guestScript = "$GuestDir\guest-winrm-bootstrap.ps1"
    Invoke-Vmrun @('-gu', $user, '-gp', $pass, 'copyFileFromHostToGuest', $vmxPath,
                   $source, $guestScript) | Out-Null

    Invoke-Vmrun @('-gu', $user, '-gp', $pass, 'runProgramInGuest', $vmxPath,
                   'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                   '-NoProfile', '-ExecutionPolicy', 'Bypass',
                   '-File', $guestScript) | Out-Null

    $statusLocal = Join-Path $env:TEMP "$name-winrm-status.txt"
    try {
        Invoke-Vmrun @('-gu', $user, '-gp', $pass, 'copyFileFromGuestToHost', $vmxPath,
                       'C:\c0015-winrm-status.txt', $statusLocal) | Out-Null
        Write-Host "[$name] status:"
        Get-Content $statusLocal | ForEach-Object { Write-Host "    $_" }
        Remove-Item $statusLocal -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "[$name] status copy failed: $($_.Exception.Message)"
    }
}

Write-Host ''
Write-Host 'Listener check'
foreach ($name in $Names) {
    $ok = Test-NetConnection -ComputerName $name -Port 5985 -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Host ("  {0,-5} 5985 {1}" -f $name, $(if ($ok) { 'open' } else { 'closed' }))
}

