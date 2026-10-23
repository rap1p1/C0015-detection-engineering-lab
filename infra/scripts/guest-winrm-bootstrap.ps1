<#
.SYNOPSIS
    Runs inside a guest. Enables WinRM for workgroup remoting and re-asserts it at boot.
.DESCRIPTION
    Copies of this script are pushed into the guest once. It configures the service, the listener,
    the firewall rule for every network profile, and a startup task that runs the script again after
    a reboot, so the channel survives restarts without another guest operation.

    Writes C:\c0015-winrm-status.txt with the result of each step.
.PARAMETER Quiet
    Suppress console output (used by the scheduled task).
#>
[CmdletBinding()]
param([switch]$Quiet)

$log   = 'C:\c0015-winrm-status.txt'
$lines = New-Object System.Collections.Generic.List[string]

function Say {
    param([string]$Message)
    $lines.Add(("{0} {1}" -f (Get-Date).ToUniversalTime().ToString('o'), $Message))
    if (-not $Quiet) { Write-Host $Message }
}

try {
    Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
    if ((Get-Service WinRM).Status -ne 'Running') { Start-Service WinRM }
    Say 'service=running starttype=automatic'
} catch {
    Say "service-error: $($_.Exception.Message)"
}

try {
    Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop | Out-Null
    Say 'psremoting=enabled'
} catch {
    Say "psremoting-error: $($_.Exception.Message)"
}

try {
    $http = Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue |
        Where-Object { $_.Keys -contains 'Transport=HTTP' }
    if (-not $http) {
        New-Item -Path WSMan:\localhost\Listener -Transport HTTP -Address * -Force | Out-Null
        Say 'listener=created'
    } else {
        Say 'listener=present'
    }
} catch {
    Say "listener-error: $($_.Exception.Message)"
}

try {
    if (-not (Get-NetFirewallRule -DisplayName 'C0015 WinRM HTTP' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName 'C0015 WinRM HTTP' -Direction Inbound -Protocol TCP `
            -LocalPort 5985 -Action Allow -Profile Any | Out-Null
        Say 'firewall=created'
    } else {
        Say 'firewall=present'
    }
} catch {
    Say "firewall-error: $($_.Exception.Message)"
}

try {
    $self = $MyInvocation.MyCommand.Path
    $tr   = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$self`" -Quiet"
    & schtasks.exe /create /tn 'C0015-WinRM' /tr $tr /sc onstart /ru SYSTEM /f | Out-Null
    Say "task=created path=$self"
} catch {
    Say "task-error: $($_.Exception.Message)"
}

try {
    $ip = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -like '192.168.50.*' } |
        Select-Object -ExpandProperty IPAddress) -join ','
    Say ("host={0} domain={1} ip={2}" -f $env:COMPUTERNAME, $env:USERDOMAIN, $ip)
} catch {
    Say "info-error: $($_.Exception.Message)"
}

$lines | Set-Content -LiteralPath $log -Encoding UTF8
if (-not $Quiet) { Get-Content -LiteralPath $log }
