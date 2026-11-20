# create-maintenance-task.ps1 - one-time lab weakness on WS01.
# Registers a maintenance task that runs as C0015\Administrator. Windows stores the password in LSA
# secrets, which is where the attacker finds it later.

param(
    [string]$TaskName = 'C0015Maintenance',
    [string]$RunAs    = 'C0015\Administrator'
)

$ErrorActionPreference = 'Stop'
$cred = Get-Credential -UserName $RunAs -Message "Password for $RunAs (stored by Task Scheduler)"
$pw   = $cred.GetNetworkCredential().Password

schtasks /create /tn $TaskName /tr "cmd.exe /c echo maintenance" /sc daily /st 02:00 `
    /ru $RunAs /rp $pw /rl HIGHEST /f
schtasks /query /tn $TaskName /fo list
