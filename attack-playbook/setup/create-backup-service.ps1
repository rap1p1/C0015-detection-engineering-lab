# create-backup-service.ps1 - one-time lab weakness on WS01.
# Registers a legacy backup service that runs as C0015\Administrator. Windows stores the service
# password in LSA secrets, which is where the attacker finds it later. The service does not need to
# start successfully for the secret to exist.

param(
    [string]$ServiceName = 'C0015Backup',
    [string]$RunAs       = 'C0015\Administrator'
)

$ErrorActionPreference = 'Stop'
$cred = Get-Credential -UserName $RunAs -Message "Password for $RunAs (stored by the service manager)"
$pw   = $cred.GetNetworkCredential().Password

sc.exe create $ServiceName binPath= 'C:\Windows\System32\cmd.exe /c timeout /t 86400' `
    start= auto obj= $RunAs password= $pw | Out-Null
sc.exe qc $ServiceName
