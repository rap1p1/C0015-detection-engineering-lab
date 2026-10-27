<#
.SYNOPSIS
    Run the reference scenario end to end and verify every stage against observed state.

.DESCRIPTION
    Linear operator script: clear alerts, reset the lab, open the sessions the scenario needs, open the
    document, wait for the payload to finish, assert the artefacts, then capture evidence from
    Elasticsearch. Each stage records a failure; the script exits non-zero and prints what failed.

.EXAMPLE
    ./tools/run/reference-run.ps1 -RunId run-2026-10-27
#>
param(
    [string]$RunId = ("run-" + (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')),
    [string]$Corpus = 'C:\C0015\corpus',
    [int]$TimeoutMinutes = 20,
    [switch]$KeepAlerts
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cred = Import-Clixml (Join-Path $repo 'stage/lab-credentials-adm.xml')
$kaliKey = Join-Path $env:USERPROFILE '.ssh\c0015_kali'
if (-not $env:ES_URL) { throw 'ES_URL is not set' }
$esUrl = $env:ES_URL
if (-not $env:ES_PASS) { throw 'ES_PASS is not set' }
$victimPw = $env:C0015_VICTIM_PW
$helpdeskPw = $env:C0015_HELPDESK_PW
if (-not $victimPw -or -not $helpdeskPw) { throw 'C0015_VICTIM_PW and C0015_HELPDESK_PW must be set' }
$evidence = Join-Path $repo "evidence/runs/$RunId"
$failed = New-Object System.Collections.Generic.List[string]
$current = ''

function Stage([string]$name) { $script:current = $name; Write-Host "`n=== $name ===" -ForegroundColor Cyan }
function Ok([string]$detail) { Write-Host "  ok: $detail" -ForegroundColor Green }
function Bad([string]$detail) { Write-Host "  FAIL: $detail" -ForegroundColor Red; $script:failed.Add("$($script:current): $detail") }
function Kali([string]$command) { ssh -i $kaliKey -o BatchMode=yes kali@192.168.50.100 $command }

Write-Host "run id: $RunId"

Stage 'preflight'
$staging = Invoke-Command -ComputerName WS01 -Credential $cred -ScriptBlock {
    try { (Invoke-WebRequest 'http://192.168.50.100/updater.exe' -Method Head -TimeoutSec 8 -UseBasicParsing).StatusCode } catch { 0 }
}
if ($staging -eq 200) { Ok 'staging reachable from the victim' } else { Bad "staging returned $staging" }
$health = & curl.exe -s -k -u "elastic:$($env:ES_PASS)" "$esUrl/_cluster/health"
if ($health -match '"status"\s*:\s*"(green|yellow)"') { Ok 'Elasticsearch reachable' } else { Bad 'Elasticsearch not reachable' }

Stage 'clear alerts'
if (-not $KeepAlerts) {
    $body = @{ query = @{ bool = @{ filter = @(@{ range = @{ '@timestamp' = @{ gte = 'now-6h' } } });
                                  should = @(@{ prefix = @{ 'kibana.alert.rule.rule_id' = 'c0015-' } });
                                  minimum_should_match = 1 } } } | ConvertTo-Json -Depth 8
    $response = & curl.exe -s -k -u "elastic:$($env:ES_PASS)" -X POST "$esUrl/.internal.alerts-security.alerts-default*/_delete_by_query?conflicts=proceed&refresh=true" -H 'Content-Type: application/json' -d $body
    $curlExit = $LASTEXITCODE
    $parsed = $response | ConvertFrom-Json
    $failures = if ($parsed.failures) { @($parsed.failures).Count } else { 0 }
    if ($curlExit -ne 0) { Bad "alert cleanup request failed with exit $curlExit" }
    elseif ($parsed.error) { Bad "alert cleanup failed: $($parsed.error.type)" }
    elseif ($parsed.timed_out) { Bad 'alert cleanup timed out' }
    elseif ($failures -gt 0) { Bad "alert cleanup had $failures failures" }
    elseif ($parsed.version_conflicts) { Bad "alert cleanup had $($parsed.version_conflicts) version conflicts" }
    else { Ok "removed $($parsed.deleted) C0015 alerts from the last six hours" }
}

Stage 'reset target'
$corpusCount = Invoke-Command -ComputerName FS01 -Credential $cred -ArgumentList $Corpus -ScriptBlock {
    param($Corpus)
    Get-ChildItem $Corpus -Recurse -File -Filter *.c0015 -ErrorAction SilentlyContinue | ForEach-Object { Rename-Item $_.FullName ($_.Name -replace '\.c0015$','') -Force }
    Get-ChildItem $Corpus -Recurse -File -Filter readme.txt -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-Process rundll32,powershell -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item 'C:\ProgramData\dump.txt','C:\ProgramData\inj.dll','C:\ProgramData\143.dll','C:\ProgramData\mk.exe','C:\ProgramData\locker.exe','C:\locker.bat','C:\readme.txt','C:\Users\Public\C0015' -Recurse -Force -ErrorAction SilentlyContinue
    foreach ($t in (schtasks /query /fo csv 2>$null | ConvertFrom-Csv | Where-Object { $_.TaskName -match 'C0015' }).TaskName) { schtasks /delete /tn $t /f 2>$null | Out-Null }
    (Get-ChildItem $Corpus -Recurse -File).Count
}
if ($corpusCount -ge 40) { Ok "corpus restored ($corpusCount files)" } else { Bad "corpus has $corpusCount files" }

Stage 'reset beachhead'
Invoke-Command -ComputerName WS01 -Credential $cred -ScriptBlock {
    Get-Process WINWORD,mshta,regsvr32,rundll32,rclone,powershell -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    foreach ($t in (schtasks /query /fo csv 2>$null | ConvertFrom-Csv | Where-Object { $_.TaskName -match 'C0015' }).TaskName) { schtasks /delete /tn $t /f 2>$null | Out-Null }
    Remove-Item 'C:\ProgramData\C0015' -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force 'C:\ProgramData\C0015' | Out-Null
    icacls 'C:\ProgramData\C0015' /grant 'Users:(OI)(CI)M' /T /Q 2>&1 | Out-Null
    Copy-Item 'C:\Windows\System32\whoami.exe' 'C:\ProgramData\C0015\updater.exe' -Force
    schtasks /create /tn C0015Updater /tr "C:\ProgramData\C0015\updater.exe" /sc minute /mo 1 /ru SYSTEM /rl HIGHEST /f 2>&1 | Out-Null
}
Ok 'beachhead reset'

Stage 'sessions'
Invoke-Command -ComputerName FS01 -Credential $cred -ScriptBlock { & cmd.exe /c 'logoff 1' 2>$null; Start-Sleep -Seconds 3 } | Out-Null
Invoke-Command -ComputerName WS01 -Credential $cred -ScriptBlock { & cmd.exe /c 'logoff 1' 2>$null; Start-Sleep -Seconds 3 } | Out-Null
Kali "pkill -x xfreerdp 2>/dev/null; echo '$helpdeskPw' | kinit helpdesk@C0015.LAB >/dev/null 2>&1; (nohup xvfb-run -a xfreerdp /v:192.168.50.30 /u:'helpdesk' /d:C0015.LAB /p:'$helpdeskPw' /cert:ignore /sec:nla /size:1024x768 /timeout:30000 >/tmp/run-helpdesk.log 2>&1 &) ; sleep 20" | Out-Null
$targetState = Invoke-Command -ComputerName FS01 -Credential $cred -ScriptBlock {
    [pscustomobject]@{
        Session = [bool](quser 2>&1 | Select-String 'helpdesk')
        Unistack = (Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" | Where-Object { $_.CommandLine -match 'Unistack' } | Measure-Object).Count
    }
}
if ($targetState.Session -and $targetState.Unistack -ge 1) { Ok 'target session and per-user host present' } else { Bad "target session=$($targetState.Session) unistack=$($targetState.Unistack)" }

Kali "echo '$victimPw' | kinit duc.user@C0015.LAB >/dev/null 2>&1; (nohup xvfb-run -a xfreerdp /v:192.168.50.20 /u:'duc.user' /d:C0015.LAB /p:'$victimPw' /cert:ignore /sec:nla /size:1024x768 /timeout:30000 >/tmp/run-victim.log 2>&1 &) ; sleep 20" | Out-Null
$victimSession = Invoke-Command -ComputerName WS01 -Credential $cred -ScriptBlock { [bool](quser 2>&1 | Select-String 'duc.user') }
if ($victimSession) { Ok 'victim session present' } else { Bad 'victim session missing' }

if ($failed.Count -gt 0) {
    Write-Host "`npreconditions failed; not starting the document" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  - $_" }
    exit 1
}

$start = (Get-Date).ToUniversalTime()
Stage 'open document'
$wordStarted = Invoke-Command -ComputerName WS01 -Credential $cred -ArgumentList $victimPw -ScriptBlock {
    param($pw)
    schtasks /delete /tn C0015Word /f 2>$null | Out-Null
    schtasks /create /tn C0015Word /tr "C:\opendoc.cmd" /sc once /st 23:59 /ru "C0015\duc.user" /rp $pw /rl HIGHEST /it /f | Out-Null
    schtasks /run /tn C0015Word | Out-Null
    Start-Sleep -Seconds 15
    [bool](Get-Process WINWORD -ErrorAction SilentlyContinue)
}
if ($wordStarted) { Ok 'Word started' } else { Bad 'Word did not start' }

Stage 'payload'
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
do {
    Start-Sleep -Seconds 15
    $log = Invoke-Command -ComputerName WS01 -Credential $cred -ScriptBlock { Get-Content 'C:\ProgramData\C0015\stage2.log' -ErrorAction SilentlyContinue }
} until (($log -match '=== stage2 end ===') -or ((Get-Date) -gt $deadline))
if ($log -match '=== stage2 end ===') { Ok 'stage2 finished' } else { Bad 'stage2 did not finish in time' }
if ($log -match 'skipped injection') { Bad 'injection step was skipped' }
Set-Content (Join-Path $env:TEMP "stage2-$RunId.log") ($log -join "`n")

Stage 'artefacts'
$state = Invoke-Command -ComputerName FS01 -Credential $cred -ArgumentList $Corpus -ScriptBlock {
    param($Corpus)
    [pscustomobject]@{
        Dump = (Get-Item 'C:\ProgramData\dump.txt' -ErrorAction SilentlyContinue).Length
        Notes = (Get-ChildItem $Corpus -Recurse -File -Filter readme.txt -ErrorAction SilentlyContinue).Count
        Renamed = (Get-ChildItem $Corpus -Recurse -File -Filter *.c0015 -ErrorAction SilentlyContinue).Count
        Persist = [bool](schtasks /query /tn C0015Persist 2>$null)
        Inject = (Get-Content 'C:\Users\Public\C0015\inject.log' -ErrorAction SilentlyContinue | Select-Object -Last 1)
    }
}
if ($state.Dump -ge 1000) { Ok "dump $($state.Dump) bytes" } else { Bad "dump missing ($($state.Dump))" }
if ($state.Notes -ge 5) { Ok "notes $($state.Notes)" } else { Bad "notes $($state.Notes)" }
if ($state.Renamed -ge 40) { Ok "renamed $($state.Renamed)" } else { Bad "renamed $($state.Renamed)" }
if ($state.Persist) { Ok 'persistence task present' } else { Bad 'persistence task missing' }
if ($state.Inject -match 'injector done') { Ok 'injector ran' } else { Bad 'injector did not run' }

$end = (Get-Date).ToUniversalTime()
Stage 'evidence'
$env:ES_PASS = 'REDACTED'
$env:ES_URL = 'https://100.77.46.126:9200'
python (Join-Path $repo 'tools/evidence/capture_run.py') --run-id $RunId --start $start.ToString('yyyy-MM-ddTHH:mm:ssZ') --end $end.ToString('yyyy-MM-ddTHH:mm:ssZ') --out $evidence | Out-Host

Stage 'summary'
if ($failed.Count -eq 0) {
    Write-Host "RUN PASSED  $($start.ToString('yyyy-MM-ddTHH:mm:ssZ')) .. $($end.ToString('yyyy-MM-ddTHH:mm:ssZ'))" -ForegroundColor Green
    exit 0
}
$failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
Write-Host 'RUN FAILED' -ForegroundColor Red
exit 1
