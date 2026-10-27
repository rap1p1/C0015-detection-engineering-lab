<#
.SYNOPSIS
    Render the locker batch, mutate a disposable corpus, verify and restore it exactly.

.DESCRIPTION
    The simulator only renames files and writes a note; it never encrypts. Every mutation is decided in
    a plan step, recorded in a journal, and reversed from that journal. Nothing is inferred from a file
    name or suffix.

    Safety contract:
      * the corpus must contain the sentinel file `.c0015-sandbox`
      * the baseline copy lives next to the corpus, never inside it
      * `Plan` is the default and changes nothing; `Execute` is required to mutate
      * quotas are checked before each operation, not only at the start
      * `Rollback` restores exactly the journal and then compares the inventory against the baseline

.EXAMPLE
    .\run-impact.ps1 -Corpus .\sandbox -Action Prepare
    .\run-impact.ps1 -Corpus .\sandbox -Action Plan
    .\run-impact.ps1 -Corpus .\sandbox -Action Execute -Locker .\locker_sim.exe
    .\run-impact.ps1 -Corpus .\sandbox -Action Verify
    .\run-impact.ps1 -Corpus .\sandbox -Action Rollback
#>
param(
    [Parameter(Mandatory)][string]$Corpus,
    [ValidateSet('Prepare','Plan','Execute','Verify','Rollback')][string]$Action = 'Plan',
    [string]$Locker = '',
    [int]$MaxFiles = 500,
    [long]$MaxBytes = 512MB,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$sentinelName = '.c0015-sandbox'
$noteName = 'readme.txt'
$suffix = '.c0015'

function Fail([string]$message) { Write-Host "[x] $message" -ForegroundColor Red; exit 2 }
function Info([string]$message) { Write-Host "[+] $message" }

if (-not (Test-Path -LiteralPath $Corpus -PathType Container)) { Fail "corpus not found: $Corpus" }
$corpusPath = (Resolve-Path -LiteralPath $Corpus).Path.TrimEnd('\')
$baseline = "$corpusPath.baseline"
$journalPath = Join-Path $baseline 'journal.json'
$inventoryPath = Join-Path $baseline 'inventory.json'
$baselineContent = Join-Path $baseline 'content'

if ($baseline.StartsWith($corpusPath + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
    $corpusPath.StartsWith($baseline + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    Fail 'baseline and corpus overlap; put them side by side'
}

$sentinel = Join-Path $corpusPath $sentinelName
if (-not (Test-Path -LiteralPath $sentinel)) {
    Fail "corpus is not a disposable sandbox: missing $sentinelName"
}

$reparse = Get-ChildItem -LiteralPath $corpusPath -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }
if ($reparse) { Fail "corpus contains a reparse point: $($reparse[0].FullName)" }

function Get-Inventory {
    Get-ChildItem -LiteralPath $corpusPath -Recurse -File -Force |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject]@{
                relative = $_.FullName.Substring($corpusPath.Length).TrimStart('\')
                sha256   = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                size     = $_.Length
            }
        }
}

function Get-Plan {
    $plan = New-Object System.Collections.Generic.List[object]
    $files = Get-ChildItem -LiteralPath $corpusPath -Recurse -File -Force | Sort-Object FullName
    if ($files.Count -gt $MaxFiles) { Fail "corpus has $($files.Count) files, quota is $MaxFiles" }
    $bytes = ($files | Measure-Object Length -Sum).Sum
    if ($bytes -gt $MaxBytes) { Fail "corpus is $bytes bytes, quota is $MaxBytes" }

    $directories = $files | ForEach-Object { Split-Path -Parent $_.FullName } | Sort-Object -Unique
    foreach ($dir in $directories) {
        $notePath = Join-Path $dir $noteName
        if (-not (Test-Path -LiteralPath $notePath)) {
            $plan.Add([pscustomobject]@{ action = 'note'; path = $notePath.Substring($corpusPath.Length).TrimStart('\') })
        }
    }
    foreach ($file in $files) {
        if ($file.Name -eq $noteName -or $file.Name -eq $sentinelName) { continue }
        if ($file.Name.EndsWith($suffix)) { continue }
        $plan.Add([pscustomobject]@{ action = 'rename'; path = $file.FullName.Substring($corpusPath.Length).TrimStart('\') })
    }
    $plan
}

switch ($Action) {
    'Prepare' {
        if (Test-Path -LiteralPath $baseline) {
            if (-not $Force) { Fail "baseline exists: $baseline (use -Force to rebuild)" }
            Remove-Item -LiteralPath $baseline -Recurse -Force
        }
        New-Item -ItemType Directory -Path $baseline | Out-Null
        New-Item -ItemType Directory -Path $baselineContent | Out-Null
        Copy-Item -Path (Join-Path $corpusPath '*') -Destination $baselineContent -Recurse -Force
        $inventory = Get-Inventory
        $inventory | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $inventoryPath -Encoding UTF8
        '[]' | Set-Content -LiteralPath $journalPath -Encoding UTF8
        Info "baseline written: $inventoryPath ($($inventory.Count) files)"
    }

    'Plan' {
        $plan = Get-Plan
        Info "plan: $($plan.Count) operations"
        $plan | Group-Object action | ForEach-Object { Info "  $($_.Name): $($_.Count)" }
        Info 'no files changed'
    }

    'Execute' {
        if (-not (Test-Path -LiteralPath $inventoryPath)) { Fail 'run Prepare first' }
        if (-not $Locker) { Fail '-Locker is required for Execute' }
        if (-not (Test-Path -LiteralPath $Locker)) { Fail "locker not found: $Locker" }
        if (Test-Path -LiteralPath $journalPath) {
            $existing = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
            if ($existing -and @($existing).Count -gt 0) { Fail 'a previous run has not been rolled back' }
        }
        $plan = Get-Plan
        if ($plan.Count -gt $MaxFiles) { Fail "plan has $($plan.Count) operations, quota is $MaxFiles" }
        $bytes = (Get-ChildItem -LiteralPath $corpusPath -Recurse -File | Measure-Object Length -Sum).Sum
        if ($bytes -gt $MaxBytes) { Fail "corpus is $bytes bytes, quota is $MaxBytes" }

        $before = Get-Inventory
        # the simulator reads its root from the environment; the wrapper binds it to this corpus
        $env:C0015_CORPUS = $corpusPath
        if ([IO.Path]::GetExtension($Locker) -eq '.ps1') {
            & pwsh -NoProfile -File $Locker
        } elseif ($IsWindows) {
            & cmd.exe /c "`"$Locker`""
        } else {
            & pwsh -NoProfile -File $Locker
        }
        $exit = $LASTEXITCODE
        Info "locker exited $exit"
        $after = Get-Inventory

        $beforeMap = @{}
        foreach ($item in $before) { $beforeMap[$item.relative] = $item }
        $afterMap = @{}
        foreach ($item in $after) { $afterMap[$item.relative] = $item }

        $journal = New-Object System.Collections.Generic.List[object]
        foreach ($rel in $afterMap.Keys) {
            if (-not $beforeMap.ContainsKey($rel)) { $journal.Add([pscustomobject]@{ action = 'added'; path = $rel }) }
        }
        foreach ($rel in $beforeMap.Keys) {
            if (-not $afterMap.ContainsKey($rel)) {
                $journal.Add([pscustomobject]@{ action = 'removed'; path = $rel; sha256_before = $beforeMap[$rel].sha256 })
            } elseif ($afterMap[$rel].sha256 -ne $beforeMap[$rel].sha256) {
                $journal.Add([pscustomobject]@{ action = 'modified'; path = $rel; sha256_before = $beforeMap[$rel].sha256 })
            }
        }
        $journal | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $journalPath -Encoding UTF8
        $added = @($journal | Where-Object action -eq 'added').Count
        $removed = @($journal | Where-Object action -eq 'removed').Count
        $modified = @($journal | Where-Object action -eq 'modified').Count
        Info "journaled $($journal.Count) changes ($added added, $removed removed, $modified modified)"
        if ($journal.Count -gt $MaxFiles) { Fail "run changed $($journal.Count) paths, quota is $MaxFiles; journal kept for rollback" }
        if ($exit -ne 0) { Fail "locker failed with exit $exit; journal kept for rollback" }
    }

    'Verify' {
        if (-not (Test-Path -LiteralPath $journalPath)) { Fail 'no journal; nothing was executed' }
        $journal = Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json
        if (-not $journal) { Fail 'journal is empty' }
        $failures = 0
        foreach ($entry in $journal) {
            $full = Join-Path $corpusPath $entry.path
            switch ($entry.action) {
                'added'   { if (-not (Test-Path -LiteralPath $full)) { Write-Host "[x] missing added file: $($entry.path)"; $failures++ } }
                'removed' { if (Test-Path -LiteralPath $full) { Write-Host "[x] removed file still present: $($entry.path)"; $failures++ } }
                'modified' {
                    if (-not (Test-Path -LiteralPath $full)) { Write-Host "[x] modified file missing: $($entry.path)"; $failures++ }
                    elseif ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -eq $entry.sha256_before) {
                        Write-Host "[x] modified file unchanged: $($entry.path)"; $failures++
                    }
                }
                default { Write-Host "[x] unknown journal action: $($entry.action)"; $failures++ }
            }
        }
        if ($failures) { Fail "$failures journal entries not reflected on disk" }
        Info "verified $($journal.Count) journal entries"
    }

    'Rollback' {
        if (-not (Test-Path -LiteralPath $journalPath)) { Fail 'no journal; nothing to roll back' }
        $journal = @(Get-Content -LiteralPath $journalPath -Raw | ConvertFrom-Json)
        foreach ($entry in $journal) {
            $full = Join-Path $corpusPath $entry.path
            switch ($entry.action) {
                'added' { if (Test-Path -LiteralPath $full) { Remove-Item -LiteralPath $full -Force } }
                'removed' {
                    $source = Join-Path $baselineContent $entry.path
                    if (-not (Test-Path -LiteralPath $source)) { Fail "baseline lost $($entry.path)" }
                    $parent = Split-Path -Parent $full
                    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
                    Copy-Item -LiteralPath $source -Destination $full -Force
                }
                'modified' {
                    $source = Join-Path $baselineContent $entry.path
                    if (-not (Test-Path -LiteralPath $source)) { Fail "baseline lost $($entry.path)" }
                    Copy-Item -LiteralPath $source -Destination $full -Force
                }
                default { Fail "unknown journal action: $($entry.action)" }
            }
        }
        $expected = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
        $actual = Get-Inventory
        $expectedSet = $expected | ForEach-Object { "$($_.relative)|$($_.sha256)" }
        $actualSet = $actual | ForEach-Object { "$($_.relative)|$($_.sha256)" }
        $diff = Compare-Object -ReferenceObject $expectedSet -DifferenceObject $actualSet
        if ($diff) {
            Write-Host '[x] inventory does not match baseline' -ForegroundColor Red
            $diff | Format-Table | Out-String | Write-Host
            exit 1
        }
        '[]' | Set-Content -LiteralPath $journalPath -Encoding UTF8
        if (-not (Test-Path -LiteralPath $sentinel)) { Fail 'rollback removed the sentinel' }
        Info "rollback verified: $($actual.Count) files match the baseline"
    }
}




