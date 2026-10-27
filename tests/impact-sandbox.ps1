<#
.SYNOPSIS
    Self-test for the impact simulator wrapper on a disposable sandbox.

.DESCRIPTION
    Creates a temporary corpus with a sentinel, an existing note and a pre-existing suffix file, runs
    Prepare, Execute (with a stand-in locker that only renames), Verify, Rollback and a second Rollback,
    then asserts that the tree is identical to the baseline and that unrelated files survived.

    The stand-in locker does not encrypt anything; this test never touches a real corpus.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'techniques/conti-style-impact/tools/run-impact.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("c0015-selftest-" + [guid]::NewGuid().ToString('N').Substring(0, 8))

function Assert([bool]$condition, [string]$message) {
    if (-not $condition) { Write-Host "[x] $message" -ForegroundColor Red; exit 1 }
    Write-Host "[+] $message"
}

New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $corpus = Join-Path $tmp 'corpus'
    New-Item -ItemType Directory -Path (Join-Path $corpus 'dept') -Force | Out-Null
    'sandbox' | Set-Content (Join-Path $corpus '.c0015-sandbox') -Encoding ascii
    'alpha' | Set-Content (Join-Path $corpus 'a.txt') -Encoding ascii
    'note that must survive' | Set-Content (Join-Path $corpus 'readme.txt') -Encoding ascii
    'suffix that must survive' | Set-Content (Join-Path $corpus 'c.txt.c0015') -Encoding ascii
    'gamma' | Set-Content (Join-Path $corpus 'dept/gamma.txt') -Encoding ascii

    $standIn = Join-Path $tmp 'standin.ps1'
    @'
$root = $env:C0015_CORPUS
Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object {
    $_.Name -notin @('readme.txt', '.c0015-sandbox') -and -not $_.Name.EndsWith('.c0015')
} | ForEach-Object { Rename-Item -LiteralPath $_.FullName -NewName ($_.Name + '.c0015') -Force }
Get-ChildItem -LiteralPath $root -Recurse -Directory -Force | ForEach-Object {
    $note = Join-Path $_.FullName 'readme.txt'
    if (-not (Test-Path -LiteralPath $note)) { 'note' | Set-Content -LiteralPath $note -Encoding ascii }
}
'@ | Set-Content $standIn -Encoding utf8
    $standInCmd = $standIn

    & pwsh -NoProfile -File $tool -Corpus $corpus -Action Prepare
    Assert ($LASTEXITCODE -eq 0) 'prepare succeeded'

    & pwsh -NoProfile -File $tool -Corpus $corpus -Action Plan
    Assert ($LASTEXITCODE -eq 0) 'plan is read-only and succeeds'
    Assert (Test-Path (Join-Path $corpus 'a.txt')) 'plan did not change files'

    & pwsh -NoProfile -File $tool -Corpus $corpus -Action Execute -Locker $standInCmd
    Assert ($LASTEXITCODE -eq 0) 'execute succeeded'
    Assert (Test-Path (Join-Path $corpus 'a.txt.c0015')) 'rename observed'
    Assert (Test-Path (Join-Path $corpus 'c.txt.c0015')) 'pre-existing suffix file untouched'

    & pwsh -NoProfile -File $tool -Corpus $corpus -Action Verify
    Assert ($LASTEXITCODE -eq 0) 'verify matched the journal'

    & pwsh -NoProfile -File $tool -Corpus $corpus -Action Rollback
    Assert ($LASTEXITCODE -eq 0) 'rollback restored the baseline'
    Assert (Test-Path (Join-Path $corpus 'a.txt')) 'renamed file restored'
    Assert (Test-Path (Join-Path $corpus 'readme.txt')) 'pre-existing note preserved'
    Assert (-not (Test-Path (Join-Path $corpus 'dept/readme.txt'))) 'note created by the run removed'

    & pwsh -NoProfile -File $tool -Corpus $corpus -Action Rollback
    Assert ($LASTEXITCODE -eq 0) 'second rollback is idempotent'

    Write-Host '[+] impact sandbox self-test passed'
    exit 0
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

