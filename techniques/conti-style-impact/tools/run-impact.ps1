<#
.SYNOPSIS
    Render locker.bat for the target list, run it from the backup server, verify, restore.
.DESCRIPTION
    The batch file keeps the campaign argument set. The simulator renames files and writes the note;
    restore removes the suffix and the note, then compares hashes against the pre-run manifest.
.EXAMPLE
    .\run-impact.ps1 -Targets FS01,WS01 -Corpus C:\C0015\corpus -Action Run
#>
param(
    [string]$Targets = 'FS01,WS01',
    [string]$Corpus  = 'C:\C0015\corpus',
    [string]$Locker  = 'C:\o4IRWsH4N1a3hjO9Sy2rPP02oyUddH7zA5xGih0ESmlhiiXD9kpWVCPfOwUnayZp_locker.exe',
    [ValidateSet('Prepare','Run','Verify','Rollback')][string]$Action = 'Prepare'
)

$root   = Split-Path -Parent $PSScriptRoot
$tpl    = Join-Path $root 'payload\locker.bat.tpl'
$bat    = Join-Path $env:TEMP 'locker.bat'
$backup = Join-Path $Corpus '_backup'

function Get-Manifest {
    Get-ChildItem -LiteralPath $Corpus -Recurse -File -Force |
        Where-Object { $_.FullName -notlike "$backup*" -and $_.Name -ne 'readme.txt' } |
        ForEach-Object {
            [pscustomobject]@{
                relative = $_.FullName.Substring($Corpus.Length).TrimStart('\')
                sha256   = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
                size     = $_.Length
            }
        }
}

switch ($Action) {
    'Prepare' {
        if (-not (Test-Path -LiteralPath $Corpus)) { throw "corpus missing: $Corpus" }
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Recurse -Force }
        New-Item -ItemType Directory -Path $backup | Out-Null
        Copy-Item -LiteralPath $Corpus -Destination $backup -Recurse -Force
        Get-Manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $backup 'manifest.json')
        Write-Host "[+] corpus backed up to $backup"
    }
    'Run' {
        if (-not (Test-Path -LiteralPath $Locker)) { throw "locker missing: $Locker" }
        $content = (Get-Content -LiteralPath $tpl -Raw).
            Replace('@@LOCKER_NAME@@', (Split-Path -Leaf $Locker)).
            Replace('@@TARGETS@@', $Targets)
        Set-Content -LiteralPath $bat -Value $content -Encoding ASCII
        Write-Host "[*] $bat"
        Get-Content -LiteralPath $bat | ForEach-Object { Write-Host "    $_" }
        & cmd.exe /c $bat
        Write-Host "[+] batch exited $LASTEXITCODE"
    }
    'Verify' {
        $notes = Get-ChildItem -LiteralPath $Corpus -Recurse -File -Filter 'readme.txt' -Force
        $locks = Get-ChildItem -LiteralPath $Corpus -Recurse -File -Filter '*.c0015' -Force
        Write-Host "[+] $($notes.Count) notes, $($locks.Count) renamed files"
    }
    'Rollback' {
        Get-ChildItem -LiteralPath $Corpus -Recurse -File -Filter '*.c0015' -Force | ForEach-Object {
            Rename-Item -LiteralPath $_.FullName -NewName ($_.Name -replace '\.c0015$','') -Force
        }
        Get-ChildItem -LiteralPath $Corpus -Recurse -File -Filter 'readme.txt' -Force |
            Remove-Item -Force
        Copy-Item -Path (Join-Path $backup '*') -Destination $Corpus -Recurse -Force
        $manifest = Get-Content -LiteralPath (Join-Path $backup 'manifest.json') -Raw | ConvertFrom-Json
        $current  = Get-Manifest
        $diff = Compare-Object ($manifest | ForEach-Object { "$($_.relative)|$($_.sha256)" }) `
                               ($current  | ForEach-Object { "$($_.relative)|$($_.sha256)" })
        if ($diff) { Write-Warning 'hash mismatch after rollback'; $diff | Format-Table } else { Write-Host '[+] rollback verified, hashes match' }
    }
}
