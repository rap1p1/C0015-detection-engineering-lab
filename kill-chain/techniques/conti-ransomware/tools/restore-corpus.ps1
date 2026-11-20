<#
.SYNOPSIS
    Reverse the simulator on a corpus: remove the notes and the .c0015 suffix.
.DESCRIPTION
    The simulator only renames files and writes readme.txt; this restores both. It refuses to run unless
    the sentinel file is present, so it cannot be pointed at a real directory by mistake.
.EXAMPLE
    ./restore-corpus.ps1 -Corpus C:\C0015\corpus
#>
param([Parameter(Mandatory)][string]$Corpus)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path (Join-Path $Corpus '.c0015-sandbox'))) { throw "not a sandbox corpus: $Corpus" }

Get-ChildItem $Corpus -Recurse -File -Filter readme.txt -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem $Corpus -Recurse -File -Filter *.c0015 -ErrorAction SilentlyContinue |
    ForEach-Object { Rename-Item $_.FullName ($_.Name -replace '\.c0015$', '') -Force }

"restored: " + (Get-ChildItem $Corpus -Recurse -File).Count + " files"
