<#
.SYNOPSIS
    Collect the winlogon session's command output into a single record file.
#>
param(
    [string]$InputFile = (Join-Path $PSScriptRoot 'discovery-output.txt'),
    [string]$OutFile   = (Join-Path $PSScriptRoot 'discovery-record.txt')
)
if (-not (Test-Path -LiteralPath $InputFile)) { throw "missing $InputFile" }
@(
    "collected_utc: $([DateTime]::UtcNow.ToString('o'))",
    "source: $InputFile",
    ''
) + (Get-Content -LiteralPath $InputFile) | Set-Content -LiteralPath $OutFile -Encoding UTF8
Write-Host "wrote $OutFile"
