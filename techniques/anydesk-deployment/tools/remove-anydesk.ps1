<#
.SYNOPSIS
    Remove the portable client and its per-user configuration after the run.
#>
param([string]$UserProfile = $env:USERPROFILE)

Get-Process -Name 'AnyDesk' -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -LiteralPath (Join-Path $UserProfile 'Videos\AnyDesk.exe') -Force -ErrorAction SilentlyContinue
foreach ($p in @(
    (Join-Path $env:APPDATA 'AnyDesk'),
    (Join-Path $env:PROGRAMDATA 'AnyDesk')
)) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host 'removed portable binary and per-user configuration'
