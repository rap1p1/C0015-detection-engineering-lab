<#
.SYNOPSIS
    Issue one discovery command per process from the winlogon session.
.DESCRIPTION
    Each entry is executed as its own cmd.exe /C invocation so the parent image stays winlogon.exe
    and the process duration matches an interactive operator rather than a single long-lived shell.
#>
param(
    [string]$HostList = 'FS01,DC01',
    [int]$IntervalMs  = 1500
)

$commands = @(
    'tasklist /s FS01',
    'net group "domain admins" /dom',
    'net localgroup "administrator"',
    'nltest /domain_trusts /all_trusts',
    'net view /all /domain',
    'time'
)
foreach ($h in $HostList.Split(',')) {
    $commands += "net view \\$h /all"
    $commands += "ping -n 1 $h"
}

$out = New-Object System.Collections.Generic.List[string]
foreach ($c in $commands) {
    $out.Add("### cmd.exe /C $c")
    Write-Host "cmd.exe /C $c"
    $out.Add((cmd.exe /c $c 2>&1 | Out-String))
    Start-Sleep -Milliseconds $IntervalMs
}
$out | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'discovery-output.txt') -Encoding UTF8
Write-Host "wrote discovery-output.txt"
