<#
.SYNOPSIS
    Place and start the portable remote-access client from a user media directory.
.EXAMPLE
    .\deploy-anydesk.ps1 -Source .\AnyDesk.exe -UserProfile C:\Users\bk.admin
#>
param(
    [Parameter(Mandatory)][string]$Source,
    [string]$UserProfile = $env:USERPROFILE,
    [switch]$Start
)
$dest = Join-Path $UserProfile 'Videos\AnyDesk.exe'
$dir  = Split-Path -Parent $dest
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

Copy-Item -LiteralPath $Source -Destination $dest -Force
$h = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
Write-Host "placed $dest"
Write-Host "sha256 $h"

if ($Start) {
    $p = Start-Process -FilePath $dest -PassThru
    Start-Sleep -Seconds 3
    Write-Host "pid $($p.Id)"
}
