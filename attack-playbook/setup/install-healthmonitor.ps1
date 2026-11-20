# install-healthmonitor.ps1 - one-time lab weakness on WS01.
# Creates the agent service and a checks directory that ordinary users can write to.

param(
    [string]$Agent = (Join-Path $PSScriptRoot '..\payloads\HealthMonitor.exe'),
    [string]$Root  = 'C:\ProgramData\HealthMonitor'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Agent)) { throw "agent binary not found: $Agent (build payloads/HealthMonitor.c first)" }

New-Item -ItemType Directory -Force $Root, (Join-Path $Root 'checks'), (Join-Path $Root 'done') | Out-Null
Copy-Item $Agent 'C:\Program Files\HealthMonitor.exe' -Force

# the weakness: Users can write into the directory the service executes from
icacls (Join-Path $Root 'checks') /grant 'Users:(OI)(CI)M' /T /Q | Out-Null

sc.exe create HealthMonitor binPath= 'C:\Program Files\HealthMonitor.exe' start= auto obj= LocalSystem | Out-Null
sc.exe start HealthMonitor | Out-Null
sc.exe query HealthMonitor
