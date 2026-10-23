<#
.SYNOPSIS
    Confirm that operator commands execute with winlogon.exe as the parent, as SYSTEM.
.DESCRIPTION
    Runs on the victim host after the migration. Uses CIM rather than Sysmon so the check works
    independently of the telemetry pipeline.
#>
$winlogon = Get-CimInstance Win32_Process -Filter "Name='winlogon'" |
    Select-Object -First 1
if (-not $winlogon) { throw 'winlogon.exe not found' }

Write-Host "winlogon PID $($winlogon.ProcessId)"

# children that indicate the implant is executing from winlogon
$children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($winlogon.ProcessId)" |
    Select-Object ProcessId, Name, CommandLine
$children | Format-Table -AutoSize

# owner of a freshly spawned process must be SYSTEM
$probe = Get-CimInstance Win32_Process -Filter "Name='cmd.exe'" |
    Where-Object { $_.ParentProcessId -eq $winlogon.ProcessId } |
    Select-Object -First 1
if ($probe) {
    $owner = Invoke-CimMethod -InputObject $probe -MethodName GetOwner
    Write-Host "probe $($probe.ProcessId) owner: $($owner.Domain)\$($owner.User)"
} else {
    Write-Host 'no cmd.exe child of winlogon yet - run a command from the winlogon session first'
}
