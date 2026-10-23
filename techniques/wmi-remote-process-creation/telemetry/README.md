# Expected telemetry - WMI remote process creation

wmic creates a process on the backup server; WmiPrvSE.exe spawns rundll32.exe which loads 143.dll and registers the second beacon.

| Source | Event | Fields |
|---|---|---|
| Sysmon E1 | `winlogon.exe` -> `cmd.exe /C wmic /node:...` then `WmiPrvSE.exe` -> `rundll32.exe` | `process.command_line`, `process.parent.name` |
| Security 4624 | network logon (type 3) on the target | `LogonType`, `TargetUserName`, `WorkstationName` |
| Security 4672 | special privileges assigned to the logon | `SubjectLogonId` |
| Security 5145 | admin share access on the target | `ShareName`, `RelativeTargetName` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
