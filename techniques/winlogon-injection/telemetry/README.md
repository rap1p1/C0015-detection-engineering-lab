# Expected telemetry - winlogon injection

The implant migrates into winlogon.exe, so subsequent operator commands execute as SYSTEM with winlogon.exe as the parent process.

| Source | Event | Fields |
|---|---|---|
| Sysmon E8 | `rundll32.exe` creates a thread in `winlogon.exe` | `SourceImage`, `TargetImage`, `NewThreadId` |
| Sysmon E10 | handle request against `winlogon.exe` | `TargetImage`, `GrantedAccess` |
| Sysmon E1 | `cmd.exe` / `powershell.exe` with `ParentImage=winlogon.exe` | `process.parent.name`, `user.name` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
