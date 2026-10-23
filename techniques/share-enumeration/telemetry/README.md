# Expected telemetry - Share enumeration with PowerView

PowerShell downloads PowerView from a local staging cradle, runs Invoke-ShareFinder with share-access checks, and writes the results to ProgramData.

| Source | Event | Fields |
|---|---|---|
| Sysmon E1 | `powershell.exe` with `IEX` and `Invoke-ShareFinder` | `process.command_line`, `process.parent.name` |
| PowerShell 4104 | script block containing `Invoke-ShareFinder` | `ScriptBlockText` |
| Sysmon E11 | `found_shares.txt` created | `file.path` |
| Security 5145 | share access checks against remote hosts | `ShareName`, `AccessMask` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
