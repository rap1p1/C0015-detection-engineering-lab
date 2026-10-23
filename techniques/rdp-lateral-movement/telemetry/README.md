# Expected telemetry — RDP through the beacon

The operator reaches the backup server over RDP tunnelled through the implant, so the implant process owns the 3389 connection.

| Source | Event | Fields |
|---|---|---|
| Sysmon E3 | implant process initiates TCP 3389 | `process.image`, `destination.port` |
| Security 4624 | type 10 interactive logon on the target | `LogonType`, `TargetLogonId` |
| Security 4778 / 4779 | session reconnect / disconnect | `SessionName`, `ClientAddress` |
| Sysmon E1 | `explorer.exe` -> `taskmgr.exe /4` inside the session | `process.command_line`, `process.parent.name` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
