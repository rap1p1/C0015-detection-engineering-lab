# Expected telemetry - Discovery through LOLBins

Host and domain discovery runs as one cmd.exe per command, spawned by winlogon.exe under a SYSTEM token.

| Source | Event | Fields |
|---|---|---|
| Sysmon E1 | `winlogon.exe` -> `cmd.exe /C net|nltest|tasklist|ping` | `process.parent.name`, `process.command_line` |
| Sysmon E3 | directory service and SMB connections to the domain controller | `destination.port` |
| Security 4688 | command line of each discovery process | `CommandLine`, `CreatorProcessName` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
