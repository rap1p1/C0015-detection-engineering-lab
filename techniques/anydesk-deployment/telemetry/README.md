# Expected telemetry - Portable AnyDesk deployment

AnyDesk is dropped into a user profile Videos directory and run from there, providing an out-of-band interactive channel.

| Source | Event | Fields |
|---|---|---|
| Sysmon E11 | `AnyDesk.exe` created under `Users\<user>\Videos` | `file.path` |
| Sysmon E1 | `AnyDesk.exe` executed from that path | `process.image`, `process.parent.name` |
| Sysmon E3 | long-lived connection to AnyDesk relay ranges | `destination.ip`, `destination.port` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
