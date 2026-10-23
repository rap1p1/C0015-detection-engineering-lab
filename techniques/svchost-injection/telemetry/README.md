# Expected telemetry — svchost injection (CDPUserSvc)

The pivot beacon on the backup server injects into the per-user svchost instance that hosts CDPUserSvc.

| Source | Event | Fields |
|---|---|---|
| Sysmon E8 | `rundll32.exe` -> `svchost.exe` | `SourceImage`, `TargetImage` |
| Sysmon E7 | `143.dll` loaded in `rundll32.exe` before the injection | `file.path`, `file.hash.sha256` |
| Sysmon E3 | callback from the injected `svchost.exe` | `process.entity_id`, `destination.port` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
