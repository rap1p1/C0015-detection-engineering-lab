# Expected telemetry - LSASS access through ProcessHacker

ProcessHacker is dropped in the root of C: and used to create a memory dump of lsass.exe, which is then parsed offline with Mimikatz.

| Source | Event | Fields |
|---|---|---|
| Sysmon E10 | handle opened against `lsass.exe` with read rights | `SourceImage`, `TargetImage`, `GrantedAccess` |
| Sysmon E11 | dump file written | `file.path`, `file.extension` |
| Sysmon E1 | `mimikatz.exe` with `sekurlsa::minidump` | `process.command_line` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
