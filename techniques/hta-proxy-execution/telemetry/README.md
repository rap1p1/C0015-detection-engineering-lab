# Expected telemetry — HTA proxy execution

mshta.exe runs the HTML Application, which fetches the next-stage module over HTTP and writes it to disk under an image extension before invoking regsvr32.

| Source | Event | Fields |
|---|---|---|
| Sysmon E1 | `mshta.exe` -> `regsvr32.exe` | `process.parent.name` |
| Sysmon E3 | mshta egress to the staging host | `destination.ip`, `destination.port` |
| Sysmon E11 | `compareForfor.jpg` created under `C:\Users\Public` | `file.path`, `file.extension` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
