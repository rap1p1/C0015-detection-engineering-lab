# Expected telemetry — svchost stage hosting

A service DLL makes svchost.exe host the stage and spawn rundll32.exe, producing the svchost-to-rundll32 edge with a SYSTEM token.

| Source | Event | Fields |
|---|---|---|
| Security 7045 | service installed | `ServiceName`, `ImagePath` |
| Sysmon E13 | `ServiceDll` and `Svchost` group registry writes | `registry.path`, `registry.data.strings` |
| Sysmon E1 | `svchost.exe -k <group>` -> `rundll32.exe` | `process.parent.name`, `process.parent.command_line` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
