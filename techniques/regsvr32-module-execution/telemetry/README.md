# Expected telemetry — regsvr32 module execution

regsvr32 loads a DLL whose extension is .jpg from a user-writable directory and calls DllRegisterServer, which starts the implant in-process.

| Source | Event | Fields |
|---|---|---|
| Sysmon E7 | unsigned module loaded by `regsvr32.exe` from `C:\Users\Public` | `file.path`, `file.code_signature.signed` |
| Sysmon E1 | `regsvr32.exe` with a non-DLL extension in the command line | `process.command_line` |
| Sysmon E3 | callback from `regsvr32.exe` | `process.entity_id`, `destination.ip` |

Collection notes: Sysmon 15.x with the profile in `infra/sysmon/`; Security channel with process
creation auditing and command-line inclusion; PowerShell script block logging for the enumeration
step. Field names in the rules assume the Elastic Common Schema mapping produced by the Elastic
Agent Windows integration.
