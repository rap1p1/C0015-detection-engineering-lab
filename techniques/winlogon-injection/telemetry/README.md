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

## StartAddress check

The `E8` event carries the address of the new thread's entry point. For an injection that address
belongs to a private allocation in the target process, not to any mapped image. A thread that starts
inside `winlogon.exe` or inside a loaded DLL is a legitimate thread creation and must not be read as
an injection.

Verification: take the `StartAddress` from the event, list the module base addresses of the target
process, and confirm the address falls outside every range. The allocation recorded in this lab
(`0x1E6854700000` for a `winlogon.exe` at its usual base) is in unbacked private memory.
