# winlogon injection

The beacon does not stay in the process that loaded it. `D8B3.dll` allocates memory in
`winlogon.exe`, writes the payload, and creates a thread there. From that point the operator works
inside a SYSTEM process at the highest integrity level on the host.

The consequence is visible in every subsequent event: discovery commands are `cmd.exe` processes
whose parent is `winlogon.exe`, and the WMI pivot is issued by `winlogon.exe` through `cmd.exe` with
`NT AUTHORITY\SYSTEM` as the user. A detection stack that only looks for shells spawned by Office or
by a scripting host will not see any of it.

## How the lab reproduces it

The stage on WS01 is loaded by `rundll32.exe` under `svchost.exe`, as SYSTEM. From that session the
operator migrates the implant into `winlogon.exe`:

```
sliver > migrate --process-name winlogon.exe
```

`migrate` builds a new implant from the active build configuration and injects it, so the new session
keeps the same C2 profile and callback interval while its host process becomes `winlogon.exe`. The
original session is left running as a fallback until the new one is confirmed.

Three details matter for fidelity:

- the source process is `rundll32.exe`, which is what `E8` records as `SourceImage`;
- the target is `winlogon.exe`, not `explorer.exe` or `svchost.exe`;
- the new session's children inherit SYSTEM, so `cmd.exe` appears with `IntegrityLevel: System`.

`tools/migrate-to-winlogon.txt` lists the exact console sequence, including the checks that must pass
before the original session is closed. `winlogon.exe` is a critical process: a fault inside the
injected image terminates the host. The lab takes a snapshot immediately before this step.

## Artifacts

| File | Purpose |
|---|---|
| `tools/migrate-to-winlogon.txt` | Console sequence and verification checks |
| `tools/verify-injection.ps1` | Confirms parent image, user, and integrity of the new session's children |

## Telemetry and detection

The rule for this behaviour lives in [`detections/eql/`](../../detections/eql/) and is listed in the index at [`detections/README.md`](../../detections/README.md). The field assumptions the rule depends on are recorded there.



## Implementation notes

The client's migrate path did not complete on this build. It requires a terminal for its progress
form, and when driven without one it either reported success without a session or returned an implant
timeout. The lab therefore loads the same Sliver shellcode with an explicit
`VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread` injector executed as `rundll32.exe`
(`tools/c0015_injector.c`). The observable is unchanged: a handle request with write rights, an `E8`
whose source image is `rundll32.exe` and whose target is `winlogon.exe`, and a session whose host
process is the logon process.

The injector reads its target PID and payload path from files next to the module, so the same build
serves the winlogon stage and the service-host stage.
