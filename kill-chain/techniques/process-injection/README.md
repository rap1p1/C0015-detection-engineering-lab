# Process injection into the service host

| | |
|---|---|
| Chain phase | Beacon hosting |
| Account | SYSTEM (injector) -> SYSTEM (svchost) |
| What happens | The agent starts `rundll32.exe injector.dll,Run`; the injector loads `beacon.dll` into a SYSTEM `svchost.exe` and calls its `StartW` export with a remote thread. On FS01 the same injector runs as `143.dll` over WMI. |
| Telemetry | Sysmon 8 (SourceImage `rundll32.exe`, TargetImage `svchost.exe`), Sysmon 7 (`dll.path` under `C:\ProgramData\c0015`), Sysmon 1 for the rundll32 command line |
| Detection | R14 (remote thread into svchost), R15 (module loaded from the staging directory), R08 (WmiPrvSE child on FS01) |
| Payload / tooling | `injector.c` (rundll32 DLL), `beacon.dll` (Sliver shared library), `agent-update.ps1` |

## How the lab reproduces it

The injector enables `SeDebugPrivilege`, finds a `svchost.exe` whose token is `S-1-5-18`, writes the
beacon path into the target, runs `LoadLibraryA` remotely, then calls the DLL's `StartW` export with a
second remote thread. The beacon lives in the service host, not in a process of its own.

## Evidence

<!-- Elastic capture for this phase: elastic-process-injection.png -->
<!-- Manual capture for this phase: manual-process-injection.png -->

No capture yet: the chain is being rebuilt and the first run of this design has not been recorded.
