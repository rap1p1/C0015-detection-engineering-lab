# payloads/dll — DLL surrogates (rundll32 / svchost)

Two artifacts:

1. `c0015_143_surrogate.c` — the lab's `143.dll` equivalent (rundll32, WMI pivot).
2. `c0015_svc_stub.c` — **v2 route A**: a `ServiceDll` stub so `svchost.exe -k c0015grp` hosts the
   stage and spawns `rundll32.exe <D8B3.dll>` with a SYSTEM token. This is the prerequisite for
   `migrate --process-name winlogon.exe`. Labeled `[LAB-MECHANISM]` — see
   `docs/fidelity-gap-and-rebuild-plan.md §5.3`.

## `c0015_143_surrogate.c` — exports

- `LabEntry` — the entry called by `rundll32.exe <dll> LabEntry` (S1 regsvr32 flow and
  S8b WMI pivot). Runtime behavior: write a marker file to a directory taken from the INI
  (`[lab] marker_dir/marker_name` from `config-phase7.ini`) and spawn the beacon from
  `[beacon] beacon_cmd` — exactly the "dll writes marker + spawns beacon" pattern of the
  campaign.
- `DllRegisterServer` — present so `regsvr32 /s` succeeds with ReturnValue 0.

## Why the space-form matters (G2)

`wmic process call create "<long cmd>"` splits arguments on **commas**, so
`...143.dll,LabEntry` returns ReturnValue 9. The verified spelling is the space form:

```
wmic /node:FS01 process call create "C:\Windows\System32\rundll32.exe C:\C0015\c0015_143_surrogate.dll LabEntry"
```

## Build

```
cl /LD c0015_143_surrogate.c /link /OUT:c0015_143_surrogate.dll   (or use the checked-in DLL)
```

Telemetry: E1 (rundll32, parent=wmiprvse in the WMI case), E7 (ImageLoad hash), E11 (marker).

---

## `c0015_svc_stub.c` — svchost ServiceDll stage (route A)

Exports `ServiceMain` (x64; svchost resolves it by name). On start it reads
`%PUBLIC%\C0015\config.ini` → `[stage] spawn_cmd` and `spawn_cmd` is executed with
`CREATE_NO_WINDOW` **as SYSTEM**, because svchost runs as SYSTEM. `spawn_cmd` is normally
`C:\Windows\System32\rundll32.exe C:\Users\Public\C0015\D8B3.dll`. The stub stays alive until
the child exits (or the service is stopped), so `ParentImage=svchost.exe` remains stable in E1.

Control path: no `config.ini` / empty `spawn_cmd` → service reports STOPPED, no process and no file.

Build (needs an x64 mingw; not available on the Windows workstation):

```
x86_64-w64-mingw32-gcc -shared -o c0015_stage.dll payloads/dll/c0015_svc_stub.c -ladvapi32
```

Install / remove (elevated, on WS01):

```powershell
# copy c0015_stage.dll to C:\Users\Public\C0015\ first
.\payloads\packaging\install_stage_service.ps1 `
    -DllPath 'C:\Users\Public\C0015\c0015_stage.dll' `
    -SpawnCmd 'C:\Windows\System32\rundll32.exe C:\Users\Public\C0015\D8B3.dll' -Start

.\payloads\packaging\install_stage_service.ps1 -Uninstall
```

The installer creates: service `c0015svc` (`svchost.exe -k c0015grp`, demand start),
`Parameters\ServiceDll`, and the `Svchost\c0015grp` multi-string group; then verifies that a
`svchost.exe -k c0015grp` exists and prints its children.

Telemetry to expect: Security `7045` (service installed), Sysmon E13 (ServiceDll + Svchost group),
E1 `svchost.exe -k c0015grp → rundll32.exe`, E7 `D8B3.dll`, E11 marker (`svc-stage.txt`).
These service artifacts do **not** exist in the source campaign — record them as lab noise.