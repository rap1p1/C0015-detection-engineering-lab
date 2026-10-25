# WMI remote process creation

Lateral movement to the backup server uses `wmic` from a `cmd.exe` that was started by
`winlogon.exe`. The command creates a process on the remote host:

```
cmd.exe /C wmic /node:<BACKUP_SERVER> process call create "rundll32.exe C:\ProgramData\143.dll DllRegisterServer"
```

On the target, `WmiPrvSE.exe` spawns `rundll32.exe`, which loads `143.dll` and calls
`DllRegisterServer`. The DLL is written to `C:\ProgramData` first, over the same administrative
share access that the pivot requires.

This is WMI process creation, not WMI event subscription. It produces a network logon on the target
and a parent-child edge from the provider host; it does not produce WMI-Activity filter, consumer, or
binding events.

## How the lab reproduces it

The operator stages `143.dll` to `\\<backup server>\C$\ProgramData\143.dll` over SMB, then issues the
`wmic` command from the winlogon session. The `143.dll` build is a shared library with an exported
`DllRegisterServer`, so the rendered command line matches the campaign exactly.

Two implementation details decide whether the edge appears at all:

- `wmic process call create` splits its argument on commas. `...143.dll,DllRegisterServer` returns
  `ReturnValue = 9` and no process is created. The space form is required.
- the credentials must be valid on the target. The lab uses a backup-server administrator account,
  because the campaign does not document where its credentials came from. The account is provisioned
  ahead of the run and never appears on a command line.

`tools/wmic-pivot.ps1` renders the command, checks the staged file hash, and verifies the resulting
process tree on the target.

## Artifacts

| File | Purpose |
|---|---|
| `tools/wmic-pivot.ps1` | Renders and runs the pivot, then verifies the target-side edge |

## Telemetry and detection

The rule for this behaviour lives in [`detections/eql/`](../../detections/eql/) and is listed in the index at [`detections/README.md`](../../detections/README.md). The field assumptions the rule depends on are recorded there.



## Comma or space

`rundll32` accepts both `module.dll,Export` and `module.dll Export`. Through `wmic process call
create` only the space form works: `wmic` splits its argument on commas and returns `ReturnValue 9`
without creating a process. The pivot in `tools/wmi-pivot.ps1` therefore uses the space form. When the
loader is started directly, the comma form is the documented one and is what the campaign uses.
