# LSASS dump with ProcessHacker

Performed from the interactive RDP session on the backup server, not from the implant. The dump is a
GUI action, so the process that owns it is `ProcessHacker.exe` with `explorer.exe` as its parent.

## Steps

1. Place the binary at `C:\ProcessHacker.exe` and start it from Explorer.
2. Enable `Options > Advanced > Enable kernel driver` if the handle request is denied.
3. Locate `lsass.exe` in the process list, right-click, `Create dump file`.
4. Accept the default path (`%TEMP%\lsass.dmp`), then move it to `C:\ProgramData\lsass.dmp`.

## Expected events

| Source | Field | Value |
|---|---|---|
| Sysmon E10 | `SourceImage` | `C:\ProcessHacker.exe` |
| Sysmon E10 | `TargetImage` | `C:\Windows\System32\lsass.exe` |
| Sysmon E10 | `GrantedAccess` | `0x1F0FFF` or `0x1410` (read rights present) |
| Sysmon E11 | `TargetFilename` | `C:\ProgramData\lsass.dmp` |

The access mask is the discriminating field. A tool that only queries process information produces a
mask without `PROCESS_VM_READ` and is not a dump.

## Handling

The dump stays on the host for the duration of the run and is deleted afterwards. Credential material
derived from it is never written to the repository, the run ledger, or the detection notes.
