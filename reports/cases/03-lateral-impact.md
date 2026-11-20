# Case 03 - WMI to FS01, exfiltration and impact

**Status:** evidence pending.

## Expected alerts

| Rule | What it should show |
|---|---|
| R06 | Defender real-time protection disabled on FS01 |
| R08 | `WmiPrvSE.exe` child on FS01, `cmd /Q /c` with the `ADMIN$` redirect |
| R14 | remote thread into `svchost.exe` (two threads per injection: LoadLibrary and StartW) |
| R15 | `beacon.dll` loaded from `C:\ProgramData` |
| R11 | `rclone.exe` copy to `Mega:DATA` |
| R12 | the locker starts with `-m -net -size 10 -nomutex` and the note follows |

## Investigation

1. Confirm the network logon on FS01 for `C0015\Administrator` and the WMI child process.
2. Confirm the Defender settings were changed before the beacon was delivered.
4. Confirm rclone's command line and exit code; there is no receiver inventory.
5. Confirm the shadow copies were deleted and the corpus was renamed with notes.

## What the chain proves and does not

- Proves: the recovered domain administrator credential was used for remote execution, persistence,
  exfiltration and impact.
- Does not prove: that data reached the cloud remote, or that the encryption is reversible.

## Evidence to capture

- 4624 type 3 with the administrator account, the E8 remote thread, the E7 module load, rclone command line, note and rename counts.

