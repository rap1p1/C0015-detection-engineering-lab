# Case 03 - WMI to FS01, exfiltration and impact

**Status:** evidence pending.

## Expected alerts

| Rule | What it should show |
|---|---|
| R08 | `WmiPrvSE.exe` child on FS01, `cmd /Q /c` with the `ADMIN$` redirect |
| R09 | 7045 service installation and the service binary |
| R11 | `rclone.exe` copy to `Mega:DATA` |
| R12 | `readme.txt` creation and the `.c0015` churn |

## Investigation

1. Confirm the network logon on FS01 for `C0015\Administrator` and the WMI child process.
2. Confirm the Defender settings were changed before the beacon was delivered.
3. Confirm the service exists with `start= auto` and survives a reboot.
4. Confirm rclone's command line and exit code; there is no receiver inventory.
5. Confirm the shadow copies were deleted and the corpus was renamed with notes.

## What the chain proves and does not

- Proves: the recovered domain administrator credential was used for remote execution, persistence,
  exfiltration and impact.
- Does not prove: that data reached the cloud remote, or that the encryption is reversible.

## Evidence to capture

- 4624 type 3 with the administrator account, 7045, rclone command line, note and rename counts.
