# Case 03 - WMI to FS01, exfiltration and impact

**Status:** evidence pending.

## Expected alerts

| Rule | What it should show |
|---|---|
| R06 | Defender real-time protection disabled on FS01 |
| R07 | `wmic /node:FS01 ... process call create` on WS01 |
| R08 | `WmiPrvSE.exe` child on FS01 |
| R14 | remote thread into `svchost.exe` (two threads per injection: LoadLibrary and StartW) |
| R15 | `beacon.dll` loaded from `C:\ProgramData` |
| R16/R17 | `svchost` resolves `checkauj.com` and then connects to the listener |
| R10 | shadow copies deleted |
| R11 | `rclone.exe` transfer invocation |
| R12 | the locker starts with its name and the full flag set |
| R19 | `C0015Persist` is created with `/sc onstart /ru SYSTEM` |

## Investigation

1. Confirm the network logon on FS01 for `C0015\Administrator` and the WMI child process.
2. Confirm the Defender change happened before the injector ran.
3. Confirm the two E8 events for the FS01 injection share the host and the thread pair, and that the
   E7 for `beacon.dll` comes from `svchost.exe`, not from `rundll32.exe`.
4. Confirm the DNS lookup and the 443 connection belong to the same `process.entity_id`.
5. Confirm rclone's command line and exit code; there is no receiver inventory.
6. Confirm the boot task was created by the payload and that the beacon returned after the reboot.
7. Confirm the shadow copies were deleted and the corpus was renamed with notes.

## What the chain proves and does not

- Proves: the recovered domain administrator credential was used for remote execution, privilege
  escalation on FS01 (SYSTEM through the service host) and impact.
- Proves: persistence across one reboot. `C0015Persist` was created from the payload, the host was
  rebooted, and a new beacon session appeared in `svchost.exe` (PID 788).
- Does not prove: survival of the task being deleted, delivery to the cloud remote, or reversible
  encryption. The task runs the injector; it does not install a service.

## Evidence to capture

- 4624 type 3 with the administrator account, the E8 remote thread, the E7 module load, rclone command line, note and rename counts.

