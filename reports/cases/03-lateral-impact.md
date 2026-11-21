# Case 03 - WMI, injection, persistence across reboot and impact

**Run:** `run-4`, window `2026-11-21T05:00Z - 05:35Z`. This is the reference case.

## Expected alerts

| Rule | Run-4 matches | What it shows |
|---|---|---|
| R07 | 6 | `wmic /node:FS01` from WS01 |
| R08 | 6 | WMI children on FS01 |
| R14 | 6 | remote threads into `svchost.exe` |
| R15 | 7 | module loads from the staging path |
| R16/R17 | 3 / 3 | DNS `checkauj.com` and the 443 connection from the same identity |
| R19 | 1 | `/create ... /sc onstart` |
| R10/R11/R12 | 1 / 1 / 1 | shadow copies, rclone, locker |

## Persistence timeline

| Time (UTC) | Source | What it records |
|---|---|---|
| 05:20:59.059 | E1, locator `AaH8je2TxY-KOm0HrUjG` | `schtasks /create` with `/sc onstart /ru SYSTEM` (R19; this is the create, not a query) |
| 05:20:59 | `C:\ProgramData\c0015\persist.log` | `=== persist ready ===`, task `Ready` (operator artifact) |
| 05:22:49 | operator | FS01 rebooted |
| after boot | `schtasks /query` | `Last Run` set, task ran |
| after boot | Sliver session `a796ef3b` | new beacon in `svchost.exe` (PID 788) |
| 05:29:26-05:29:28 | `fs01_task.log` | defences, injection, rclone, impact all pass |

The middle of the chain (task actually running at boot) is confirmed by the task `Last Run` and the new
`svchost` session; the E8/E7 of that new instance are part of the run-4 totals, with the full locator
list in `evidence/runs/run-4`.

## Identity

| Stage | Account |
|---|---|
| injector on WS01 | SYSTEM (agent) |
| beacon in `svchost` on WS01 | SYSTEM |
| WMI call to FS01 | `C0015\Administrator` |
| injector and beacon on FS01 | SYSTEM (`C0015\FS01$` on the network) |
| `rclone`, `vssadmin`, locker on FS01 | `C0015\Administrator` (E1 user field) |

## What it proves

The credential was used for remote execution, the beacon was placed in an existing service host, a boot
task was created by the payload and survived one reboot, and the impact steps ran after the reboot.

It does not prove persistence across task deletion, delivery to the cloud remote, or reversible
encryption. R14's six matches are three injections with two threads each, not six successful injections.
