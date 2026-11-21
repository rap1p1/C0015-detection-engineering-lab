# T-003 - WMI, injection, boot persistence and impact

| Field | Value |
|---|---|
| Run | run-4 (2026-11-21 05:00-05:35Z) |
| Host | FS01 |
| Account | `C0015\Administrator`, SYSTEM |
| Priority | Critical |
| Status | Open - evidence captured |

## Summary

The administrator credential was used over WMI to disable Defender and to run the injector, which put
the beacon inside a SYSTEM `svchost`. The payload then created a boot task, the host was rebooted, the
beacon returned, and the impact steps ran.

## Evidence

- R07/R08: `wmic /node:FS01` calls from WS01 and WMI children on FS01.
- R14: E8 into `svchost`, locator `AaH8j-2TxY-KOm1ZuJZ_`; six matches are three injections x two threads.
- R16/R17: DNS `checkauj.com` and the 443 connection from the same `process.entity_id`; E3 `AaH8mO2TxY-KOm3K0pf-`.
- R19: `/create ... /sc onstart`, locator `AaH8je2TxY-KOm0HrUjG` (not the `/query` event).
- Persistence: task `C0015Persist` Ready, reboot, new session `a796ef3b` in `svchost`, then `fs01_task.log` passes.
- R10/R11/R12: shadow copies, rclone exit 0, locker `renamed=40; notes=4`.

## Not proven

Survival of task deletion, receiver-side delivery of the exfiltration, reversible encryption.

## Note

This is a scheduled task created by the payload, not an auto-start service. R09 is retired and is not
part of this case.
