# T-003 - WMI to FS01, persistence, exfiltration and impact

| Field | Value |
|---|---|
| Case | [03-lateral-impact](../cases/03-lateral-impact.md) |
| Host | FS01 |
| Account | `C0015\Administrator`, SYSTEM |
| Priority | Critical |
| Status | Open - evidence pending |

## Summary

The administrator credential was used over WMI to disable Defender on FS01 and deliver a beacon, which was
installed as an auto-start service. The beacon ran rclone to MEGA, deleted shadow copies and ran the
ransomware over the corpus.

## Findings

- Network logon and WMI child process on FS01.
- Service with auto start; survives reboot.
- rclone command line to `Mega:DATA`, exit 0.
- Notes and `.c0015` files after the locker ran.

## Unknowns

- Transfer volume and whether data reached the remote.
- Whether other hosts are reachable with the same credential.

## Escalation

Containment recommended but not performed. Rebuild FS01 from snapshot and restore the corpus from baseline.
