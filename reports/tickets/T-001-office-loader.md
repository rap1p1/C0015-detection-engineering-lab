# Ticket T-001: Office document starts a proxy-executed unsigned module

| Field | Value |
|---|---|
| Ticket | T-001 |
| Case | [Office to loader](../cases/office-loader.md) |
| Run | `run-1`, capture `cap-run1-2` |
| Opened (UTC) | 2026-10-27T12:22:19Z |
| Status | Open - escalated to Tier 2 |

## Summary

`ws01` reported an unsigned module load 0.234 s after `mshta.exe` started `regsvr32.exe` from a file
in the user's profile. The process chain begins under `WINWORD.EXE`. A second unsigned module was loaded
from `C:\Windows\Temp` sixteen seconds later.

## Priority

High. Office ancestry plus an unsigned module from a user-writable path is a credible execution chain,
and the host is a user workstation on the same segment as the file server.

## Entities

| Type | Value |
|---|---|
| Host | `ws01` (192.168.50.20) |
| User | `C0015\duc.user` |
| Processes | `WINWORD.EXE`, `cmd.exe`, `mshta.exe`, `regsvr32.exe`, `rundll32.exe` |
| Files | `C:\Users\duc.user\compareforfor.hta`, `C:\Users\Public\compareForfor.jpg`, `C:\Windows\Temp\c0015_d8b3.dll` |

## Evidence

| Event | Locator |
|---|---|
| `cmd.exe` under Word | `AaF9T4505TXapMFDnV4y` |
| `regsvr32.exe` under `mshta.exe` | `AaF9T4505TXapMFqnWWP` |
| Unsigned load of `compareForfor.jpg` | `AaF9T4505TXapMFqnWWV` |
| Unsigned load of `c0015_d8b3.dll` | `AaF9T4505TXapMGSnkEd` |

All four are in `.ds-logs-windows.sysmon_operational-c0015-2026.10.24-000002` and are linked from
[`sources/by_alert.json`](../../evidence/runs/run-1/sources/by_alert.json).

## Findings

- Process ancestry from Word through `cmd.exe` and `mshta.exe` to `regsvr32.exe` is confirmed by parent
  fields and timestamps.
- Two unsigned module loads are confirmed within the same minute.
- The module path for the first load is in the user profile, not a system directory.

## Unknowns

- Whether the document executed a macro (needs Office or AMSI telemetry).
- Whether either module made a network connection; no network event is in the bundle.
- Whether the modules executed successfully.

## Actions taken

- Alert triaged, source events resolved and linked.
- Timeline reconstructed from the four documents.

## Recommended actions

- Pull network telemetry for `ws01` for 12:21:40Z - 12:23:00Z.
- Collect `C:\Users\Public\compareForfor.jpg` and `C:\Windows\Temp\c0015_d8b3.dll` for hashing.
- Check whether the same file names appear on `fs01`.

## Escalation

Tier 2: the chain reaches proxy execution with an unsigned module, and the host is adjacent to the file
server. Containment is recommended but has **not** been performed.




