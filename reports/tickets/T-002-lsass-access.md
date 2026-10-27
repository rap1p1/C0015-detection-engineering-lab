# Ticket T-002: LSASS opened with a dump-like access mask

| Field | Value |
|---|---|
| Ticket | T-002 |
| Case | [LSASS access](../cases/lsass-access.md) |
| Run | `run-1`, capture `cap-final04-v3` |
| Opened (UTC) | 2026-10-27T12:27:19Z |
| Status | Open - Tier 1 investigation |

## Summary

`fs01` reported `mk.exe` opening `lsass.exe` with `0x1010`.

## Priority

High: LSASS access with a read mask is a credential-theft precursor, and `fs01` holds the backup corpus.

## Entities

| Type | Value |
|---|---|
| Host | `fs01` (192.168.50.30) |
| Process | `mk.exe` (no parent recorded) |
| Target | `C:\Windows\system32\lsass.exe`, access `0x1010` |

## Evidence

| Event | Locator |
|---|---|
| Process access to LSASS | `AaF9VI505TXapMFlrcSr` |

## Findings

- Access mask is consistent with reading LSASS memory.
- No parent process and no user field are present on the event.

## Unknowns

- Whether a dump file was written.
- How `mk.exe` arrived on the host and under which account it ran.

## Actions taken

- Alert triaged, source event resolved.

## Recommended actions

- Search for file creation in `C:\ProgramData` and `C:\Windows\Temp` in the same minute.
- Locate the process creation of `mk.exe` and its parent.
- Compare with known administrative tooling before containment.

## Escalation

Tier 2 if a dump artefact or an unexplained `mk.exe` origin is found; otherwise close as inconclusive with
the telemetry gap recorded.

